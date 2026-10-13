//! 检测层（docs/PRD.md §5.1）。每个检测器是独立的常驻 task，产出
//! [`crate::alert::Alert`] 并经 [`crate::notify::Notifier`] 发布。
//!
//! 生命周期约定：`run` 函数持有 [`CancellationToken`]，收到取消信号后应尽快返回；
//! [`supervised`] 负责在 panic / 异常退出时按指数退避重启，并在收到取消信号时
//! 中止当前实例，保证持有的 [`crate::notify::Notifier`] 克隆全部释放，
//! 否则告警分发器会因 channel 未关闭而无法退出。

pub mod behavior;
pub mod fim;
pub mod net;
pub mod ports;
pub mod process;
pub mod report;
pub mod ssh;

use std::future::Future;
use std::time::Duration;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

/// 检测器监督器（PRD NF-02）：panic / 异常退出后按指数退避重启；
/// 稳定运行超过 60s 再出错则重置退避。收到取消信号时中止当前实例并返回。
pub async fn supervised<F, Fut>(name: &'static str, token: CancellationToken, factory: F)
where
    F: Fn(CancellationToken) -> Fut,
    Fut: Future<Output = anyhow::Result<()>> + Send + 'static,
{
    const STABLE: Duration = Duration::from_secs(60);
    const MAX_BACKOFF: Duration = Duration::from_secs(60);
    let mut backoff = Duration::from_secs(1);
    loop {
        let started = Instant::now();
        let mut task = tokio::spawn(factory(token.clone()));
        tokio::select! {
            result = &mut task => match result {
                Ok(Ok(())) => {
                    tracing::info!(detector = name, "检测器正常退出");
                    return;
                }
                Ok(Err(err)) => {
                    tracing::warn!(detector = name, error = %err, "检测器异常退出，准备重启");
                }
                Err(panic) => {
                    tracing::warn!(detector = name, error = %panic, "检测器 panic，准备重启");
                }
            },
            _ = token.cancelled() => {
                tracing::info!(detector = name, "收到停止信号，中止检测器");
                task.abort();
                let _ = task.await;
                return;
            }
        }
        if started.elapsed() >= STABLE {
            backoff = Duration::from_secs(1);
        }
        tracing::warn!(detector = name, backoff = backoff.as_secs(), "重启检测器");
        tokio::select! {
            _ = tokio::time::sleep(backoff) => {}
            _ = token.cancelled() => return,
        }
        backoff = (backoff * 2).min(MAX_BACKOFF);
    }
}
