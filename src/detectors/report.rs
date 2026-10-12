//! ALR-08 心跳报平安 + ALR-09 每日摘要（PRD §5.2）。
//!
//! 两者均为显式开启的主动通知，使用 [`crate::alert::Alert::always_send`] 绕过
//! min_level 过滤（但仍受限流与聚合约束）。统计数据来自 store 的 alert_log。

use crate::alert::{Alert, Level};
use crate::config::{DigestCfg, HeartbeatCfg};
use crate::notify::Notifier;
use crate::store::Store;
use anyhow::Result;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::time::Instant as TokioInstant;
use tokio_util::sync::CancellationToken;

pub async fn run(
    heartbeat: HeartbeatCfg,
    digest: DigestCfg,
    notifier: Notifier,
    store: Option<Arc<Store>>,
    token: CancellationToken,
) -> Result<()> {
    if !heartbeat.enabled && !digest.enabled {
        return Ok(());
    }
    let started = Instant::now();
    tracing::info!(
        heartbeat = heartbeat.enabled,
        digest = digest.enabled,
        digest_hour = digest.at_hour,
        "report 任务已启动（心跳/每日摘要）"
    );
    let hb_interval = Duration::from_secs(heartbeat.interval_sec.max(60));
    let mut hb_deadline = heartbeat.enabled.then(|| TokioInstant::now() + hb_interval);
    let mut dg_deadline = digest
        .enabled
        .then(|| TokioInstant::now() + until_next_hour(digest.at_hour));

    loop {
        let now = TokioInstant::now();
        let wait = [hb_deadline, dg_deadline]
            .into_iter()
            .flatten()
            .map(|deadline| deadline.saturating_duration_since(now))
            .min()
            .unwrap_or(Duration::from_secs(3600));
        tokio::select! {
            _ = tokio::time::sleep(wait) => {}
            _ = token.cancelled() => return Ok(()),
        }
        let now = TokioInstant::now();
        if let Some(deadline) = hb_deadline
            && now >= deadline
        {
            send_heartbeat(&notifier, store.as_deref(), started).await?;
            hb_deadline = Some(now + hb_interval);
        }
        if let Some(deadline) = dg_deadline
            && now >= deadline
        {
            send_digest(&notifier, store.as_deref()).await?;
            dg_deadline = Some(now + until_next_hour(digest.at_hour));
        }
    }
}

async fn send_heartbeat(
    notifier: &Notifier,
    store: Option<&Store>,
    started: Instant,
) -> Result<()> {
    let uptime = human_duration(started.elapsed());
    let (pending, events_24h) = match store {
        Some(store) => {
            let now = chrono::Utc::now().timestamp();
            let pending = store.outbox_pending_count().unwrap_or(-1);
            let events: i64 = store
                .alert_stats_since(now - 86400)
                .map(|rows| rows.iter().map(|(_, n)| n).sum())
                .unwrap_or(-1);
            (pending, events)
        }
        None => (-1, -1),
    };
    let alert = Alert::new(
        Level::Info,
        "heartbeat",
        "honeyguard 心跳",
        format!(
            "agent 存活，已运行 {uptime}。\n过去 24h 告警 {events_24h} 条，待发队列 {pending} 条。\n（长时间收不到心跳请检查服务器与 honeyguard 服务）"
        ),
    )
    .with_key("heartbeat")
    .always_send();
    notifier.publish(alert).await?;
    Ok(())
}

async fn send_digest(notifier: &Notifier, store: Option<&Store>) -> Result<()> {
    let body = match store {
        Some(store) => {
            let now = chrono::Utc::now().timestamp();
            let stats = store.alert_stats_since(now - 86400).unwrap_or_default();
            let top = store
                .alert_top_keys_since(now - 86400, 5)
                .unwrap_or_default();
            if stats.is_empty() {
                "过去 24h 无告警事件。".to_string()
            } else {
                let mut lines = vec!["过去 24h 告警统计：".to_string()];
                for (detector, count) in &stats {
                    lines.push(format!("  {detector}: {count} 条"));
                }
                if !top.is_empty() {
                    lines.push("高频来源 Top5：".to_string());
                    for (key, count) in &top {
                        lines.push(format!("  {key} × {count}"));
                    }
                }
                lines.join("\n")
            }
        }
        None => "状态数据库不可用，无法统计（过去 24h 告警见运行日志）".to_string(),
    };
    let alert = Alert::new(Level::Info, "digest", "honeyguard 每日摘要", body)
        .with_key("digest")
        .always_send();
    notifier.publish(alert).await?;
    Ok(())
}

/// 距下一次本地时区 `at_hour` 点的时长（DST 极端场景按 1 小时兜底）。
pub(crate) fn until_next_hour(at_hour: u8) -> Duration {
    use chrono::{Local, Timelike};
    let now = Local::now();
    let today_at = now
        .with_hour(at_hour as u32)
        .and_then(|t| t.with_minute(0))
        .and_then(|t| t.with_second(0))
        .and_then(|t| t.with_nanosecond(0));
    let Some(today_at) = today_at else {
        return Duration::from_secs(3600);
    };
    // 用“今天目标 + 1 天”保留时区上下文，避免手工做本地时区换算
    let target = if today_at > now {
        today_at
    } else {
        today_at + chrono::Duration::days(1)
    };
    (target - now).to_std().unwrap_or(Duration::from_secs(3600))
}

fn human_duration(d: Duration) -> String {
    let secs = d.as_secs();
    if secs >= 86400 {
        format!("{} 天 {} 小时", secs / 86400, (secs % 86400) / 3600)
    } else if secs >= 3600 {
        format!("{} 小时 {} 分", secs / 3600, (secs % 3600) / 60)
    } else {
        format!("{} 分钟", secs.max(1) / 60)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn until_next_hour_is_bounded() {
        let d = until_next_hour(8);
        assert!(d.as_secs() > 0);
        assert!(d.as_secs() <= 86400 + 3600, "最长不超过一天多一点：{d:?}");
    }

    #[test]
    fn human_duration_formats() {
        assert_eq!(human_duration(Duration::from_secs(90_000)), "1 天 1 小时");
        assert_eq!(human_duration(Duration::from_secs(3660)), "1 小时 1 分");
        assert_eq!(human_duration(Duration::from_secs(30)), "0 分钟");
    }
}
