//! 告警出站管道：分级过滤 → 聚合/静默 → 限流 → outbox 持久化 → Webhook 投递。
//!
//! 语义（与 PRD ALR-03/04/05 一致）：
//! - 低于 `min_level` 的告警直接丢弃（记 debug 日志）；
//! - 同一聚合键的**首条**告警立即发送；
//! - 聚合窗口内的后续同类告警合并，窗口结束时补发一条摘要（“另有 N 次”）；
//! - 发送后进入静默期，期内同类事件被抑制并计数（计入下一条告警正文）；
//! - 令牌桶按分钟配额限流，critical 不受限流约束；
//! - Webhook 通道：告警先写入 SQLite outbox 再投递（入队即持久）；
//!   失败按指数退避重试（封顶 5 分钟），进程重启后自动补发积压，
//!   积压超过 100 条时丢弃 info/warning 只保留 critical。

pub mod policy;
pub mod template;
pub mod webhook;

use crate::alert::{Alert, Level};
use crate::config::{AlertCfg, WebhookCfg};
use crate::store::Store;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::Notify;
use tokio::sync::mpsc;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

/// 告警投递后端；`Mock` 仅用于测试（不经过 outbox，同步记录）。
pub enum Delivery {
    Webhook(reqwest::Client),
    #[doc(hidden)]
    Mock(Arc<Mutex<Vec<Alert>>>),
}

impl Delivery {
    /// 直发（无持久化路径使用：Mock，或 Webhook 无存储时的降级）。
    async fn deliver(&self, targets: &[WebhookCfg], alert: &Alert) -> Vec<anyhow::Result<()>> {
        match self {
            Delivery::Webhook(client) => {
                let mut results = Vec::with_capacity(targets.len());
                for wh in targets {
                    results.push(webhook::send_one(client, wh, alert).await);
                }
                results
            }
            Delivery::Mock(recorded) => {
                recorded
                    .lock()
                    .expect("Mock 记录锁中毒")
                    .push(alert.clone());
                (0..targets.len()).map(|_| Ok(())).collect()
            }
        }
    }

    fn is_webhook(&self) -> bool {
        matches!(self, Delivery::Webhook(_))
    }
}

/// 告警发布端（可 clone，多处发布；全部 drop 后分发器会 flush 遗留聚合并退出）。
#[derive(Clone)]
pub struct Notifier {
    tx: mpsc::Sender<Alert>,
}

/// 分发器与 outbox worker 的任务句柄；`shutdown` 保证按正确顺序等待两者退出。
pub struct NotifierHandle {
    dispatcher: tokio::task::JoinHandle<()>,
    worker: Option<(tokio::task::JoinHandle<()>, CancellationToken)>,
}

impl NotifierHandle {
    /// 等待分发器 flush 退出（需先 drop 所有 [`Notifier`] 克隆），
    /// 再停止 outbox worker 并等它完成最后一轮补发。
    /// 若发布端未全部释放导致分发器不退出，10s 后强制中止而非永久挂起。
    pub async fn shutdown(self) -> anyhow::Result<()> {
        let mut dispatcher = self.dispatcher;
        match tokio::time::timeout(Duration::from_secs(10), &mut dispatcher).await {
            Ok(Ok(())) => {}
            Ok(Err(join_err)) => anyhow::bail!("告警分发器异常退出: {join_err}"),
            Err(_) => {
                tracing::warn!("告警分发器 10s 内未退出（可能存在未释放的发布端），强制中止");
                dispatcher.abort();
                let _ = dispatcher.await;
            }
        }
        if let Some((worker, token)) = self.worker {
            token.cancel();
            worker
                .await
                .map_err(|e| anyhow::anyhow!("outbox worker 异常退出: {e}"))?;
        }
        Ok(())
    }
}

impl Notifier {
    /// 启动出站管道。
    ///
    /// `store` 提供时 Webhook 通道走 outbox 持久化投递；`None` 降级为单次直发（不重试）。
    pub fn start(
        cfg: AlertCfg,
        targets: Vec<WebhookCfg>,
        delivery: Delivery,
        store: Option<Arc<Store>>,
    ) -> (Self, NotifierHandle) {
        let (tx, rx) = mpsc::channel(256);
        let client = match &delivery {
            Delivery::Webhook(client) => Some(client.clone()),
            Delivery::Mock(_) => None,
        };
        let worker_store = store.clone();
        let wake = match (&delivery, &store) {
            (Delivery::Webhook(_), Some(_)) => Some(Arc::new(Notify::new())),
            _ => None,
        };
        let dispatcher = tokio::spawn(dispatcher_loop(
            rx,
            cfg,
            targets,
            Arc::new(delivery),
            store,
            wake.clone(),
        ));

        let worker = match (client, worker_store, wake) {
            (Some(client), Some(store), Some(wake)) => {
                let stop = CancellationToken::new();
                let handle = tokio::spawn(outbox_worker(client, store, wake, stop.clone()));
                Some((handle, stop))
            }
            _ => None,
        };
        (Self { tx }, NotifierHandle { dispatcher, worker })
    }

    /// 发布一条告警（进入分级/聚合/限流管道）。
    pub async fn publish(&self, alert: Alert) -> anyhow::Result<()> {
        self.tx
            .send(alert)
            .await
            .map_err(|_| anyhow::anyhow!("告警分发器已停止"))
    }
}

/// outbox worker：被唤醒或每 5s 扫描到期条目投递；指数退避（封顶 5 分钟）。
async fn outbox_worker(
    client: reqwest::Client,
    store: Arc<Store>,
    wake: Arc<Notify>,
    stop: CancellationToken,
) {
    const TICK: Duration = Duration::from_secs(5);
    const BATCH: i64 = 50;

    match store.outbox_pending_count() {
        Ok(0) => {}
        Ok(n) => tracing::info!(pending = n, "outbox 启动：发现积压待发告警，将自动补发"),
        Err(err) => tracing::warn!(error = %err, "outbox 积压计数失败"),
    }

    loop {
        tokio::select! {
            _ = wake.notified() => {}
            _ = tokio::time::sleep(TICK) => {}
            _ = stop.cancelled() => {
                // 退出前尽力清一轮已在队列中的到期条目
                if let Err(err) = drain_due(&client, &store, BATCH).await {
                    tracing::warn!(error = %err, "outbox 退出补发失败");
                }
                tracing::info!("outbox worker 退出");
                return;
            }
        }
        if let Ok(deleted) = store.trim_backlog()
            && deleted > 0
        {
            tracing::warn!(deleted, "outbox 积压超限，丢弃了部分非 critical 告警");
        }
        if let Err(err) = drain_due(&client, &store, BATCH).await {
            tracing::warn!(error = %err, "outbox 投递循环出错");
        }
    }
}

async fn drain_due(client: &reqwest::Client, store: &Store, batch: i64) -> anyhow::Result<()> {
    const MAX_BACKOFF: i64 = 300;
    loop {
        let now = chrono::Utc::now().timestamp();
        let rows = store.outbox_due(now, batch)?;
        if rows.is_empty() {
            return Ok(());
        }
        for row in rows {
            match webhook::send_raw(client, &row.url, &row.body).await {
                Ok(()) => store.outbox_delete(row.id)?,
                Err(err) => {
                    let attempts = row.attempts + 1;
                    let backoff = 2i64.pow(attempts.min(9) as u32).min(MAX_BACKOFF);
                    store.outbox_schedule_retry(row.id, attempts, now + backoff)?;
                    tracing::warn!(
                        attempts,
                        retry_in_sec = backoff,
                        error = %err,
                        "webhook 投递失败，已排期重试"
                    );
                }
            }
        }
        // 若一批投完仍有更多到期条目则继续（受批次上限保护）
    }
}

/// 单个聚合键的会话状态。
struct KeyState {
    /// 最近一次实际发出（首条或摘要）的时间，聚合窗口与静默期都锚定在这里。
    last_sent: Instant,
    /// 聚合窗口内合并的后续事件；Some 即意味着有待发摘要。
    merged: Option<MergedAlert>,
    /// 该键出现过的最高级别（摘要按最高级别推送）。
    max_level: Level,
    /// 静默期内被抑制的事件数（计入下一条正文）。
    suppressed: u32,
}

struct MergedAlert {
    /// 最新一条事件的内容（摘要展示最新信息）。
    alert: Alert,
    /// 窗口内后续事件次数。
    extra: u32,
}

struct Dispatcher {
    cfg: AlertCfg,
    window: Duration,
    silence: Duration,
    targets: Vec<WebhookCfg>,
    delivery: Arc<Delivery>,
    store: Option<Arc<Store>>,
    wake: Option<Arc<Notify>>,
    rate: policy::RateLimiter,
    states: HashMap<String, KeyState>,
}

impl Dispatcher {
    fn new(
        cfg: AlertCfg,
        targets: Vec<WebhookCfg>,
        delivery: Arc<Delivery>,
        store: Option<Arc<Store>>,
        wake: Option<Arc<Notify>>,
    ) -> Self {
        let window = Duration::from_secs(cfg.aggregate_window_sec.max(1));
        let silence = Duration::from_secs(cfg.silence_sec);
        let rate = policy::RateLimiter::new(cfg.rate_limit_per_min);
        Self {
            cfg,
            window,
            silence,
            targets,
            delivery,
            store,
            wake,
            rate,
            states: HashMap::new(),
        }
    }

    async fn on_alert(&mut self, alert: Alert) {
        if alert.level < self.cfg.min_level && !alert.always_send {
            tracing::debug!(level = %alert.level, detector = %alert.detector, "低于 min_level，丢弃告警");
            return;
        }
        let key = alert.aggregate_key();
        let now = Instant::now();

        let Some(state) = self.states.get_mut(&key) else {
            self.emit(key, alert).await;
            return;
        };
        state.max_level = state.max_level.max(alert.level);

        if now < state.last_sent + self.window {
            let escalated = alert.level.max(
                state
                    .merged
                    .as_ref()
                    .map(|m| m.alert.level)
                    .unwrap_or(Level::Info),
            );
            let mut alert = alert;
            alert.level = escalated;
            match &mut state.merged {
                Some(m) => {
                    m.extra += 1;
                    m.alert = alert;
                }
                None => state.merged = Some(MergedAlert { alert, extra: 1 }),
            }
            tracing::debug!(key = %key, "聚合窗口内，合并同类告警");
        } else if !self.silence.is_zero() && now < state.last_sent + self.silence {
            state.suppressed += 1;
            tracing::debug!(key = %key, total = state.suppressed, "静默期内，抑制同类告警");
        } else {
            let mut alert = alert;
            alert.level = state.max_level;
            self.emit(key, alert).await;
        }
    }

    /// 限流 + 投递 + 重置该键状态。被限流丢弃时不更新状态，后续事件可再次尝试。
    async fn emit(&mut self, key: String, mut alert: Alert) {
        let now = Instant::now();
        if !self.rate.try_acquire(now) && alert.level != Level::Critical {
            tracing::warn!(key = %key, "触发限流，丢弃告警（critical 不受限流约束）");
            return;
        }
        let suppressed = self.states.get(&key).map(|s| s.suppressed).unwrap_or(0);
        if suppressed > 0 {
            alert.body = format!(
                "{}\n\n（静默期内另抑制了 {suppressed} 次同类事件）",
                alert.body
            );
        }

        // 记入告警日志（心跳/每日摘要的统计数据来源；失败不影响投递）
        if let Some(store) = &self.store {
            let ts = chrono::Utc::now().timestamp();
            if let Err(err) = store.alert_log_add(
                ts,
                alert.level,
                &alert.detector,
                &alert.title,
                &alert.aggregate_key(),
            ) {
                tracing::warn!(error = %err, "告警日志写入失败");
            }
        }

        if self.delivery.is_webhook()
            && let Some(store) = &self.store
        {
            // 持久化路径：渲染冻结进 outbox，由 worker 投递与重试
            let mut queued = 0usize;
            for wh in &self.targets {
                let rendered = template::render_body(wh, &alert)
                    .and_then(|body| Ok((body, template::build_url(wh)?)));
                match rendered {
                    Ok((body, url)) => {
                        let ts = chrono::Utc::now().timestamp();
                        match store.outbox_push(&url, &body, alert.level, ts) {
                            Ok(_) => queued += 1,
                            Err(err) => {
                                tracing::warn!(error = %err, "告警写入 outbox 失败，该目标将丢失")
                            }
                        }
                    }
                    Err(err) => tracing::warn!(error = %err, "告警渲染失败，跳过该目标"),
                }
            }
            if queued > 0
                && let Some(wake) = &self.wake
            {
                wake.notify_one();
            }
        } else {
            // 降级路径（Mock / 无存储）：单次直发，不重试
            let results = self.delivery.deliver(&self.targets, &alert).await;
            for (i, result) in results.iter().enumerate() {
                if let Err(err) = result {
                    tracing::warn!(provider = %self.targets[i].provider, error = %err, "webhook 投递失败（降级模式，无重试）");
                }
            }
        }

        self.states.insert(
            key,
            KeyState {
                last_sent: now,
                merged: None,
                max_level: alert.level,
                suppressed: 0,
            },
        );
    }

    async fn flush_keys(&mut self, keys: Vec<String>) {
        for key in keys {
            let Some(state) = self.states.get_mut(&key) else {
                continue;
            };
            let Some(merged) = state.merged.take() else {
                continue;
            };
            let mut alert = merged.alert;
            alert.level = state.max_level;
            alert.body = format!(
                "{}\n\n（聚合窗口内又有 {} 次同类事件）",
                alert.body, merged.extra
            );
            tracing::debug!(key = %key, extra = merged.extra, "发送聚合摘要");
            self.emit(key, alert).await;
        }
    }

    async fn flush_due(&mut self) {
        let now = Instant::now();
        let due: Vec<String> = self
            .states
            .iter()
            .filter(|(_, s)| s.merged.is_some() && now >= s.last_sent + self.window)
            .map(|(k, _)| k.clone())
            .collect();
        self.flush_keys(due).await;
    }

    /// 分发器退出前 flush 所有遗留摘要（进程优雅停止时不丢聚合中的事件）。
    async fn flush_all(&mut self) {
        let keys: Vec<String> = self
            .states
            .iter()
            .filter(|(_, s)| s.merged.is_some())
            .map(|(k, _)| k.clone())
            .collect();
        self.flush_keys(keys).await;
    }

    fn next_wait(&self, now: Instant) -> Duration {
        const IDLE: Duration = Duration::from_secs(1);
        self.states
            .values()
            .filter(|s| s.merged.is_some())
            .map(|s| s.last_sent + self.window)
            .min()
            .and_then(|deadline| deadline.checked_duration_since(now))
            .map(|w| w.min(IDLE))
            .unwrap_or(IDLE)
    }
}

async fn dispatcher_loop(
    mut rx: mpsc::Receiver<Alert>,
    cfg: AlertCfg,
    targets: Vec<WebhookCfg>,
    delivery: Arc<Delivery>,
    store: Option<Arc<Store>>,
    wake: Option<Arc<Notify>>,
) {
    let mut d = Dispatcher::new(cfg, targets, delivery, store, wake);
    loop {
        d.flush_due().await;
        let wait = d.next_wait(Instant::now());
        tokio::select! {
            maybe = rx.recv() => {
                let Some(alert) = maybe else {
                    d.flush_all().await;
                    tracing::info!("告警分发器退出");
                    return;
                };
                d.on_alert(alert).await;
            }
            _ = tokio::time::sleep(wait) => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mock_delivery() -> (Arc<Mutex<Vec<Alert>>>, Delivery) {
        let recorded = Arc::new(Mutex::new(Vec::new()));
        (recorded.clone(), Delivery::Mock(recorded))
    }

    fn cfg(min: Level, window_sec: u64, silence_sec: u64, rate: u32) -> AlertCfg {
        AlertCfg {
            min_level: min,
            rate_limit_per_min: rate,
            aggregate_window_sec: window_sec,
            silence_sec,
            webhooks: vec![],
            ..Default::default()
        }
    }

    fn alert(key: &str, level: Level) -> Alert {
        Alert::new(level, "det", format!("标题-{key}"), "内容").with_key(key)
    }

    /// 让分发器有机会处理已入队的告警（paused 时钟下 5ms 睡眠即会推进调度）。
    async fn settle() {
        for _ in 0..4 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    #[tokio::test(start_paused = true)]
    async fn first_alert_sends_immediately_and_merges_followups() {
        let (recorded, delivery) = mock_delivery();
        let (notifier, done) =
            Notifier::start(cfg(Level::Info, 60, 120, 100), vec![], delivery, None);

        notifier.publish(alert("k1", Level::Warning)).await.unwrap();
        settle().await;
        assert_eq!(recorded.lock().unwrap().len(), 1, "首条应立即发送");

        notifier.publish(alert("k1", Level::Info)).await.unwrap();
        notifier
            .publish(alert("k1", Level::Critical))
            .await
            .unwrap();
        settle().await;
        assert_eq!(
            recorded.lock().unwrap().len(),
            1,
            "窗口内应合并，不重复发送"
        );

        tokio::time::advance(Duration::from_secs(61)).await;
        settle().await;
        let got: Vec<Alert> = recorded.lock().unwrap().clone();
        assert_eq!(got.len(), 2, "窗口到期后应发送聚合摘要");
        assert!(
            got[1].body.contains("又有 2 次"),
            "摘要应包含合并次数，实际：{}",
            got[1].body
        );
        assert_eq!(got[1].level, Level::Critical, "摘要级别取窗口内最高");

        drop(notifier);
        done.shutdown().await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn silence_suppresses_then_recovers() {
        let (recorded, delivery) = mock_delivery();
        let (notifier, done) =
            Notifier::start(cfg(Level::Info, 60, 120, 100), vec![], delivery, None);

        notifier.publish(alert("k1", Level::Warning)).await.unwrap();
        settle().await; // t≈0 发出首条

        tokio::time::advance(Duration::from_secs(70)).await;
        settle().await; // 过窗口但无合并，无摘要
        assert_eq!(recorded.lock().unwrap().len(), 1);

        notifier.publish(alert("k1", Level::Warning)).await.unwrap(); // 静默期内
        settle().await;
        assert_eq!(recorded.lock().unwrap().len(), 1, "静默期内应抑制");

        tokio::time::advance(Duration::from_secs(65)).await; // t≈135 > 静默结束
        settle().await;
        notifier.publish(alert("k1", Level::Warning)).await.unwrap();
        settle().await;
        let got: Vec<Alert> = recorded.lock().unwrap().clone();
        assert_eq!(got.len(), 2, "静默期过后应恢复发送");
        assert!(
            got[1].body.contains("抑制了 1 次"),
            "恢复后的首条应带上抑制计数，实际：{}",
            got[1].body
        );

        drop(notifier);
        done.shutdown().await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn below_min_level_dropped() {
        let (recorded, delivery) = mock_delivery();
        let (notifier, done) =
            Notifier::start(cfg(Level::Warning, 60, 0, 100), vec![], delivery, None);
        notifier.publish(alert("k1", Level::Info)).await.unwrap();
        settle().await;
        assert!(recorded.lock().unwrap().is_empty());
        drop(notifier);
        done.shutdown().await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn rate_limit_drops_warning_but_not_critical() {
        let (recorded, delivery) = mock_delivery();
        let (notifier, done) = Notifier::start(cfg(Level::Info, 60, 0, 1), vec![], delivery, None);

        notifier.publish(alert("a", Level::Warning)).await.unwrap();
        settle().await; // 用掉唯一令牌

        notifier.publish(alert("b", Level::Warning)).await.unwrap();
        notifier.publish(alert("c", Level::Critical)).await.unwrap();
        settle().await;

        let got: Vec<Alert> = recorded.lock().unwrap().clone();
        assert_eq!(got.len(), 2, "warning 被限流丢弃，critical 不受限");
        assert!(
            got.iter().any(|a| a.title == "标题-a"),
            "首条 warning 已持令牌应送达"
        );
        assert!(got.iter().any(|a| a.title == "标题-c"), "critical 应送达");
        assert!(
            !got.iter().any(|a| a.title == "标题-b"),
            "第二条 warning 应被限流丢弃"
        );

        drop(notifier);
        done.shutdown().await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn shutdown_flushes_pending_summary() {
        let (recorded, delivery) = mock_delivery();
        let (notifier, done) =
            Notifier::start(cfg(Level::Info, 3600, 3600, 100), vec![], delivery, None);

        notifier.publish(alert("k1", Level::Warning)).await.unwrap();
        settle().await;
        notifier.publish(alert("k1", Level::Warning)).await.unwrap(); // 进入聚合
        settle().await;
        assert_eq!(recorded.lock().unwrap().len(), 1, "窗口未到期不应有摘要");

        drop(notifier); // 关闭发布端 → 分发器应 flush 聚合中的摘要后退出
        done.shutdown().await.unwrap();
        let got: Vec<Alert> = recorded.lock().unwrap().clone();
        assert_eq!(got.len(), 2, "退出前应 flush 聚合摘要");
        assert!(got[1].body.contains("又有 1 次"));
    }

    #[test]
    fn delivery_enum_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Delivery>();
    }
}
