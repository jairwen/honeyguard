//! DET-01 SSH 暴力破解 + DET-02 登录成功通知（PRD §5.1）。
//!
//! 暴力破解达到阈值（window_sec 内 max_failures 次）推送 critical 告警；
//! 开启 `ban` 时同步把来源 IP 写入防火墙封禁（见 [`crate::ban`]），
//! 封禁记录持久化，重启后恢复未到期封禁，到期自动解封。

use crate::alert::{Alert, Level};
use crate::ban::Firewall;
use crate::collectors::ssh::{LogSource, SshEvent};
use crate::config::{BanCfg, SshBruteforceCfg, SshLoginCfg, SshLoginMode};
use crate::notify::Notifier;
use crate::store::Store;
use crate::whitelist::Whitelist;
use anyhow::Result;
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

/// 检测器入口（由 supervised 监督）：管理日志源生命周期，源中断后 60s 重试。
/// 日志源完全不可用（如非 Linux 开发机）时降级为警告并周期重试，不让进程退出。
/// `store` 提供 new_ip 模式的登录 IP 持久化；None 时退化为内存集合（重启后丢失）。
/// `firewall` 提供 ban 动作的防火墙后端；None 时达到阈值仅告警不封禁。
pub async fn run(
    brute: SshBruteforceCfg,
    login: SshLoginCfg,
    whitelist: Arc<Whitelist>,
    notifier: Notifier,
    store: Option<Arc<Store>>,
    firewall: Option<Arc<dyn Firewall>>,
    token: CancellationToken,
) -> Result<()> {
    if !brute.enabled && (!login.enabled || login.mode == SshLoginMode::Off) {
        tracing::info!("ssh_bruteforce 与 ssh_login 均未启用，检测器不启动");
        return Ok(());
    }
    loop {
        tokio::select! {
            spawn_result = LogSource::spawn() => match spawn_result {
                Ok(events) => {
                    tokio::select! {
                        result = detect(
                            &brute, &login, &whitelist, &notifier,
                            store.as_deref(), firewall.clone(), events,
                        ) => {
                            if let Err(err) = result {
                                tracing::warn!(error = %err, "SSH 事件处理中断");
                            }
                        }
                        _ = token.cancelled() => return Ok(()),
                    }
                }
                Err(err) => {
                    tracing::warn!(error = %err, "SSH 日志源不可用（非 Linux 或无权限？），60s 后重试");
                }
            },
            _ = token.cancelled() => return Ok(()),
        }
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(60)) => {}
            _ = token.cancelled() => return Ok(()),
        }
    }
}

/// 事件消费主循环。独立成函数便于用合成事件流做行为测试。
async fn detect(
    brute: &SshBruteforceCfg,
    login: &SshLoginCfg,
    whitelist: &Whitelist,
    notifier: &Notifier,
    store: Option<&Store>,
    firewall: Option<Arc<dyn Firewall>>,
    mut events: mpsc::Receiver<SshEvent>,
) -> Result<()> {
    let window = Duration::from_secs(brute.window_sec.max(1));
    // 每个来源 IP 的失败记录（时间戳 + 用户名），滑动窗口
    let mut failures: HashMap<IpAddr, VecDeque<(Instant, Option<String>)>> = HashMap::new();
    // 已告警 IP → 告警时刻；窗口内不重复告警（跨窗口的持续爆破依赖 Notifier 静默期）
    let mut alerted: HashMap<IpAddr, Instant> = HashMap::new();
    // new_ip 模式已见 IP：优先持久化到 store，无 store 时退化为内存集合
    let mut seen_login_ips: HashSet<IpAddr> = HashSet::new();
    // 生效中的封禁：IP → 到期时刻（None = 永久）
    let mut bans: HashMap<IpAddr, Option<Instant>> =
        restore_bans(&brute.ban, store, firewall.as_ref()).await;

    loop {
        // 最近一个到期时刻：没有限时封禁时只等事件
        let next_expiry = bans.values().filter_map(Option::as_ref).copied().min();
        tokio::select! {
            event = events.recv() => {
                let Some(event) = event else { break };
                match event {
                    SshEvent::AuthFailure { user, ip } => {
                        if !brute.enabled || whitelist.allows_ip(ip) {
                            tracing::debug!(ip = %ip, "认证失败事件被跳过（未启用或白名单）");
                            continue;
                        }
                        let now = Instant::now();
                        let queue = failures.entry(ip).or_default();
                        queue.push_back((now, user));
                        while queue
                            .front()
                            .is_some_and(|(t, _)| now.duration_since(*t) > window)
                        {
                            queue.pop_front();
                        }
                        if (queue.len() as u32) < brute.max_failures {
                            continue;
                        }
                        if alerted
                            .get(&ip)
                            .is_some_and(|t| now.duration_since(*t) < window)
                        {
                            continue; // 本窗口已告警
                        }
                        alerted.insert(ip, now);
                        let ban_note =
                            enforce_ban(&brute.ban, firewall.as_ref(), store, &mut bans, ip).await;
                        let alert = Alert::new(
                            Level::Critical,
                            "ssh_bruteforce",
                            "SSH 暴力破解",
                            format!(
                                "来源 {ip} 在 {} 内认证失败 {} 次（阈值 {}），尝试用户：{}。{}",
                                human_duration(window),
                                queue.len(),
                                brute.max_failures,
                                top_users(queue),
                                ban_note,
                            ),
                        )
                        .with_key(ip.to_string());
                        notifier.publish(alert).await?;
                    }
                    SshEvent::AuthSuccess { user, ip, method } => {
                        if !login.enabled
                            || login.mode == SshLoginMode::Off
                            || whitelist.allows_ip(ip)
                            || whitelist.allows_user(&user)
                        {
                            tracing::debug!(ip = %ip, user = %user, "登录成功事件被跳过");
                            continue;
                        }
                        let (level, title, body) = match login.mode {
                            SshLoginMode::All => (
                                Level::Info,
                                "SSH 登录成功",
                                format!("用户 {user} 从 {ip} 通过 {method} 登录成功。"),
                            ),
                            SshLoginMode::NewIp => {
                                let first_seen = match store {
                                    Some(s) => {
                                        s.login_ip_first_seen(&ip, chrono::Utc::now().timestamp())?
                                    }
                                    None => seen_login_ips.insert(ip),
                                };
                                if !first_seen {
                                    continue; // 已知 IP，不打扰
                                }
                                (
                                    Level::Critical,
                                    "陌生 IP 登录成功",
                                    format!(
                                        "首次见到 {ip} 使用 {method} 登录用户 {user}。若非本人操作，立即检查！"
                                    ),
                                )
                            }
                            SshLoginMode::Off => unreachable!("前面已过滤"),
                        };
                        let alert =
                            Alert::new(level, "ssh_login", title, body).with_key(format!("{user}@{ip}"));
                        notifier.publish(alert).await?;
                    }
                }
            }
            // 没有限时封禁时该分支 pending，等价于只等事件
            _ = async {
                match next_expiry {
                    Some(deadline) => tokio::time::sleep_until(deadline).await,
                    None => std::future::pending::<()>().await,
                }
            } => {
                expire_bans(firewall.as_ref(), store, &mut bans).await;
            }
        }
    }
    Ok(()) // 日志源关闭
}

/// 启动时恢复持久化的封禁：未到期的确保防火墙规则在位（覆盖机器重启后规则丢失），
/// 已到期的顺手解封清理。检测器因日志源中断重启时本函数幂等。
async fn restore_bans(
    cfg: &BanCfg,
    store: Option<&Store>,
    firewall: Option<&Arc<dyn Firewall>>,
) -> HashMap<IpAddr, Option<Instant>> {
    let mut bans = HashMap::new();
    if !cfg.enabled {
        return bans;
    }
    let (Some(fw), Some(store)) = (firewall, store) else {
        return bans;
    };
    let now_wall = chrono::Utc::now().timestamp();
    for (ip, banned_at, duration_sec) in store.ban_load().unwrap_or_else(|e| {
        tracing::warn!(error = %e, "封禁记录读取失败，跳过恢复");
        Vec::new()
    }) {
        if duration_sec != 0 && banned_at + duration_sec <= now_wall {
            if let Err(e) = fw.unban(ip).await {
                tracing::warn!(error = %e, ip = %ip, "过期封禁解封失败（规则可能本就不在）");
            }
            if let Err(e) = store.ban_delete(&ip) {
                tracing::warn!(error = %e, ip = %ip, "过期封禁记录清理失败");
            }
            continue;
        }
        if let Err(e) = fw.ban(ip).await {
            tracing::warn!(error = %e, ip = %ip, "恢复封禁规则失败");
        }
        let deadline = if duration_sec == 0 {
            None
        } else {
            Some(Instant::now() + Duration::from_secs((banned_at + duration_sec - now_wall) as u64))
        };
        bans.insert(ip, deadline);
    }
    if !bans.is_empty() {
        tracing::info!(count = bans.len(), "已恢复未到期封禁");
    }
    bans
}

/// 达到阈值时执行封禁，返回追加到告警正文末尾的说明（未启用时为空串）。
async fn enforce_ban(
    cfg: &BanCfg,
    firewall: Option<&Arc<dyn Firewall>>,
    store: Option<&Store>,
    bans: &mut HashMap<IpAddr, Option<Instant>>,
    ip: IpAddr,
) -> String {
    if !cfg.enabled {
        return String::new();
    }
    let Some(fw) = firewall else {
        return "\n自动封禁不可用（未检测到 iptables/nft 或无权限），本次仅告警。".into();
    };
    if let Some(reason) = crate::ban::ban_refusal(ip, cfg.allow_private) {
        return format!("\n未自动封禁：{ip} 是{reason}。");
    }
    if bans.contains_key(&ip) {
        return "\n该 IP 已在封禁中。".into();
    }
    match fw.ban(ip).await {
        Ok(_) => {
            let (deadline, note) = if cfg.duration_sec == 0 {
                (
                    None,
                    format!("\n已自动封禁 {ip}（永久）。解封命令：honeyguard unban {ip}"),
                )
            } else {
                let duration = Duration::from_secs(cfg.duration_sec);
                (
                    Some(Instant::now() + duration),
                    format!(
                        "\n已自动封禁 {ip}，{} 后自动解封。提前解封：honeyguard unban {ip}",
                        human_duration(duration)
                    ),
                )
            };
            bans.insert(ip, deadline);
            if let Some(s) = store
                && let Err(e) =
                    s.ban_put(&ip, chrono::Utc::now().timestamp(), cfg.duration_sec as i64)
            {
                tracing::warn!(error = %e, "封禁记录持久化失败（重启后可能丢失）");
            }
            note
        }
        Err(e) => {
            tracing::warn!(error = %e, ip = %ip, "自动封禁执行失败");
            format!("\n自动封禁失败：{e:#}（检查 root 权限与 iptables/nftables）。")
        }
    }
}

/// 解封全部到期封禁；解封失败的保留记录并 60s 后重试。
async fn expire_bans(
    firewall: Option<&Arc<dyn Firewall>>,
    store: Option<&Store>,
    bans: &mut HashMap<IpAddr, Option<Instant>>,
) {
    let Some(fw) = firewall else { return };
    let now = Instant::now();
    let expired: Vec<IpAddr> = bans
        .iter()
        .filter(|(_, deadline)| deadline.is_some_and(|t| t <= now))
        .map(|(ip, _)| *ip)
        .collect();
    for ip in expired {
        match fw.unban(ip).await {
            Ok(_) => {
                tracing::info!(ip = %ip, "封禁到期，已解封");
                bans.remove(&ip);
                if let Some(s) = store
                    && let Err(e) = s.ban_delete(&ip)
                {
                    tracing::warn!(error = %e, ip = %ip, "到期封禁记录删除失败");
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, ip = %ip, "到期解封失败，60s 后重试");
                bans.insert(ip, Some(Instant::now() + Duration::from_secs(60)));
            }
        }
    }
}

/// 窗口内尝试用户 Top5。
fn top_users(queue: &VecDeque<(Instant, Option<String>)>) -> String {
    let mut counts: HashMap<&str, usize> = HashMap::new();
    for (_, user) in queue {
        *counts
            .entry(user.as_deref().unwrap_or("(未知)"))
            .or_default() += 1;
    }
    let mut entries: Vec<_> = counts.into_iter().collect();
    entries.sort_unstable_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(b.0)));
    let top: Vec<String> = entries
        .iter()
        .take(5)
        .map(|(user, count)| format!("{user}×{count}"))
        .collect();
    top.join("、")
}

fn human_duration(d: Duration) -> String {
    let secs = d.as_secs();
    if secs >= 60 && secs.is_multiple_of(60) {
        format!("{} 分钟", secs / 60)
    } else {
        format!("{secs} 秒")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ban::testutil::MockFirewall;
    use crate::config::AlertCfg;
    use crate::notify::{Delivery, Notifier as NotifierImpl};
    use crate::store::Store;
    use std::str::FromStr;
    use std::sync::{Arc, Mutex};

    fn ip(s: &str) -> IpAddr {
        IpAddr::from_str(s).unwrap()
    }

    async fn settle() {
        for _ in 0..6 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    fn notifier(min_level: Level) -> (Arc<Mutex<Vec<Alert>>>, Notifier) {
        let recorded = Arc::new(Mutex::new(Vec::new()));
        let (n, _) = NotifierImpl::start(
            AlertCfg {
                min_level,
                rate_limit_per_min: 1000,
                ..Default::default()
            },
            vec![],
            Delivery::Mock(recorded.clone()),
            None,
        );
        (recorded, n)
    }

    fn failure(user: Option<&str>, addr: IpAddr) -> SshEvent {
        SshEvent::AuthFailure {
            user: user.map(str::to_string),
            ip: addr,
        }
    }

    /// 以 'static 所有权 spawn 检测循环（detect 借用参数，spawn 要求自持有）。
    fn spawn_detect(
        brute: SshBruteforceCfg,
        login: SshLoginCfg,
        whitelist: Arc<Whitelist>,
        notifier: &Notifier,
        firewall: Option<Arc<MockFirewall>>,
        store: Option<Arc<Store>>,
        rx: mpsc::Receiver<SshEvent>,
    ) {
        let notifier = notifier.clone();
        let firewall: Option<Arc<dyn Firewall>> = firewall.map(|fw| fw as Arc<dyn Firewall>);
        tokio::spawn(async move {
            let _ = detect(
                &brute,
                &login,
                &whitelist,
                &notifier,
                store.as_deref(),
                firewall,
                rx,
            )
            .await;
        });
    }

    #[tokio::test(start_paused = true)]
    async fn brute_force_alerts_once_per_window() {
        let (recorded, notifier) = notifier(Level::Info);
        let (tx, rx) = mpsc::channel(64);
        let brute = SshBruteforceCfg {
            enabled: true,
            window_sec: 600,
            max_failures: 3,
            ..Default::default()
        };
        let login = SshLoginCfg {
            enabled: false,
            ..Default::default()
        };
        let whitelist = Arc::new(Whitelist::default());
        spawn_detect(
            brute.clone(),
            login.clone(),
            whitelist,
            &notifier,
            None,
            None,
            rx,
        );

        let attacker = ip("203.0.113.7");
        for i in 0..3 {
            tx.send(failure(Some(&format!("u{i}")), attacker))
                .await
                .unwrap();
        }
        settle().await;
        let got = recorded.lock().unwrap().clone();
        assert_eq!(got.len(), 1, "达到阈值应告警一次");
        assert_eq!(got[0].level, Level::Critical);
        assert_eq!(got[0].detector, "ssh_bruteforce");
        assert!(got[0].body.contains("203.0.113.7"), "{}", got[0].body);
        assert!(got[0].body.contains("失败 3 次"), "{}", got[0].body);

        // 同窗口内继续爆破：不再重复告警
        for _ in 0..5 {
            tx.send(failure(Some("root"), attacker)).await.unwrap();
        }
        settle().await;
        assert_eq!(recorded.lock().unwrap().len(), 1, "窗口内不重复告警");
    }

    #[tokio::test(start_paused = true)]
    async fn below_threshold_no_alert() {
        let (recorded, notifier) = notifier(Level::Info);
        let (tx, rx) = mpsc::channel(64);
        let brute = SshBruteforceCfg {
            enabled: true,
            window_sec: 600,
            max_failures: 20,
            ..Default::default()
        };
        let login = SshLoginCfg {
            enabled: false,
            ..Default::default()
        };
        let whitelist = Arc::new(Whitelist::default());
        spawn_detect(
            brute.clone(),
            login.clone(),
            whitelist,
            &notifier,
            None,
            None,
            rx,
        );
        for i in 0..19 {
            tx.send(failure(Some("root"), ip("203.0.113.7")))
                .await
                .unwrap();
            if i % 7 == 0 {
                settle().await;
            }
        }
        settle().await;
        assert!(recorded.lock().unwrap().is_empty(), "未达阈值不应告警");
    }

    #[tokio::test(start_paused = true)]
    async fn whitelist_ip_suppresses_failures() {
        let (recorded, notifier) = notifier(Level::Info);
        let (tx, rx) = mpsc::channel(64);
        let brute = SshBruteforceCfg {
            enabled: true,
            window_sec: 600,
            max_failures: 2,
            ..Default::default()
        };
        let login = SshLoginCfg {
            enabled: false,
            ..Default::default()
        };
        let whitelist = Arc::new(
            Whitelist::from_cfg(&crate::config::WhitelistCfg {
                ips: vec!["203.0.113.0/24".into()],
                ..Default::default()
            })
            .unwrap(),
        );
        spawn_detect(
            brute.clone(),
            login.clone(),
            whitelist,
            &notifier,
            None,
            None,
            rx,
        );
        for _ in 0..5 {
            tx.send(failure(Some("root"), ip("203.0.113.9")))
                .await
                .unwrap();
        }
        settle().await;
        assert!(
            recorded.lock().unwrap().is_empty(),
            "白名单 IP 不应触发告警"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn login_all_mode_notifies_every_success() {
        let (recorded, notifier) = notifier(Level::Info);
        let (tx, rx) = mpsc::channel(64);
        let brute = SshBruteforceCfg::default();
        let login = SshLoginCfg {
            enabled: true,
            mode: SshLoginMode::All,
        };
        let whitelist = Arc::new(Whitelist::default());
        spawn_detect(
            brute.clone(),
            login.clone(),
            whitelist,
            &notifier,
            None,
            None,
            rx,
        );
        tx.send(SshEvent::AuthSuccess {
            user: "deploy".into(),
            ip: ip("198.51.100.2"),
            method: "publickey".into(),
        })
        .await
        .unwrap();
        settle().await;
        let got = recorded.lock().unwrap().clone();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].level, Level::Info);
        assert_eq!(got[0].detector, "ssh_login");
        assert!(got[0].body.contains("deploy") && got[0].body.contains("198.51.100.2"));
    }

    #[tokio::test(start_paused = true)]
    async fn login_new_ip_mode_only_first_time_critical() {
        let (recorded, notifier) = notifier(Level::Info);
        let (tx, rx) = mpsc::channel(64);
        let brute = SshBruteforceCfg::default();
        let login = SshLoginCfg {
            enabled: true,
            mode: SshLoginMode::NewIp,
        };
        let whitelist = Arc::new(Whitelist::default());
        spawn_detect(
            brute.clone(),
            login.clone(),
            whitelist,
            &notifier,
            None,
            None,
            rx,
        );

        let success = SshEvent::AuthSuccess {
            user: "root".into(),
            ip: ip("198.51.100.9"),
            method: "password".into(),
        };
        tx.send(success.clone()).await.unwrap();
        settle().await;
        {
            let got = recorded.lock().unwrap().clone();
            assert_eq!(got.len(), 1);
            assert_eq!(got[0].level, Level::Critical, "陌生 IP 首登应为 critical");
        }

        // 静默期（默认 30 分钟）外同 IP 再登录：已知 IP 不再告警
        tokio::time::advance(Duration::from_secs(2400)).await;
        settle().await;
        tx.send(success).await.unwrap();
        settle().await;
        assert_eq!(recorded.lock().unwrap().len(), 1, "已知 IP 不应重复告警");
    }

    fn ban_cfg(duration_sec: u64) -> BanCfg {
        BanCfg {
            enabled: true,
            duration_sec,
            ..Default::default()
        }
    }

    #[tokio::test(start_paused = true)]
    async fn ban_executed_at_threshold_and_expires() {
        let (recorded, notifier) = notifier(Level::Info);
        let (tx, rx) = mpsc::channel(64);
        let brute = SshBruteforceCfg {
            enabled: true,
            window_sec: 600,
            max_failures: 3,
            ban: ban_cfg(60),
        };
        let login = SshLoginCfg::default();
        let whitelist = Arc::new(Whitelist::default());
        let fw = Arc::new(MockFirewall::default());
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::open(&dir.path().join("state.db")).unwrap());
        spawn_detect(
            brute,
            login,
            whitelist,
            &notifier,
            Some(fw.clone()),
            Some(store.clone()),
            rx,
        );

        let attacker = ip("203.0.113.7");
        for i in 0..3 {
            tx.send(failure(Some(&format!("u{i}")), attacker))
                .await
                .unwrap();
        }
        settle().await;
        let got = recorded.lock().unwrap().clone();
        assert_eq!(got.len(), 1);
        assert!(
            got[0].body.contains("已自动封禁 203.0.113.7"),
            "{}",
            got[0].body
        );
        assert!(fw.banned.lock().unwrap().contains(&attacker));
        assert_eq!(store.ban_load().unwrap().len(), 1, "封禁应持久化");

        // 60 秒到期自动解封并清理记录
        tokio::time::advance(Duration::from_secs(61)).await;
        settle().await;
        assert!(!fw.banned.lock().unwrap().contains(&attacker), "到期应解封");
        assert!(store.ban_load().unwrap().is_empty(), "到期应删记录");
    }

    #[tokio::test(start_paused = true)]
    async fn permanent_ban_never_expires() {
        let (recorded, notifier) = notifier(Level::Info);
        let (tx, rx) = mpsc::channel(64);
        let brute = SshBruteforceCfg {
            enabled: true,
            window_sec: 600,
            max_failures: 2,
            ban: ban_cfg(0),
        };
        let login = SshLoginCfg::default();
        let whitelist = Arc::new(Whitelist::default());
        let fw = Arc::new(MockFirewall::default());
        spawn_detect(
            brute,
            login,
            whitelist,
            &notifier,
            Some(fw.clone()),
            None,
            rx,
        );

        let attacker = ip("203.0.113.8");
        for _ in 0..2 {
            tx.send(failure(Some("root"), attacker)).await.unwrap();
        }
        settle().await;
        assert!(
            recorded.lock().unwrap()[0].body.contains("永久"),
            "永久封禁应说明"
        );

        // 很久之后仍在封禁中
        tokio::time::advance(Duration::from_secs(90 * 86400)).await;
        settle().await;
        assert!(fw.banned.lock().unwrap().contains(&attacker));
    }

    #[tokio::test(start_paused = true)]
    async fn private_ip_refused_by_default() {
        let (recorded, notifier) = notifier(Level::Info);
        let (tx, rx) = mpsc::channel(64);
        let brute = SshBruteforceCfg {
            enabled: true,
            window_sec: 600,
            max_failures: 2,
            ban: ban_cfg(3600),
        };
        let login = SshLoginCfg::default();
        let whitelist = Arc::new(Whitelist::default());
        let fw = Arc::new(MockFirewall::default());
        spawn_detect(
            brute,
            login,
            whitelist,
            &notifier,
            Some(fw.clone()),
            None,
            rx,
        );

        for _ in 0..3 {
            tx.send(failure(Some("root"), ip("192.168.1.5")))
                .await
                .unwrap();
        }
        settle().await;
        let got = recorded.lock().unwrap().clone();
        assert_eq!(got.len(), 1, "仍应告警");
        assert!(
            got[0].body.contains("未自动封禁") && got[0].body.contains("内网"),
            "{}",
            got[0].body
        );
        assert!(fw.banned.lock().unwrap().is_empty(), "内网默认不封");
    }

    #[tokio::test(start_paused = true)]
    async fn ban_failure_noted_in_alert() {
        let (recorded, notifier) = notifier(Level::Info);
        let (tx, rx) = mpsc::channel(64);
        let brute = SshBruteforceCfg {
            enabled: true,
            window_sec: 600,
            max_failures: 2,
            ban: ban_cfg(3600),
        };
        let login = SshLoginCfg::default();
        let whitelist = Arc::new(Whitelist::default());
        let fw = Arc::new(MockFirewall {
            fail: true,
            ..Default::default()
        });
        spawn_detect(brute, login, whitelist, &notifier, Some(fw), None, rx);

        for _ in 0..2 {
            tx.send(failure(Some("root"), ip("203.0.113.9")))
                .await
                .unwrap();
        }
        settle().await;
        let got = recorded.lock().unwrap().clone();
        assert_eq!(got.len(), 1);
        assert!(got[0].body.contains("自动封禁失败"), "{}", got[0].body);
    }

    #[tokio::test(start_paused = true)]
    async fn restores_bans_from_store_on_start() {
        let (tx, rx) = mpsc::channel(64);
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::open(&dir.path().join("state.db")).unwrap());
        let now = chrono::Utc::now().timestamp();
        let active = ip("203.0.113.7");
        let expired = ip("198.51.100.9");
        store.ban_put(&active, now - 100, 3600).unwrap(); // 剩 ~3500s
        store.ban_put(&expired, now - 7200, 3600).unwrap(); // 已过期 1h

        let fw = Arc::new(MockFirewall::default());
        // 模拟机器未重启时规则残留：过期 IP 规则仍在防火墙
        fw.ban(expired).await.unwrap();

        let (_, notifier) = notifier(Level::Info);
        let brute = SshBruteforceCfg {
            enabled: true,
            window_sec: 600,
            max_failures: 5,
            ban: ban_cfg(3600),
        };
        let login = SshLoginCfg::default();
        let whitelist = Arc::new(Whitelist::default());
        spawn_detect(
            brute,
            login,
            whitelist,
            &notifier,
            Some(fw.clone()),
            Some(store.clone()),
            rx,
        );
        settle().await;

        let banned = fw.banned.lock().unwrap().clone();
        assert!(banned.contains(&active), "未到期封禁应恢复规则");
        assert!(!banned.contains(&expired), "过期封禁应清理");
        let rows = store.ban_load().unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].0, active);
        drop(tx); // 结束检测循环
    }
}
