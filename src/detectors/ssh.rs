//! DET-01 SSH 暴力破解 + DET-02 登录成功通知（PRD §5.1）。

use crate::alert::{Alert, Level};
use crate::collectors::ssh::{LogSource, SshEvent};
use crate::config::{SshBruteforceCfg, SshLoginCfg, SshLoginMode};
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
pub async fn run(
    brute: SshBruteforceCfg,
    login: SshLoginCfg,
    whitelist: Arc<Whitelist>,
    notifier: Notifier,
    store: Option<Arc<Store>>,
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
                        result = detect(&brute, &login, &whitelist, &notifier, store.as_deref(), events) => {
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
    mut events: mpsc::Receiver<SshEvent>,
) -> Result<()> {
    let window = Duration::from_secs(brute.window_sec.max(1));
    // 每个来源 IP 的失败记录（时间戳 + 用户名），滑动窗口
    let mut failures: HashMap<IpAddr, VecDeque<(Instant, Option<String>)>> = HashMap::new();
    // 已告警 IP → 告警时刻；窗口内不重复告警（跨窗口的持续爆破依赖 Notifier 静默期）
    let mut alerted: HashMap<IpAddr, Instant> = HashMap::new();
    // new_ip 模式已见 IP：优先持久化到 store，无 store 时退化为内存集合
    let mut seen_login_ips: HashSet<IpAddr> = HashSet::new();

    while let Some(event) = events.recv().await {
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
                let alert = Alert::new(
                    Level::Critical,
                    "ssh_bruteforce",
                    "SSH 暴力破解",
                    format!(
                        "来源 {ip} 在 {} 内认证失败 {} 次（阈值 {}），尝试用户：{}。\n建议：确认是否为合法访问，必要时封禁该 IP 并改用密钥登录。",
                        human_duration(window),
                        queue.len(),
                        brute.max_failures,
                        top_users(queue),
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
    Ok(()) // 日志源关闭
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
    use crate::config::AlertCfg;
    use crate::notify::{Delivery, Notifier as NotifierImpl};
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
        rx: mpsc::Receiver<SshEvent>,
    ) {
        let notifier = notifier.clone();
        tokio::spawn(async move {
            let _ = detect(&brute, &login, &whitelist, &notifier, None, rx).await;
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
        };
        let login = SshLoginCfg {
            enabled: false,
            ..Default::default()
        };
        let whitelist = Arc::new(Whitelist::default());
        spawn_detect(brute.clone(), login.clone(), whitelist, &notifier, rx);

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
        };
        let login = SshLoginCfg {
            enabled: false,
            ..Default::default()
        };
        let whitelist = Arc::new(Whitelist::default());
        spawn_detect(brute.clone(), login.clone(), whitelist, &notifier, rx);
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
        spawn_detect(brute.clone(), login.clone(), whitelist, &notifier, rx);
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
        spawn_detect(brute.clone(), login.clone(), whitelist, &notifier, rx);
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
        spawn_detect(brute.clone(), login.clone(), whitelist, &notifier, rx);

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
}
