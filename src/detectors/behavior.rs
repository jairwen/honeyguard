//! DET-09 行为基线：通过长期观测构建“进程 ↔ 通信对象”画像，发现异常通信习惯。
//!
//! 模型（全部持久化在 SQLite）：
//! - **进程画像**（behavior_procs）：以 exe 路径为身份，记录首次出现时间、
//!   历史并发外连峰值、是否“广泛连接型”（P2P/BT 类）；
//! - **通信关系**（behavior_pairs）：(exe, 远端 IP) 粒度的观测记录。
//!
//! 判定规则：
//! - 首次扫描为**普查**：存量进程与关系全部静默入档（避免装机告警风暴）；
//! - 每个进程有学习期（默认 7 天，自首次被观测起算）：期内只记录不告警；
//! - 学习期满的进程连接**未见过的远端 IP** → warning（告警一次后关系转正）；
//! - **全新进程**首次出现在外连中 → warning（新落地的程序在对外通信）；
//! - **广泛连接型**（远端 IP 去重数 ≥ 阈值，如 P2P/种子/BT 客户端）：
//!   陌生 IP 不再告警（其本性就是连海量节点），改为监控**并发激增**
//!   （当前并发 ≥ 峰值 N 倍且 ≥ 绝对下限）→ warning（疑似被用于扫描/DDoS）。
//!
//! `honeyguard baseline` 清空行为基线重新学习。

use crate::alert::{Alert, Level};
use crate::config::BehaviorCfg;
use crate::detectors::net::{TCP_ESTABLISHED, UDP_CONNECTED, build_inode_map, parse_proc_net};
use crate::notify::Notifier;
use crate::store::{BehaviorProc, Store};
use crate::whitelist::Whitelist;
use anyhow::Result;
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio_util::sync::CancellationToken;

pub async fn run(
    cfg: BehaviorCfg,
    whitelist: Arc<Whitelist>,
    notifier: Notifier,
    store: Option<Arc<Store>>,
    token: CancellationToken,
) -> Result<()> {
    if !Path::new("/proc/net/tcp").exists() {
        tracing::warn!("behavior 检测器：/proc/net 不可用（非 Linux？），不启动");
        return Ok(());
    }
    let Some(store) = store else {
        tracing::warn!("behavior 检测器：状态数据库不可用，无长期观测能力，不启动");
        return Ok(());
    };
    let interval = Duration::from_secs(cfg.interval_sec.max(1));
    tracing::info!(
        interval_sec = cfg.interval_sec,
        learn_days = cfg.learn_sec / 86400,
        p2p_ip_threshold = cfg.p2p_ip_threshold,
        "behavior 检测器已启动"
    );
    loop {
        tokio::select! {
            _ = tokio::time::sleep(interval) => {}
            _ = token.cancelled() => {
                tracing::info!("behavior 检测器退出");
                return Ok(());
            }
        }
        let inputs = collect();
        let now = chrono::Utc::now().timestamp();
        if let Err(err) = process_scan(&inputs, &cfg, &whitelist, &notifier, &store, now).await {
            tracing::warn!(error = %err, "behavior 扫描出错");
        }
    }
}

/// 一轮扫描的输入：按 exe 聚合的通信对象（同 IP 去重，取任一端口）。
#[derive(Debug, Clone)]
pub struct ScanInput {
    pub exe: String,
    pub comm: String,
    pub remotes: HashMap<IpAddr, u16>,
}

/// 单条 (进程, 远端) 关系的判定结论。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// 静默记录（学习期 / 已知关系 / 广泛连接型的陌生 IP）。
    Record,
    /// 全新进程首次出现在外连中。
    AlertNewProcess,
    /// 学习期满的进程连接了未见过的远端。
    AlertUnknownPeer,
}

/// 纯判定函数（便于行为测试）。
pub fn judge(
    profile: Option<&BehaviorProc>,
    pair_known: bool,
    now: i64,
    cfg: &BehaviorCfg,
) -> Verdict {
    let Some(p) = profile else {
        return Verdict::AlertNewProcess;
    };
    let age = (now - p.first_seen).max(0) as u64;
    if age < cfg.learn_sec {
        return Verdict::Record; // 学习期
    }
    if pair_known || p.p2p_like {
        return Verdict::Record;
    }
    Verdict::AlertUnknownPeer
}

/// 并发激增判定（广泛连接型专用；纯函数）。
pub fn is_spike(p: &BehaviorProc, current: u32, cfg: &BehaviorCfg) -> bool {
    p.p2p_like
        && p.max_concurrent > 0
        && current >= cfg.spike_min
        && current as u64 >= cfg.spike_factor as u64 * p.max_concurrent as u64
}

/// 处理一轮扫描：普查 / 学习 / 告警 / 画像更新。返回告警数。
pub async fn process_scan(
    inputs: &[ScanInput],
    cfg: &BehaviorCfg,
    whitelist: &Whitelist,
    notifier: &Notifier,
    store: &Store,
    now: i64,
) -> Result<usize> {
    let mut profiles = store.behavior_procs_load()?;
    let census = profiles.is_empty(); // 首轮：存量进程静默普查
    let mut alerts = 0usize;

    for input in inputs {
        if whitelist.allows_process(&input.exe) || whitelist.allows_process(&input.comm) {
            continue;
        }
        let profile = profiles.get(&input.exe).cloned();
        let profile_ref = profile.as_ref();
        let current = input.remotes.len() as u32;
        let spike = profile_ref.is_some_and(|p| !census && is_spike(p, current, cfg));

        if !census {
            for (ip, port) in &input.remotes {
                if whitelist.allows_ip(*ip) {
                    continue;
                }
                let known = store
                    .behavior_pair_hits(&input.exe, &ip.to_string())?
                    .is_some();
                match judge(profile_ref, known, now, cfg) {
                    Verdict::AlertNewProcess => {
                        let alert = Alert::new(
                            Level::Warning,
                            "behavior",
                            "新进程发起外连",
                            format!(
                                "新进程 {}（{}）首次出现在出站连接中，目标 {ip}:{port}。\n该进程已进入为期 {} 天的观测期。若非你部署的程序，请立即排查！",
                                input.exe,
                                input.comm,
                                cfg.learn_sec / 86400,
                            ),
                        )
                        .with_key(input.exe.clone());
                        notifier.publish(alert).await?;
                        alerts += 1;
                    }
                    Verdict::AlertUnknownPeer => {
                        let known_peers = store.behavior_distinct_ips(&input.exe)?;
                        let alert = Alert::new(
                            Level::Warning,
                            "behavior",
                            "进程通信对象异常",
                            format!(
                                "进程 {}（{}）连接了观测期内未出现过的远端 {ip}:{port}（其已知通信对象 {known_peers} 个）。\n若非业务变更（新版本/新依赖），请排查该连接。",
                                input.exe, input.comm,
                            ),
                        )
                        .with_key(format!("{}:{ip}", input.exe));
                        notifier.publish(alert).await?;
                        alerts += 1;
                    }
                    Verdict::Record => {}
                }
                // 告警与否都落库：未知关系告警一次后转正，新进程进入学习期
                store.behavior_pair_touch(&input.exe, &ip.to_string(), *port, now)?;
            }

            if spike && let Some(p) = profile_ref {
                let alert = Alert::new(
                    Level::Warning,
                    "behavior",
                    "广泛连接型进程并发激增",
                    format!(
                        "进程 {}（{}）当前并发出站连接 {} 条，达历史峰值 {} 的 {} 倍以上。\n疑似被用于扫描/DDoS 或行为异常，请确认。",
                        input.exe,
                        input.comm,
                        current,
                        p.max_concurrent,
                        current / p.max_concurrent.max(1),
                    ),
                )
                .with_key(input.exe.clone());
                notifier.publish(alert).await?;
                alerts += 1;
            }
        } else {
            // 普查：只入档
            for (ip, port) in &input.remotes {
                store.behavior_pair_touch(&input.exe, &ip.to_string(), *port, now)?;
            }
        }

        // 画像维护
        if profile.is_none() {
            store.behavior_proc_insert(&input.exe, &input.comm, now)?;
            profiles.insert(
                input.exe.clone(),
                BehaviorProc {
                    comm: input.comm.clone(),
                    first_seen: now,
                    last_seen: now,
                    p2p_like: false,
                    max_concurrent: 0,
                },
            );
        }
        // 广泛连接型判定（去重 IP 数达阈值）
        let distinct = store.behavior_distinct_ips(&input.exe)?;
        let p2p = distinct >= cfg.p2p_ip_threshold as i64;
        if p2p && profile.is_some_and(|p| !p.p2p_like) {
            tracing::info!(
                exe = %input.exe,
                distinct,
                "behavior：进程已识别为广泛连接型（P2P 类），陌生 IP 不再告警，转为并发监控"
            );
        }
        store.behavior_proc_touch(&input.exe, now, current, p2p)?;
    }

    if census {
        tracing::info!(procs = inputs.len(), "behavior 首轮普查完成，画像已建立");
    } else if alerts > 0 {
        tracing::warn!(alerts, "behavior 检测到异常通信行为");
    }
    Ok(alerts)
}

/// 从 /proc 采集当前出站连接并按进程聚合（TCP ESTABLISHED + UDP 已连接，排除回环）。
fn collect() -> Vec<ScanInput> {
    let inode_map = build_inode_map();
    let mut by_exe: HashMap<String, ScanInput> = HashMap::new();
    for (file, ipv6, tcp) in [
        ("/proc/net/tcp", false, true),
        ("/proc/net/tcp6", true, true),
        ("/proc/net/udp", false, false),
        ("/proc/net/udp6", true, false),
    ] {
        let Ok(data) = std::fs::read_to_string(file) else {
            continue;
        };
        let wanted = if tcp { TCP_ESTABLISHED } else { UDP_CONNECTED };
        for entry in parse_proc_net(&data, ipv6) {
            if entry.state != wanted || entry.remote.port() == 0 || entry.remote.ip().is_loopback()
            {
                continue;
            }
            let Some((_, comm, exe)) = inode_map.get(&entry.inode) else {
                continue; // 归属不明的连接交给 outbound 检测器
            };
            if exe.is_empty() {
                continue;
            }
            let input = by_exe.entry(exe.clone()).or_insert_with(|| ScanInput {
                exe: exe.clone(),
                comm: comm.clone(),
                remotes: HashMap::new(),
            });
            input
                .remotes
                .entry(entry.remote.ip())
                .or_insert(entry.remote.port());
        }
    }
    by_exe.into_values().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alert::Level as L;
    use crate::config::AlertCfg;
    use crate::notify::{Delivery, Notifier as NotifierImpl};
    use std::str::FromStr;
    use std::sync::Mutex;

    fn notifier() -> (Arc<Mutex<Vec<Alert>>>, Notifier) {
        let recorded = Arc::new(Mutex::new(Vec::new()));
        let (n, _) = NotifierImpl::start(
            AlertCfg {
                min_level: L::Info,
                rate_limit_per_min: 10_000,
                silence_sec: 0,
                ..Default::default()
            },
            vec![],
            Delivery::Mock(recorded.clone()),
            None,
        );
        (recorded, n)
    }

    fn cfg(learn_sec: u64, p2p_threshold: u32, spike_min: u32, spike_factor: u32) -> BehaviorCfg {
        BehaviorCfg {
            enabled: true,
            interval_sec: 60,
            learn_sec,
            p2p_ip_threshold: p2p_threshold,
            spike_factor,
            spike_min,
        }
    }

    fn input(exe: &str, ips: &[&str]) -> ScanInput {
        ScanInput {
            exe: exe.to_string(),
            comm: "test-proc".to_string(),
            remotes: ips
                .iter()
                .map(|s| (IpAddr::from_str(s).unwrap(), 443u16))
                .collect(),
        }
    }

    async fn settle() {
        for _ in 0..4 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    #[tokio::test]
    async fn census_then_learn_then_unknown_peer_alerts_once() {
        let (recorded, notifier) = notifier();
        let store = Store::open(Path::new(":memory:")).unwrap();
        let cfg = cfg(100, 50, 40, 4);
        let wl = Whitelist::default();

        // 首轮普查：静默
        let n = process_scan(
            &[input("/usr/bin/app", &["10.0.0.1"])],
            &cfg,
            &wl,
            &notifier,
            &store,
            1000,
        )
        .await
        .unwrap();
        assert_eq!(n, 0);

        // 学习期内（+50s）：新对象也静默
        let n = process_scan(
            &[input("/usr/bin/app", &["10.0.0.1", "10.0.0.2"])],
            &cfg,
            &wl,
            &notifier,
            &store,
            1050,
        )
        .await
        .unwrap();
        assert_eq!(n, 0, "学习期不应告警");

        // 学习期满（+200s）：陌生对象告警
        let n = process_scan(
            &[input("/usr/bin/app", &["10.0.0.1", "10.0.0.2", "10.0.0.3"])],
            &cfg,
            &wl,
            &notifier,
            &store,
            1200,
        )
        .await
        .unwrap();
        assert_eq!(n, 1, "应为 10.0.0.3 告警一次");
        settle().await;
        {
            let got = recorded.lock().unwrap().clone();
            assert_eq!(got.len(), 1);
            assert_eq!(got[0].title, "进程通信对象异常");
            assert!(got[0].body.contains("10.0.0.3"), "{}", got[0].body);
        }

        // 同一对象再次出现：已转正，不重复告警
        let n = process_scan(
            &[input("/usr/bin/app", &["10.0.0.1", "10.0.0.3"])],
            &cfg,
            &wl,
            &notifier,
            &store,
            1300,
        )
        .await
        .unwrap();
        assert_eq!(n, 0, "告警过的关系应转正");
    }

    #[tokio::test]
    async fn new_process_alerts_once() {
        let (recorded, notifier) = notifier();
        let store = Store::open(Path::new(":memory:")).unwrap();
        let cfg = cfg(100, 50, 40, 4);
        let wl = Whitelist::default();

        process_scan(
            &[input("/usr/bin/known", &["10.0.0.1"])],
            &cfg,
            &wl,
            &notifier,
            &store,
            1000,
        )
        .await
        .unwrap();
        let n = process_scan(
            &[
                input("/usr/bin/known", &["10.0.0.1"]),
                input("/tmp/malware", &["203.0.113.9"]),
            ],
            &cfg,
            &wl,
            &notifier,
            &store,
            1100,
        )
        .await
        .unwrap();
        assert_eq!(n, 1, "新进程应告警一次");
        settle().await;
        {
            let got = recorded.lock().unwrap().clone();
            assert_eq!(got.len(), 1);
            assert_eq!(got[0].title, "新进程发起外连");
            assert!(got[0].body.contains("/tmp/malware"));
        }

        // 下一轮：新进程仍在学习期（age 50 < 100），静默
        let n = process_scan(
            &[
                input("/usr/bin/known", &["10.0.0.1"]),
                input("/tmp/malware", &["203.0.113.9", "203.0.113.10"]),
            ],
            &cfg,
            &wl,
            &notifier,
            &store,
            1150,
        )
        .await
        .unwrap();
        assert_eq!(n, 0);
    }

    #[tokio::test]
    async fn p2p_classification_and_spike_alert() {
        let (recorded, notifier) = notifier();
        let store = Store::open(Path::new(":memory:")).unwrap();
        // 学习期 0：立刻进入判定；3 个去重 IP 即判 P2P；并发 ≥5 且 ≥2×峰值告警
        let cfg = cfg(0, 3, 5, 2);
        let wl = Whitelist::default();

        // 普查建档
        process_scan(
            &[input("/usr/bin/p2p", &["10.0.0.1", "10.0.0.2", "10.0.0.3"])],
            &cfg,
            &wl,
            &notifier,
            &store,
            1000,
        )
        .await
        .unwrap();
        // 再来两个新 IP：普查轮末已按去重数 3 ≥3 标记 p2p，本轮陌生 IP 静默
        let n = process_scan(
            &[input(
                "/usr/bin/p2p",
                &["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.1.0.1", "10.1.0.2"],
            )],
            &cfg,
            &wl,
            &notifier,
            &store,
            1100,
        )
        .await
        .unwrap();
        assert_eq!(n, 0, "广泛连接型进程的陌生 IP 不应告警");
        settle().await;
        recorded.lock().unwrap().clear();

        // 已是广泛连接型：陌生 IP 不告警
        let n = process_scan(
            &[input("/usr/bin/p2p", &["10.0.0.1", "10.2.0.9"])],
            &cfg,
            &wl,
            &notifier,
            &store,
            1200,
        )
        .await
        .unwrap();
        assert_eq!(n, 0, "广泛连接型的陌生 IP 不应告警");

        // 并发激增：此前峰值 5，现在 12 条（≥5 且 ≥2×5=10）→ 告警
        let ips: Vec<String> = (1..=12).map(|i| format!("10.30.0.{i}")).collect();
        let refs: Vec<&str> = ips.iter().map(String::as_str).collect();
        let n = process_scan(
            &[input("/usr/bin/p2p", &refs)],
            &cfg,
            &wl,
            &notifier,
            &store,
            1300,
        )
        .await
        .unwrap();
        assert_eq!(n, 1, "并发激增应告警（既有新 IP 不叠加）");
        settle().await;
        let got = recorded.lock().unwrap().clone();
        assert!(
            got.iter().any(|a| a.title == "广泛连接型进程并发激增"),
            "{:?}",
            got.iter().map(|a| &a.title).collect::<Vec<_>>()
        );
    }

    #[tokio::test]
    async fn whitelisted_process_fully_skipped() {
        let (recorded, notifier) = notifier();
        let store = Store::open(Path::new(":memory:")).unwrap();
        let cfg = cfg(0, 50, 40, 4);
        let wl = Whitelist::from_cfg(&crate::config::WhitelistCfg {
            processes: vec!["/usr/bin/known-*".into()],
            ..Default::default()
        })
        .unwrap();
        process_scan(
            &[input("/usr/bin/known-app", &["10.0.0.1"])],
            &cfg,
            &wl,
            &notifier,
            &store,
            1000,
        )
        .await
        .unwrap();
        let n = process_scan(
            &[input("/usr/bin/known-app", &["10.0.0.1", "198.51.100.1"])],
            &cfg,
            &wl,
            &notifier,
            &store,
            2000,
        )
        .await
        .unwrap();
        assert_eq!(n, 0, "白名单进程完全跳过");
        assert!(
            store.behavior_procs_load().unwrap().is_empty(),
            "白名单进程不入档"
        );
        assert!(recorded.lock().unwrap().is_empty());
    }

    #[test]
    fn judge_matrix() {
        let cfg = cfg(100, 50, 40, 4);
        let learned = BehaviorProc {
            comm: "x".into(),
            first_seen: 0,
            last_seen: 0,
            p2p_like: false,
            max_concurrent: 10,
        };
        let learning = BehaviorProc {
            first_seen: 10_000 - 50, // age 50 < learn_sec 100
            ..learned.clone()
        };
        let p2p = BehaviorProc {
            p2p_like: true,
            ..learned.clone()
        };
        let now = 10_000i64;

        assert_eq!(judge(None, false, now, &cfg), Verdict::AlertNewProcess);
        assert_eq!(judge(Some(&learning), false, now, &cfg), Verdict::Record);
        assert_eq!(judge(Some(&learned), true, now, &cfg), Verdict::Record);
        assert_eq!(
            judge(Some(&learned), false, now, &cfg),
            Verdict::AlertUnknownPeer
        );
        assert_eq!(judge(Some(&p2p), false, now, &cfg), Verdict::Record);
    }

    #[test]
    fn spike_guard_clauses() {
        let cfg = cfg(0, 3, 5, 2);
        let p = BehaviorProc {
            comm: "p".into(),
            first_seen: 0,
            last_seen: 0,
            p2p_like: true,
            max_concurrent: 10,
        };
        assert!(!is_spike(&p, 4, &cfg), "低于绝对下限");
        assert!(!is_spike(&p, 15, &cfg), "未达倍数");
        assert!(is_spike(&p, 20, &cfg), "5 且 2×10 达标");
        let no_history = BehaviorProc {
            max_concurrent: 0,
            ..p.clone()
        };
        assert!(!is_spike(&no_history, 100, &cfg), "无历史峰值不判定");
        let not_p2p = BehaviorProc {
            p2p_like: false,
            ..p
        };
        assert!(!is_spike(&not_p2p, 100, &cfg), "非广泛连接型不判定");
    }
}
