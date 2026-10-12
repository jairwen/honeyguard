//! DET-04 可疑进程检测（PRD §5.1）：CPU 差分采样 + 挖矿特征匹配。
//!
//! 每 interval 读取 `/proc/[pid]/stat` 的 utime+stime 做差分得到 CPU 占用；
//! 持续超阈值达 duration 且命中挖矿特征（进程名/命令行关键词，或可执行文件位于
//! /tmp、/dev/shm、/var/tmp 等常见恶意落地区）→ critical；
//! 高 CPU 但无特征 → 仅 info 日志（PRD：默认不推送）。

use crate::alert::{Alert, Level};
use crate::config::ProcessCfg;
use crate::notify::Notifier;
use crate::whitelist::Whitelist;
use anyhow::Result;
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

/// Linux CLK_TCK 实际恒为 100（userspace ABI 保证），无需 sysconf。
const CLK_TCK: f64 = 100.0;

const MINER_SIGNS: &[&str] = &[
    "kdevtmpfsi",
    "kinsing",
    "xmrig",
    "minerd",
    "cpuminer",
    "stratum+tcp",
    "stratum+ssl",
    "--donate-level",
    "cryptonight",
    "moneroocean",
    "nanopool",
    "nicehash",
    "supportxmr",
    "pool.hashvault",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatSample {
    pub comm: String,
    pub utime: u64,
    pub stime: u64,
    pub ppid: i32,
}

/// 解析 /proc/[pid]/stat（comm 可含空格与括号，按最后一个 ')' 切分）。
pub fn parse_stat(content: &str) -> Option<StatSample> {
    let open = content.find('(')?;
    let close = content.rfind(')')?;
    let comm = content[open + 1..close].to_string();
    // ')' 之后从第 3 字段（state）开始：ppid=idx1, utime=idx11, stime=idx12
    let fields: Vec<&str> = content[close + 1..].split_whitespace().collect();
    Some(StatSample {
        comm,
        ppid: fields.get(1)?.parse().ok()?,
        utime: fields.get(11)?.parse().ok()?,
        stime: fields.get(12)?.parse().ok()?,
    })
}

/// 挖矿/恶意特征判定：名称或命令行命中关键词，或 exe 位于常见恶意落地目录。
pub fn looks_like_miner(comm: &str, cmdline: &str, exe: &str) -> bool {
    let haystack = format!("{comm} {cmdline}").to_lowercase();
    if MINER_SIGNS.iter().any(|sign| haystack.contains(sign)) {
        return true;
    }
    const SUSPICIOUS_DIRS: &[&str] = &["/tmp/", "/dev/shm/", "/var/tmp/", "/run/shm/"];
    !exe.is_empty() && SUSPICIOUS_DIRS.iter().any(|dir| exe.starts_with(dir))
}

pub async fn run(
    cfg: ProcessCfg,
    whitelist: Arc<Whitelist>,
    notifier: Notifier,
    token: CancellationToken,
) -> Result<()> {
    if !Path::new("/proc").exists() {
        tracing::warn!("process 检测器：/proc 不可用（非 Linux？），不启动");
        return Ok(());
    }
    let interval = Duration::from_secs(cfg.interval_sec.max(1));
    let duration = Duration::from_secs(cfg.duration_sec.max(interval.as_secs()));
    // pid → (累计 ticks, 采样时刻)
    let mut prev: HashMap<i32, (u64, Instant)> = HashMap::new();
    // pid → 首次超阈值时刻 / 已告警标记
    let mut above_since: HashMap<i32, Instant> = HashMap::new();
    let mut alerted: HashMap<i32, String> = HashMap::new(); // pid → comm（防 pid 复用误判）
    tracing::info!(
        interval_sec = cfg.interval_sec,
        cpu_threshold = cfg.cpu_threshold,
        duration_sec = cfg.duration_sec,
        "process 检测器已启动"
    );

    loop {
        tokio::select! {
            _ = tokio::time::sleep(interval) => {}
            _ = token.cancelled() => {
                tracing::info!("process 检测器退出");
                return Ok(());
            }
        }
        let now = Instant::now();
        let current = sample_all();
        let live: Vec<i32> = current.keys().copied().collect();

        for (pid, stat) in &current {
            let Some(&(past_ticks, past_at)) = prev.get(pid) else {
                continue;
            };
            let elapsed = now.duration_since(past_at).as_secs_f64();
            if elapsed < interval.as_secs_f64() * 0.5 {
                continue; // 采样间隔异常，跳过本轮差分
            }
            let delta_ticks = (stat.utime + stat.stime).saturating_sub(past_ticks);
            let cpu_pct = delta_ticks as f64 / CLK_TCK / elapsed * 100.0;
            let comm = stat.comm.as_str();

            if cpu_pct >= cfg.cpu_threshold as f64 {
                let since = *above_since.entry(*pid).or_insert(now);
                let sustained_for = now.duration_since(since);
                if sustained_for < duration || alerted.contains_key(pid) {
                    continue;
                }
                let exe = read_link(&format!("/proc/{pid}/exe"));
                let cmdline = read_cmdline(*pid);
                if whitelist.allows_process(comm)
                    || exe.as_deref().is_some_and(|e| whitelist.allows_process(e))
                {
                    tracing::debug!(pid, comm, "高 CPU 进程命中白名单，跳过");
                    continue;
                }
                if looks_like_miner(comm, &cmdline, exe.as_deref().unwrap_or("")) {
                    let parent = read_comm(stat.ppid);
                    let alert = Alert::new(
                        Level::Critical,
                        "process",
                        "疑似挖矿进程",
                        format!(
                            "进程 {comm} (pid {pid}) CPU 占用 {cpu_pct:.0}% 已持续 {} 秒，命中挖矿特征。\nexe：{}\n命令行：{}\n父进程：{} (pid {})\n建议：立即隔离排查，检查 crontab 与 systemd 定时器。",
                            sustained_for.as_secs(),
                            exe.as_deref().unwrap_or("(未知)"),
                            cmdline,
                            parent.as_deref().unwrap_or("(未知)"),
                            stat.ppid,
                        ),
                    )
                    .with_key(format!("{comm}:{pid}"));
                    notifier.publish(alert).await?;
                    alerted.insert(*pid, comm.to_string());
                } else {
                    // PRD DET-04：高 CPU 无特征 → info 仅记录，默认不推送
                    tracing::info!(
                        pid,
                        comm,
                        cpu = format!("{cpu_pct:.0}%"),
                        "进程持续高 CPU（未命中挖矿特征，仅记录）"
                    );
                }
            } else {
                above_since.remove(pid);
                // 进程 CPU 回落后允许再次告警（挖矿进程可能被 attacker 重启降载规避）
                if alerted.get(pid).is_some_and(|a| a == comm) {
                    alerted.remove(pid);
                }
            }
        }

        // 更新基线 & 清理已退出进程的状态
        prev.clear();
        for pid in live {
            if let Some(stat) = current.get(&pid) {
                prev.insert(pid, (stat.utime + stat.stime, now));
            }
        }
        let live_set: Vec<i32> = prev.keys().copied().collect();
        above_since.retain(|pid, _| live_set.contains(pid));
        alerted.retain(|pid, _| live_set.contains(pid));
    }
}

/// 扫描 /proc 下全部进程的 stat（/proc 体量小，同步读取代价可忽略）。
fn sample_all() -> HashMap<i32, StatSample> {
    let mut out = HashMap::new();
    let Ok(dir) = std::fs::read_dir("/proc") else {
        return out;
    };
    for entry in dir.flatten() {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|s| s.parse::<i32>().ok())
        else {
            continue;
        };
        if let Ok(content) = std::fs::read_to_string(format!("/proc/{pid}/stat"))
            && let Some(stat) = parse_stat(&content)
        {
            out.insert(pid, stat);
        }
    }
    out
}

fn read_link(path: &str) -> Option<String> {
    std::fs::read_link(path)
        .ok()
        .map(|p| p.to_string_lossy().into_owned())
}

fn read_cmdline(pid: i32) -> String {
    std::fs::read_to_string(format!("/proc/{pid}/cmdline"))
        .map(|s| s.trim_matches('\0').replace('\0', " "))
        .unwrap_or_default()
}

fn read_comm(pid: i32) -> Option<String> {
    std::fs::read_to_string(format!("/proc/{pid}/comm"))
        .ok()
        .map(|s| s.trim().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_stat_with_spaces_in_comm() {
        // "Web Content" 含空格；字段编号按 man proc_pid_stat
        let content = "1234 (Web Content) R 1200 1234 1200 34816 1234 4194624 12345 0 1 2 56000 7800 0 0 20 0 12 0 98765 0";
        let stat = parse_stat(content).expect("应解析成功");
        assert_eq!(stat.comm, "Web Content");
        assert_eq!(stat.utime, 56000);
        assert_eq!(stat.stime, 7800);
        assert_eq!(stat.ppid, 1200);
    }

    #[test]
    fn parses_simple_stat() {
        let content = "42 (sshd) S 1 42 42 0 -1 4194624 100 0 0 0 10 5 0 0 20 0 8 0 55555";
        let stat = parse_stat(content).unwrap();
        assert_eq!(stat.comm, "sshd");
        assert_eq!(stat.utime, 10);
        assert_eq!(stat.stime, 5);
    }

    #[test]
    fn rejects_garbage() {
        assert!(parse_stat("not a stat line").is_none());
    }

    #[test]
    fn miner_signatures_detected() {
        assert!(looks_like_miner("kdevtmpfsi", "", "/tmp/kdevtmpfsi"));
        assert!(looks_like_miner(
            "python3",
            "run.py -o stratum+tcp://pool.x:3333",
            "/usr/bin/python3"
        ));
        assert!(looks_like_miner("bash", "", "/dev/shm/x")); // 可疑落地目录
        assert!(!looks_like_miner("node", "server.js", "/usr/bin/node"));
        assert!(!looks_like_miner("mysqld", "", "/usr/sbin/mysqld"));
        // 空白 exe 不应命中可疑目录规则
        assert!(!looks_like_miner("bash", "", ""));
    }
}
