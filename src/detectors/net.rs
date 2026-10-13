//! DET-03 可疑出站连接（PRD §5.1）：周期解析 `/proc/net/tcp{,6}` 与 `udp{,6}`。
//!
//! 规则：目的端口命中矿池黑名单或 IP 命中本地黑名单文件 → critical；
//! 非 53/80/123/443 端口上的 ESTABLISHED 连接持续 ≥ 3 个扫描周期 → warning
//! （与 DET-09 行为基线联动去噪：连接可归属且归属进程已被行为画像跟踪——
//! 含学习期与广泛连接型——时不触发，交由行为基线判定；无法归属进程的连接仍告警）。
//! 告警正文附带 socket 归属进程（通过 `/proc/[pid]/fd` 的 socket inode 反查，尽力而为）。

use crate::alert::{Alert, Level};
use crate::config::OutboundCfg;
use crate::notify::Notifier;
use crate::store::Store;
use crate::whitelist::Whitelist;
use anyhow::Result;
use ipnet::IpNet;
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tokio_util::sync::CancellationToken;

/// 视为“常见业务端口”的长连接不告警。
const COMMON_PORTS: &[u16] = &[53, 80, 123, 443];
/// 长连接判定所需连续出现的扫描周期数。
const SUSTAINED_CYCLES: u32 = 3;
/// TCP state 01 = ESTABLISHED；UDP 的“已连接”表项固定为 07。
pub(crate) const TCP_ESTABLISHED: u8 = 0x01;
pub(crate) const UDP_CONNECTED: u8 = 0x07;
/// TCP state 0A = LISTEN（供 listen_ports 检测器复用）。
pub(crate) const TCP_LISTEN: u8 = 0x0A;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnEntry {
    pub local: SocketAddr,
    pub remote: SocketAddr,
    pub state: u8,
    pub uid: u32,
    pub inode: u64,
}

/// 解析 /proc/net/{tcp,tcp6,udp,udp6} 内容（纯函数，fixture 测试）。
pub fn parse_proc_net(data: &str, ipv6: bool) -> Vec<ConnEntry> {
    let mut out = Vec::new();
    for line in data.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 10 {
            continue;
        }
        let Some(local) = parse_addr_port(fields[1], ipv6) else {
            continue;
        };
        let Some(remote) = parse_addr_port(fields[2], ipv6) else {
            continue;
        };
        let Ok(state) = u8::from_str_radix(fields[3], 16) else {
            continue;
        };
        let Ok(uid) = fields[7].parse() else { continue };
        let Ok(inode) = fields[9].parse() else {
            continue;
        };
        out.push(ConnEntry {
            local,
            remote,
            state,
            uid,
            inode,
        });
    }
    out
}

/// "0100007F:0016" → 127.0.0.1:22（内核侧为小端十六进制）。
fn parse_addr_port(s: &str, ipv6: bool) -> Option<SocketAddr> {
    let (hex_addr, hex_port) = s.split_once(':')?;
    let port = u16::from_str_radix(hex_port, 16).ok()?;
    let ip = if ipv6 {
        // 内核把 IPv6 按 4 个 32 位小端字输出：每 8 个 hex 字符一个字，逐字字节翻转
        let hex_bytes = hex_addr.as_bytes();
        if hex_bytes.len() != 32 {
            return None;
        }
        let mut fixed = [0u8; 16];
        let (words, _) = hex_bytes.as_chunks::<8>();
        for (i, chunk) in words.iter().enumerate() {
            let word = u32::from_str_radix(std::str::from_utf8(chunk.as_slice()).ok()?, 16).ok()?;
            fixed[i * 4..i * 4 + 4].copy_from_slice(&word.swap_bytes().to_be_bytes());
        }
        IpAddr::V6(Ipv6Addr::from(fixed))
    } else {
        let bits = u32::from_str_radix(hex_addr, 16).ok()?;
        IpAddr::V4(Ipv4Addr::from(bits.swap_bytes()))
    };
    Some(SocketAddr::new(ip, port))
}

pub async fn run(
    cfg: OutboundCfg,
    whitelist: Arc<Whitelist>,
    notifier: Notifier,
    store: Option<Arc<Store>>,
    token: CancellationToken,
) -> Result<()> {
    if !Path::new("/proc/net/tcp").exists() {
        tracing::warn!("outbound 检测器：/proc/net 不可用（非 Linux？），不启动");
        return Ok(());
    }
    let blocklist = load_blocklists(&cfg.blocklist_files);
    let interval = Duration::from_secs(cfg.interval_sec.max(1));
    // remote → 连续出现周期数 + 是否已告警（断开后重连可再次告警）
    let mut sustained: HashMap<SocketAddr, (u32, bool)> = HashMap::new();
    tracing::info!(
        interval_sec = cfg.interval_sec,
        bad_ports = cfg.bad_ports.len(),
        blocklist_nets = blocklist.len(),
        behavior_linked = store.is_some(),
        "outbound 检测器已启动"
    );

    loop {
        tokio::select! {
            _ = tokio::time::sleep(interval) => {}
            _ = token.cancelled() => {
                tracing::info!("outbound 检测器退出");
                return Ok(());
            }
        }
        let mut entries = Vec::new();
        for (file, ipv6, tcp) in [
            ("/proc/net/tcp", false, true),
            ("/proc/net/tcp6", true, true),
            ("/proc/net/udp", false, false),
            ("/proc/net/udp6", true, false),
        ] {
            if let Ok(data) = std::fs::read_to_string(file) {
                let wanted = if tcp { TCP_ESTABLISHED } else { UDP_CONNECTED };
                entries.extend(
                    parse_proc_net(&data, ipv6)
                        .into_iter()
                        .filter(|e| e.state == wanted && e.remote.port() != 0),
                );
            }
        }

        let mut seen: HashSet<SocketAddr> = HashSet::new();
        for entry in &entries {
            let remote = entry.remote;
            if !seen.insert(remote) {
                continue; // 同一 remote 多条 socket 只处理一次
            }
            let rip = remote.ip();
            if whitelist.allows_ip(rip) {
                continue;
            }
            if cfg.bad_ports.contains(&remote.port()) {
                let alert = build_alert(
                    Level::Critical,
                    "可疑外连：矿池/可疑端口",
                    &format!("命中可疑端口黑名单 {remote}"),
                    entry,
                );
                notifier.publish(alert.with_key(remote.to_string())).await?;
                continue;
            }
            if blocklist.iter().any(|net| net.contains(&rip)) {
                let alert = build_alert(
                    Level::Critical,
                    "可疑外连：命中恶意 IP 黑名单",
                    &format!("远程 {rip} 命中本地黑名单"),
                    entry,
                );
                notifier.publish(alert.with_key(rip.to_string())).await?;
                continue;
            }
            // 长连接判定（非黑名单路径）
            let (cycles, alerted) = sustained.entry(remote).or_insert((0, false));
            *cycles += 1;
            // 行为基线联动去噪：连接可归属且归属进程已被行为画像跟踪（含学习期与
            // 广泛连接型）时，其通信习惯由 DET-09 负责判定，本规则不再打扰；
            // 无行为基线（无存储）或无法归属进程的连接仍按原规则告警。
            let behavior_tracked = store.as_ref().is_some_and(|store| {
                find_socket_owner(entry.inode)
                    .map(|(_, _, _, exe)| {
                        !exe.is_empty() && store.behavior_proc_known(&exe).unwrap_or(false)
                    })
                    .unwrap_or(false)
            });
            if should_alert_sustained(*cycles, *alerted, remote.port(), behavior_tracked) {
                *alerted = true;
                let alert = build_alert(
                    Level::Warning,
                    "可疑长连接",
                    &format!("非通用端口上的连接已持续 {} 个扫描周期", *cycles),
                    entry,
                );
                notifier.publish(alert.with_key(remote.to_string())).await?;
            }
        }
        // 清理已消失的连接
        sustained.retain(|remote, _| seen.contains(remote));
    }
}

/// 可疑长连接判定（纯函数，联动行为基线去噪）。
/// `behavior_tracked`：连接可归属且归属进程已被行为画像跟踪（DET-09 域）。
pub(crate) fn should_alert_sustained(
    cycles: u32,
    alerted: bool,
    port: u16,
    behavior_tracked: bool,
) -> bool {
    cycles >= SUSTAINED_CYCLES && !alerted && !COMMON_PORTS.contains(&port) && !behavior_tracked
}

fn build_alert(level: Level, title: &str, reason: &str, entry: &ConnEntry) -> Alert {
    let owner = find_socket_owner(entry.inode)
        .map(|(pid, comm, cmdline, _)| format!("进程 {comm} (pid {pid})，命令行：{cmdline}"))
        .unwrap_or_else(|| "归属进程未知（需要 root 权限或连接已消失）".to_string());
    Alert::new(
        level,
        "outbound",
        title,
        format!(
            "{reason}\n本地 {} → 远程 {}\nuid {}，inode {}\n{owner}",
            entry.local, entry.remote, entry.uid, entry.inode
        ),
    )
}

/// 通过 socket inode 反查归属进程：遍历 /proc/[pid]/fd/* 的 "socket:[inode]" 链接。
/// 返回 (pid, comm, cmdline, exe)。
pub(crate) fn find_socket_owner(inode: u64) -> Option<(i32, String, String, String)> {
    let dir = std::fs::read_dir("/proc").ok()?;
    for entry in dir.flatten() {
        let name = entry.file_name();
        let Some(pid) = name.to_str().and_then(|s| s.parse::<i32>().ok()) else {
            continue;
        };
        let fd_dir = entry.path().join("fd");
        let Ok(fds) = std::fs::read_dir(&fd_dir) else {
            continue;
        };
        for fd in fds.flatten() {
            if let Ok(target) = std::fs::read_link(fd.path())
                && target.to_string_lossy() == format!("socket:[{inode}]")
            {
                let comm = std::fs::read_to_string(format!("/proc/{pid}/comm"))
                    .map(|s| s.trim().to_string())
                    .unwrap_or_default();
                let cmdline = std::fs::read_to_string(format!("/proc/{pid}/cmdline"))
                    .map(|s| s.trim_matches('\0').replace('\0', " "))
                    .unwrap_or_default();
                let exe = std::fs::read_link(format!("/proc/{pid}/exe"))
                    .map(|p| {
                        p.to_string_lossy()
                            .trim_end_matches(" (deleted)")
                            .to_string()
                    })
                    .unwrap_or_default();
                return Some((pid, comm, cmdline, exe));
            }
        }
    }
    None
}

/// 单次遍历 /proc 建立 inode → (pid, comm, exe) 映射，供行为基线每轮批量归属。
pub(crate) fn build_inode_map() -> std::collections::HashMap<u64, (i32, String, String)> {
    let mut map = std::collections::HashMap::new();
    let Ok(dir) = std::fs::read_dir("/proc") else {
        return map;
    };
    for entry in dir.flatten() {
        let name = entry.file_name();
        let Some(pid) = name.to_str().and_then(|s| s.parse::<i32>().ok()) else {
            continue;
        };
        let fd_dir = entry.path().join("fd");
        let Ok(fds) = std::fs::read_dir(&fd_dir) else {
            continue;
        };
        let comm = std::fs::read_to_string(format!("/proc/{pid}/comm"))
            .map(|s| s.trim().to_string())
            .unwrap_or_default();
        let exe = std::fs::read_link(format!("/proc/{pid}/exe"))
            .map(|p| {
                p.to_string_lossy()
                    .trim_end_matches(" (deleted)")
                    .to_string()
            })
            .unwrap_or_default();
        for fd in fds.flatten() {
            if let Ok(target) = std::fs::read_link(fd.path())
                && let Some(rest) = target.to_string_lossy().strip_prefix("socket:[")
                && let Ok(inode) = rest.trim_end_matches(']').parse::<u64>()
            {
                map.insert(inode, (pid, comm.clone(), exe.clone()));
            }
        }
    }
    map
}

/// 加载本地黑名单文件（每行一个 IP 或 CIDR，# 注释）；坏行告警跳过，不让检测器挂掉。
fn load_blocklists(files: &[std::path::PathBuf]) -> Vec<IpNet> {
    let mut nets = Vec::new();
    for file in files {
        match std::fs::read_to_string(file) {
            Ok(content) => {
                for (no, line) in content.lines().enumerate() {
                    let line = line.split('#').next().unwrap_or("").trim();
                    if line.is_empty() {
                        continue;
                    }
                    match IpNet::from_str(line) {
                        Ok(net) => nets.push(net),
                        Err(_) => {
                            tracing::warn!(file = %file.display(), line = no + 1, "黑名单行无法解析，已跳过")
                        }
                    }
                }
                tracing::info!(file = %file.display(), "已加载黑名单文件");
            }
            Err(err) => {
                tracing::warn!(file = %file.display(), error = %err, "黑名单文件读取失败，跳过")
            }
        }
    }
    nets
}

#[cfg(test)]
mod tests {
    use super::*;

    const TCP_FIXTURE: &str = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n \
        0: 0100007F:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 12345 1 0000000000000000 100 0 0 10 0\n \
        1: 0100007F:9C4A 69A1C2B4:0D05 01 00000000:00000000 00:00000000 00000000     0        0 54321 1 0000000000000000 24 4 30 10 -1\n \
        2: 00000000:0000 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 11111 1 0000000000000000 100 0 0 10 0\n";

    #[test]
    fn parses_ipv4_entries() {
        let entries = parse_proc_net(TCP_FIXTURE, false);
        assert_eq!(entries.len(), 3, "表头应被跳过");
        let listen = &entries[0];
        assert_eq!(
            listen.local,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 22)
        );
        assert_eq!(listen.state, 0x0A, "LISTEN");
        assert_eq!(listen.inode, 12345);
        let established = &entries[1];
        assert_eq!(established.local.port(), 0x9C4A);
        // 69A1C2B4 小端翻转 → 180.194.161.105
        assert_eq!(
            established.remote.ip(),
            IpAddr::V4(Ipv4Addr::new(180, 194, 161, 105))
        );
        assert_eq!(established.remote.port(), 0x0D05, "3333 矿池端口");
        assert_eq!(established.state, TCP_ESTABLISHED);
        assert_eq!(established.uid, 0);
        assert_eq!(established.inode, 54321);
    }

    #[test]
    fn parses_ipv6_entries() {
        // ::1 内核形态为 00000000×3 + 01000000；2001:db8::1 = b80d0120 + 0×16 + 01000000
        let local_hex = format!("{}01000000", "00000000".repeat(3));
        let remote_hex = format!("{}{}01000000", "b80d0120", "0".repeat(16));
        assert_eq!(local_hex.len(), 32);
        assert_eq!(remote_hex.len(), 32);
        let fixture = format!(
            "  sl  local_address rem_address st ...\n \
             0: {local_hex}:0035 {remote_hex}:D042 01 0:0 00:0 0 0 0 99999\n"
        );
        let entries = parse_proc_net(&fixture, true);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].local.ip(), IpAddr::V6(Ipv6Addr::LOCALHOST));
        assert_eq!(entries[0].local.port(), 53);
        assert_eq!(
            entries[0].remote.ip(),
            IpAddr::V6(Ipv6Addr::from_str("2001:db8::1").unwrap())
        );
        assert_eq!(entries[0].remote.port(), 0xD042);
        assert_eq!(entries[0].inode, 99999);
    }

    #[test]
    fn common_port_set_excludes_miner_ports() {
        assert!(COMMON_PORTS.contains(&443));
        assert!(!COMMON_PORTS.contains(&3333));
    }

    #[test]
    fn sustained_rule_suppressed_by_behavior_baseline() {
        // 无行为基线（未跟踪）：达到周期即告警
        assert!(should_alert_sustained(SUSTAINED_CYCLES, false, 8080, false));
        assert!(
            !should_alert_sustained(SUSTAINED_CYCLES - 1, false, 8080, false),
            "未达周期"
        );
        assert!(
            !should_alert_sustained(SUSTAINED_CYCLES, true, 8080, false),
            "已告警过"
        );
        assert!(
            !should_alert_sustained(SUSTAINED_CYCLES, false, 443, false),
            "通用端口"
        );
        // 行为基线已跟踪该进程（学习期/已知关系/广泛连接型）：去噪，不再告警
        assert!(!should_alert_sustained(SUSTAINED_CYCLES, false, 8080, true));
    }
}
