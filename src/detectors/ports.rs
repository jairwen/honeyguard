//! DET-06 新增监听端口检测（PRD §5.1）：周期扫描 LISTEN socket 与 SQLite 基线比对。
//!
//! 新出现的监听端口 → warning（后门/反弹 shell 的常见前置动作），并附带归属进程。
//! 端口消失保留基线条目（避免正常服务重启造成误报）；重新出现的新端口才会告警。
//! 首次运行建基线不告警；`honeyguard baseline update` 重建。

use crate::alert::{Alert, Level};
use crate::config::ListenPortsCfg;
use crate::detectors::net::{TCP_LISTEN, parse_proc_net};
use crate::notify::Notifier;
use crate::store::Store;
use anyhow::Result;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio_util::sync::CancellationToken;

pub async fn run(
    cfg: ListenPortsCfg,
    notifier: Notifier,
    store: Option<Arc<Store>>,
    token: CancellationToken,
) -> Result<()> {
    if !Path::new("/proc/net/tcp").exists() {
        tracing::warn!("listen_ports 检测器：/proc/net 不可用（非 Linux？），不启动");
        return Ok(());
    }
    let Some(store) = store else {
        tracing::warn!("listen_ports 检测器：状态数据库不可用，无法建立基线，不启动");
        return Ok(());
    };
    let interval = Duration::from_secs(cfg.interval_sec.max(1));
    tracing::info!(interval_sec = cfg.interval_sec, "listen_ports 检测器已启动");
    loop {
        tokio::select! {
            _ = tokio::time::sleep(interval) => {}
            _ = token.cancelled() => {
                tracing::info!("listen_ports 检测器退出");
                return Ok(());
            }
        }
        if let Err(err) = scan(&notifier, &store).await {
            tracing::warn!(error = %err, "listen_ports 扫描出错");
        }
    }
}

/// 一轮扫描：返回新出现的监听端口数。
pub async fn scan(notifier: &Notifier, store: &Store) -> Result<usize> {
    let Some(listeners) = current_listeners() else {
        return Ok(0); // /proc 暂不可读，跳过本轮
    };
    // (ip, port) → inode（ip 字符串化便于与基线比对）
    let current: Vec<((String, u16), u64)> = listeners
        .into_iter()
        .map(|(addr, inode)| ((addr.ip().to_string(), addr.port()), inode))
        .collect();

    let baseline = store.listen_load()?;
    if baseline.is_empty() {
        for ((ip, port), _) in &current {
            store.listen_put(ip, *port)?;
        }
        tracing::info!(count = current.len(), "listen_ports 基线已建立");
        return Ok(0);
    }

    let mut alerts = 0usize;
    for ((ip, port), inode) in &current {
        let key = (ip.clone(), *port);
        if baseline.contains(&key) {
            continue;
        }
        store.listen_put(ip, *port)?; // 立即入基线，避免下轮重复告警
        let owner = super::net::find_socket_owner(*inode)
            .map(|(pid, comm, cmdline)| format!("进程 {comm} (pid {pid})，命令行：{cmdline}"))
            .unwrap_or_else(|| "归属进程未知".to_string());
        let alert = Alert::new(
            Level::Warning,
            "listen_ports",
            "新增监听端口",
            format!("新增监听 {ip}:{port}\n{owner}\n请确认是否为合法服务。"),
        )
        .with_key(format!("{ip}:{port}"));
        if notifier.publish(alert).await.is_ok() {
            alerts += 1;
        }
    }
    if alerts > 0 {
        tracing::warn!(alerts, "listen_ports 检测到新增监听端口");
    }
    Ok(alerts)
}

/// `honeyguard baseline update`：重建端口基线。返回条目数。
pub fn rebuild_baseline(store: &Store) -> Result<usize> {
    store.listen_clear()?;
    let Some(listeners) = current_listeners() else {
        return Ok(0);
    };
    for (addr, _) in &listeners {
        store.listen_put(&addr.ip().to_string(), addr.port())?;
    }
    Ok(listeners.len())
}

/// 扫描 /proc/net/tcp{,6} 的 LISTEN 表项：(本地地址, socket inode)。
fn current_listeners() -> Option<Vec<(SocketAddr, u64)>> {
    let mut out = Vec::new();
    for (file, ipv6) in [("/proc/net/tcp", false), ("/proc/net/tcp6", true)] {
        let Ok(data) = std::fs::read_to_string(file) else {
            continue;
        };
        for entry in parse_proc_net(&data, ipv6) {
            if entry.state == TCP_LISTEN {
                out.push((entry.local, entry.inode));
            }
        }
    }
    Some(out)
}
