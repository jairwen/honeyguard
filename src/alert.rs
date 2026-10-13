//! 告警模型：分级与告警对象。

use chrono::{DateTime, Local};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::sync::{OnceLock, RwLock};

/// 主机名缓存：配置加载时写入，未设置时回退系统主机名。
static HOST: OnceLock<String> = OnceLock::new();

/// 出口公网 IP 缓存（egress 探测任务定期刷新；None = 未探测到/未启用）。
static EGRESS_IP: RwLock<Option<String>> = RwLock::new(None);

/// 设置全局主机名（配置 `server.host` 非空时调用一次）。
pub fn set_host(host: impl Into<String>) {
    let _ = HOST.set(host.into());
}

/// 更新出口公网 IP 展示值。
pub fn set_egress_ip(ip: Option<String>) {
    if let Ok(mut guard) = EGRESS_IP.write() {
        *guard = ip;
    }
}

/// 当前出口公网 IP（未探测到为 None）。
pub fn egress_ip() -> Option<String> {
    EGRESS_IP.read().ok().and_then(|g| g.clone())
}

/// 获取本机展示名：`NODEA(203.0.113.4)`（配置名/主机名 + 出口 IP，IP 未知时只有名字）。
pub fn host() -> String {
    let base = HOST.get().cloned().unwrap_or_else(|| {
        hostname::get()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|_| "unknown".into())
    });
    match egress_ip() {
        Some(ip) => format!("{base}({ip})"),
        None => base,
    }
}

/// 告警级别，顺序即严重程度：Info < Warning < Critical。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Level {
    Info,
    Warning,
    Critical,
}

impl fmt::Display for Level {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Level::Info => "info",
            Level::Warning => "warning",
            Level::Critical => "critical",
        })
    }
}

/// 一条待推送的告警。
#[derive(Debug, Clone)]
pub struct Alert {
    /// 短事件 ID（8 位十六进制），用于排查与去重。
    pub event_id: String,
    pub level: Level,
    /// 产生告警的检测器名，如 `ssh_bruteforce`。
    pub detector: String,
    pub title: String,
    pub body: String,
    /// 聚合主体（如同一来源 IP / 同一文件路径）。
    key: Option<String>,
    /// 绕过 min_level 过滤（心跳/摘要这类显式开启的主动通知）。
    pub always_send: bool,
    pub host: String,
    pub time: DateTime<Local>,
}

impl Alert {
    pub fn new(
        level: Level,
        detector: &str,
        title: impl Into<String>,
        body: impl Into<String>,
    ) -> Self {
        Self {
            event_id: new_event_id(),
            level,
            detector: detector.to_string(),
            title: title.into(),
            body: body.into(),
            key: None,
            always_send: false,
            host: host(),
            time: Local::now(),
        }
    }

    /// 设置聚合主体（检测器按需调用，如来源 IP、文件路径）。
    pub fn with_key(mut self, key: impl Into<String>) -> Self {
        self.key = Some(key.into());
        self
    }

    /// 绕过 min_level 过滤（心跳/摘要等显式开启的主动通知）。
    pub fn always_send(mut self) -> Self {
        self.always_send = true;
        self
    }

    /// 聚合键：`检测器:主体`（无主体时退化为标题）。
    pub fn aggregate_key(&self) -> String {
        format!(
            "{}:{}",
            self.detector,
            self.key.as_deref().unwrap_or(&self.title)
        )
    }
}

fn new_event_id() -> String {
    let id = uuid::Uuid::new_v4().simple().to_string();
    id[..8].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn level_ordering() {
        assert!(Level::Info < Level::Warning);
        assert!(Level::Warning < Level::Critical);
    }

    #[test]
    fn aggregate_key_uses_key_when_present() {
        let a = Alert::new(Level::Warning, "ssh_bruteforce", "t", "b").with_key("1.2.3.4");
        assert_eq!(a.aggregate_key(), "ssh_bruteforce:1.2.3.4");
        let b = Alert::new(Level::Warning, "ssh_login", "登录成功", "b");
        assert_eq!(b.aggregate_key(), "ssh_login:登录成功");
    }
}
