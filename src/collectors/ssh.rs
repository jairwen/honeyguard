//! SSH 日志采集（PRD DET-01/DET-02 数据源）。
//!
//! 双轨源：优先 journald（`journalctl -f -n 0 -o json _COMM=sshd` 子进程），
//! 无 journalctl 时回退 tail `/var/log/auth.log`（含轮转处理）。
//! 两种源的行分别归一化为 [`SshEvent`]；解析函数均为纯函数，用真实格式样本测试。

use anyhow::{Context, Result};
use std::net::IpAddr;
use std::path::Path;
use std::process::Stdio;
use std::str::FromStr;
use tokio::io::{AsyncBufReadExt, AsyncSeekExt, BufReader};
use tokio::process::{Child, ChildStdout, Command};
use tokio::sync::mpsc;
use tokio::time::Duration;

const AUTH_LOG: &str = "/var/log/auth.log";

/// 从 sshd 日志解析出的关注事件（只保留检测器需要的部分）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SshEvent {
    /// 认证失败（Failed password / Invalid user / preauth 断开）。
    AuthFailure { user: Option<String>, ip: IpAddr },
    /// 认证成功。method 如 password / publickey。
    AuthSuccess {
        user: String,
        ip: IpAddr,
        method: String,
    },
}

/// 解析 sshd 单条消息（journald 的 MESSAGE 字段，或 auth.log 中 `sshd[pid]: ` 之后的部分）。
pub fn parse_sshd_message(msg: &str) -> Option<SshEvent> {
    // 按家族分组编译一次；regex 只在此模块使用。
    static PATTERNS: std::sync::OnceLock<Vec<regex::Regex>> = std::sync::OnceLock::new();
    let patterns = PATTERNS.get_or_init(|| {
        vec![
            // Failed password for root from 1.2.3.4 port 55555 ssh2
            // Failed publickey for invalid user admin from 1.2.3.4 port 4242 ssh2
            regex::Regex::new(
                r"Failed (?:password|publickey|none|keyboard-interactive\S*) for (?:invalid user )?(\S+) from (\S+) port",
            ).unwrap(),
            // Invalid user admin from 1.2.3.4 port 4242
            regex::Regex::new(r"Invalid user (\S+) from (\S+)").unwrap(),
            // Accepted publickey for root from 1.2.3.4 port 22 ssh2: ...
            regex::Regex::new(r"Accepted (\S+) for (\S+) from (\S+) port").unwrap(),
            // Connection closed by authenticating user root 1.2.3.4 port 55555 [preauth]
            // Connection closed by invalid user admin 1.2.3.4 port 55555 [preauth]
            regex::Regex::new(
                r"Connection closed by (?:authenticating |invalid )?user (\S+) (\S+) port",
            ).unwrap(),
        ]
    });

    if let Some(c) = patterns[0].captures(msg) {
        return Some(SshEvent::AuthFailure {
            user: Some(c[1].to_string()),
            ip: IpAddr::from_str(&c[2]).ok()?,
        });
    }
    if let Some(c) = patterns[1].captures(msg) {
        return Some(SshEvent::AuthFailure {
            user: Some(c[1].to_string()),
            ip: IpAddr::from_str(&c[2]).ok()?,
        });
    }
    if let Some(c) = patterns[2].captures(msg) {
        return Some(SshEvent::AuthSuccess {
            method: c[1].to_string(),
            user: c[2].to_string(),
            ip: IpAddr::from_str(&c[3]).ok()?,
        });
    }
    if let Some(c) = patterns[3].captures(msg) {
        return Some(SshEvent::AuthFailure {
            user: Some(c[1].to_string()),
            ip: IpAddr::from_str(&c[2]).ok()?,
        });
    }
    None
}

/// 解析 auth.log 整行（`Oct 12 03:14:15 host sshd[123]: Failed ...`）。
pub fn parse_auth_log_line(line: &str) -> Option<SshEvent> {
    let marker = "sshd[";
    let idx = line.find(marker)?;
    let rest = &line[idx..];
    let colon = rest.find(": ")?;
    parse_sshd_message(&rest[colon + 2..])
}

/// 解析 `journalctl -o json` 输出的单行。
pub fn parse_journald_line(line: &str) -> Option<SshEvent> {
    let value: serde_json::Value = serde_json::from_str(line).ok()?;
    let message = value.get("MESSAGE")?.as_str()?;
    parse_sshd_message(message)
}

/// SSH 日志源句柄：`spawn` 后台持续向返回的 channel 推送事件，源中断即 channel 关闭，
/// 由上层（[`crate::detectors::supervised`]）负责重启整个检测器。
pub struct LogSource;

impl LogSource {
    pub async fn spawn() -> Result<mpsc::Receiver<SshEvent>> {
        let (tx, rx) = mpsc::channel(1024);
        let mut command = Command::new("journalctl");
        command
            .args(["-f", "-n", "0", "-o", "json", "_COMM=sshd"])
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true);
        match command.spawn() {
            Ok(mut child) => {
                let stdout = child.stdout.take().context("获取 journalctl stdout")?;
                tracing::info!("SSH 日志源：journald（journalctl -f _COMM=sshd）");
                tokio::spawn(pump_journald(stdout, child, tx));
                Ok(rx)
            }
            // 没有 journalctl（容器/裁剪系统）→ 回退 auth.log
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                if Path::new(AUTH_LOG).exists() {
                    tracing::info!("SSH 日志源：tail {AUTH_LOG}");
                    tokio::spawn(tail_auth_log(tx, AUTH_LOG));
                    Ok(rx)
                } else {
                    Err(anyhow::anyhow!(
                        "无可用 SSH 日志源：journalctl 不存在，且 {AUTH_LOG} 不存在"
                    ))
                }
            }
            Err(e) => Err(e.into()),
        }
    }
}

async fn pump_journald(stdout: ChildStdout, mut child: Child, tx: mpsc::Sender<SshEvent>) {
    let mut lines = BufReader::new(stdout).lines();
    loop {
        match lines.next_line().await {
            Ok(Some(line)) => {
                if let Some(event) = parse_journald_line(&line)
                    && tx.send(event).await.is_err()
                {
                    break; // 检测器已退出
                }
            }
            Ok(None) => {
                tracing::warn!("journalctl 输出流关闭");
                break;
            }
            Err(e) => {
                tracing::warn!(error = %e, "读取 journalctl 输出失败");
                break;
            }
        }
    }
    let _ = child.wait().await;
}

/// tail 文件并推送解析后的事件；文件变短视为轮转，从头重读；文件消失则等待重试。
async fn tail_auth_log(tx: mpsc::Sender<SshEvent>, path: &str) {
    let mut pos: Option<u64> = None; // None = 首次打开，跳到文件末尾只看新增
    loop {
        match open_and_read(path, &mut pos).await {
            Ok(lines) => {
                for line in lines {
                    if let Some(event) = parse_auth_log_line(&line)
                        && tx.send(event).await.is_err()
                    {
                        return; // 检测器已退出
                    }
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, "读取 {path} 失败，稍后重试");
            }
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

async fn open_and_read(path: &str, pos: &mut Option<u64>) -> Result<Vec<String>> {
    use tokio::io::AsyncReadExt;
    let mut file = tokio::fs::File::open(path)
        .await
        .with_context(|| format!("打开 {path}"))?;
    let len = file.metadata().await?.len();
    match *pos {
        None => {
            // 只关注启动之后的新事件
            file.seek(std::io::SeekFrom::Start(len)).await?;
            *pos = Some(len);
            Ok(Vec::new())
        }
        Some(p) if len < p => {
            // 轮转：文件被截断，从头读
            file.seek(std::io::SeekFrom::Start(0)).await?;
            let mut buf = Vec::new();
            file.read_to_end(&mut buf).await?;
            *pos = Some(buf.len() as u64);
            Ok(String::from_utf8_lossy(&buf)
                .lines()
                .map(str::to_string)
                .collect())
        }
        Some(p) => {
            file.seek(std::io::SeekFrom::Start(p)).await?;
            let mut buf = Vec::new();
            file.read_to_end(&mut buf).await?;
            *pos = Some(p + buf.len() as u64);
            Ok(String::from_utf8_lossy(&buf)
                .lines()
                .map(str::to_string)
                .collect())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        IpAddr::from_str(s).unwrap()
    }

    #[test]
    fn parses_common_failure_messages() {
        let cases = [
            (
                "Failed password for root from 203.0.113.7 port 55124 ssh2",
                "root",
            ),
            (
                "Failed password for invalid user admin from 203.0.113.7 port 4242 ssh2",
                "admin",
            ),
            (
                "Failed publickey for git from 203.0.113.8 port 40022 ssh2",
                "git",
            ),
            (
                "Connection closed by authenticating user root 203.0.113.9 port 40124 [preauth]",
                "root",
            ),
            (
                "Connection closed by invalid user oracle 203.0.113.9 port 40126 [preauth]",
                "oracle",
            ),
        ];
        for (msg, user) in cases {
            let Some(SshEvent::AuthFailure { user: u, ip: addr }) = parse_sshd_message(msg) else {
                panic!("应识别为认证失败: {msg}");
            };
            assert_eq!(u.as_deref(), Some(user), "{msg}");
            assert!(addr.is_ipv4(), "{msg}");
        }
        // Invalid user 探测行（无 Failed 前缀）
        let Some(SshEvent::AuthFailure { user: u, .. }) =
            parse_sshd_message("Invalid user postgres from 203.0.113.10 port 51000")
        else {
            panic!("应识别 Invalid user 探测");
        };
        assert_eq!(u.as_deref(), Some("postgres"));
    }

    #[test]
    fn parses_success_messages() {
        let Some(SshEvent::AuthSuccess {
            user,
            ip: addr,
            method,
        }) = parse_sshd_message(
            "Accepted publickey for deploy from 198.51.100.2 port 51422 ssh2: ED25519 SHA256:xyz",
        )
        else {
            panic!("应识别为认证成功");
        };
        assert_eq!(user, "deploy");
        assert_eq!(addr, ip("198.51.100.2"));
        assert_eq!(method, "publickey");

        let Some(SshEvent::AuthSuccess { method, .. }) =
            parse_sshd_message("Accepted password for root from 1.2.3.4 port 22 ssh2")
        else {
            panic!("应识别密码登录");
        };
        assert_eq!(method, "password");
    }

    #[test]
    fn ignores_unrelated_messages() {
        assert!(parse_sshd_message("Server listening on 0.0.0.0 port 22.").is_none());
        assert!(
            parse_sshd_message("Received disconnect from 1.2.3.4 port 4:11: Bye Bye").is_none()
        );
        assert!(parse_sshd_message("Pixmap requested").is_none());
    }

    #[test]
    fn parses_auth_log_full_line() {
        let line = "Oct 12 03:14:15 vps-01 sshd[12345]: Failed password for root from 203.0.113.7 port 55124 ssh2";
        assert!(matches!(
            parse_auth_log_line(line),
            Some(SshEvent::AuthFailure { .. })
        ));
        // 非 sshd 行（cron/sudo）不应产生事件
        assert!(
            parse_auth_log_line(
                "Oct 12 03:14:15 vps-01 sudo: deploy : TTY=pts/0 ; COMMAND=/bin/ls"
            )
            .is_none()
        );
    }

    #[test]
    fn parses_journald_json_line() {
        let line = r#"{"__REALTIME_TIMESTAMP":"1760000000000000","_COMM":"sshd","MESSAGE":"Accepted publickey for root from 203.0.113.7 port 51422 ssh2: RSA SHA256:abc"}"#;
        assert!(matches!(
            parse_journald_line(line),
            Some(SshEvent::AuthSuccess { .. })
        ));
        assert!(parse_journald_line(r#"{"MESSAGE":"Server listening on :: port 22."}"#).is_none());
    }
}
