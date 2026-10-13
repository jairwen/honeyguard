//! 出口公网 IP 探测（`server.egress_ip`，默认开启）。
//!
//! 依次尝试多个公网探测服务，响应体须能解析为合法 IP 才采纳；
//! 定时刷新（默认 10 分钟）写入 [`crate::alert::set_egress_ip`]，
//! 告警中的主机名随之显示为 `NODEA(1.2.3.4)` 格式。
//! 全部探测失败时保留旧值并告警日志，不影响任何检测。

use crate::alert;
use anyhow::{Result, bail};
use std::net::IpAddr;
use std::str::FromStr;
use std::time::Duration;
use tokio_util::sync::CancellationToken;

/// 探测服务列表（按序回退，返回纯文本 IP）。
const PROVIDERS: &[&str] = &[
    "https://api.ipify.org",
    "https://ip.sb/",
    "https://ifconfig.me/ip",
];

/// 刷新间隔：VPS 出口 IP 变化不频繁，10 分钟足够及时。
const REFRESH_INTERVAL: Duration = Duration::from_secs(600);

/// 解析探测响应体为合法 IP（纯函数，测试覆盖）。
pub fn parse_egress(body: &str) -> Option<IpAddr> {
    IpAddr::from_str(body.trim()).ok()
}

/// 探测一次出口 IP（多源回退）。成功返回 IP 字符串。
pub async fn fetch_once(client: &reqwest::Client) -> Result<String> {
    let mut last_err = None;
    for url in PROVIDERS {
        match client.get(*url).send().await {
            Ok(resp) if resp.status().is_success() => {
                if let Ok(body) = resp.text().await
                    && let Some(ip) = parse_egress(&body)
                {
                    return Ok(ip.to_string());
                }
                last_err = Some(anyhow::anyhow!("{url} 响应无法解析为 IP"));
            }
            Ok(resp) => last_err = Some(anyhow::anyhow!("{url} 返回 HTTP {}", resp.status())),
            Err(err) => last_err = Some(anyhow::anyhow!("{url} 请求失败: {err}")),
        }
    }
    match last_err {
        Some(err) => bail!("全部出口 IP 探测服务不可用: {err}"),
        None => bail!("无可用探测服务"),
    }
}

/// 探测并更新全局展示值。IP 变化时记 info 日志。
pub async fn refresh(client: &reqwest::Client) -> Result<String> {
    let ip = fetch_once(client).await?;
    let changed = alert::egress_ip().as_deref() != Some(ip.as_str());
    alert::set_egress_ip(Some(ip.clone()));
    if changed {
        tracing::info!(egress_ip = %ip, "出口 IP 已更新");
    }
    Ok(ip)
}

/// 常驻刷新任务（由 supervised 监督）。
pub async fn run(client: reqwest::Client, token: CancellationToken) -> Result<()> {
    tracing::info!(
        interval_sec = REFRESH_INTERVAL.as_secs(),
        "egress 出口 IP 探测任务已启动"
    );
    loop {
        if let Err(err) = refresh(&client).await {
            tracing::warn!(error = %err, "出口 IP 探测失败（保留上次结果）");
        }
        tokio::select! {
            _ = tokio::time::sleep(REFRESH_INTERVAL) => {}
            _ = token.cancelled() => {
                tracing::info!("egress 探测任务退出");
                return Ok(());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_valid_ips_only() {
        assert_eq!(
            parse_egress("203.0.113.4\n").unwrap().to_string(),
            "203.0.113.4"
        );
        assert_eq!(
            parse_egress("  2001:db8::1  ").unwrap().to_string(),
            "2001:db8::1"
        );
        assert!(parse_egress("<html>blocked</html>").is_none());
        assert!(parse_egress("").is_none());
        assert!(parse_egress("203.0.113.4 extra garbage").is_none());
    }

    #[test]
    fn host_display_composes_egress() {
        alert::set_host("NODEA");
        alert::set_egress_ip(Some("203.0.113.4".into()));
        assert_eq!(alert::host(), "NODEA(203.0.113.4)");
        alert::set_egress_ip(None);
        assert_eq!(alert::host(), "NODEA");
    }
}
