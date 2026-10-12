//! Webhook HTTP 投递：单次发送与指数退避重试（PRD ALR-05 的重试部分；outbox 持久化在 M1）。

use crate::alert::Alert;
use crate::config::WebhookCfg;
use crate::notify::template;
use anyhow::{Context, Result, bail};
use std::time::Duration;

/// 指数退避上限（PRD ALR-05）。
const MAX_BACKOFF: Duration = Duration::from_secs(300);

/// 共享 HTTP 客户端：10 秒超时（PRD ALR-01）。
pub fn http_client() -> reqwest::Client {
    // reqwest 以 rustls-no-provider 方式构建：进程内必须先安装 ring CryptoProvider，
    // 否则发起 TLS 请求时会 panic。重复安装返回 Err，忽略即可。
    let _ = rustls::crypto::ring::default_provider().install_default();
    reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .user_agent(format!("honeyguard/{}", env!("CARGO_PKG_VERSION")))
        .build()
        .expect("构建 HTTP 客户端失败")
}

/// 日志脱敏：URL query 可能含 access_token / sign，一律不落日志（PRD NF-03）。
fn mask_url(url: &str) -> &str {
    url.split('?').next().unwrap_or(url)
}

/// 用已渲染好的 url/body 直接投递（outbox 重试路径：渲染结果在入队时冻结）。
pub async fn send_raw(client: &reqwest::Client, url: &str, body: &str) -> Result<()> {
    let resp = client
        .post(url)
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(body.to_string())
        .send()
        .await
        .with_context(|| format!("请求 webhook 失败: {}", mask_url(url)))?;
    let status = resp.status();
    if !status.is_success() {
        bail!("webhook {} 返回 HTTP {}", mask_url(url), status);
    }
    Ok(())
}

/// 向单个 webhook 发送一次请求。非 2xx 视为失败（PRD ALR-01）。
pub async fn send_one(client: &reqwest::Client, wh: &WebhookCfg, alert: &Alert) -> Result<()> {
    let body = template::render_body(wh, alert)?;
    let url = template::build_url(wh)?;
    send_raw(client, &url, &body).await
}

/// 带指数退避的重试发送：backoff = base * 2^(n-1)，封顶 [`MAX_BACKOFF`]。
pub async fn send_with_retry(
    client: &reqwest::Client,
    wh: &WebhookCfg,
    alert: &Alert,
    max_attempts: u32,
    base_backoff: Duration,
) -> Result<()> {
    debug_assert!(max_attempts >= 1, "至少尝试一次");
    let mut last_err = None;
    for attempt in 1..=max_attempts {
        match send_one(client, wh, alert).await {
            Ok(()) => return Ok(()),
            Err(err) => {
                tracing::warn!(
                    attempt,
                    max_attempts,
                    provider = %wh.provider,
                    url = mask_url(&wh.url),
                    error = %err,
                    "webhook 发送失败"
                );
                last_err = Some(err);
            }
        }
        if attempt < max_attempts {
            let backoff = base_backoff
                .saturating_mul(1 << (attempt - 1).min(16))
                .min(MAX_BACKOFF);
            tokio::time::sleep(backoff).await;
        }
    }
    Err(last_err.expect("max_attempts >= 1")).with_context(|| {
        format!(
            "webhook {} 连续 {max_attempts} 次发送失败",
            mask_url(&wh.url)
        )
    })
}
