//! Webhook 消息模板：预置钉钉/飞书/企业微信/Slack + 自定义变量替换（PRD ALR-01/02）。
//!
//! 预置模板用 `serde_json::json!` 组装，用户内容作为 JSON 值注入，天然完成转义；
//! custom 模板是用户直接书写的完整 JSON body，只做 `{{变量}}` 字符串替换。

use crate::alert::Alert;
use crate::config::{Provider, WebhookCfg};
use anyhow::{Result, bail};
use base64::Engine as _;
use hmac::{Hmac, KeyInit, Mac};
use percent_encoding::{AsciiSet, CONTROLS, utf8_percent_encode};
use serde_json::json;

const DINGTALK_TEXT: &str =
    "**[{{level}}] {{title}}**\n\n{{body}}\n\n> {{host}} · {{time}} · `{{event_id}}`";
const FEISHU_TEXT: &str = "[{{level}}] {{title}}\n{{body}}\n{{host}} · {{time}} · {{event_id}}";
const WECOM_TEXT: &str = "**[{{level}}] {{title}}**\n> {{body}}\n> {{host}} · {{time}}";
const SLACK_TEXT: &str = "[{{level}}] *{{title}}*\n{{body}}\n_{{host}} · {{time}}_";
const TITLE_LINE: &str = "[{{level}}] {{title}}";

/// 渲染请求 body（JSON 字符串）。
pub fn render_body(wh: &WebhookCfg, alert: &Alert) -> Result<String> {
    Ok(match wh.provider {
        Provider::Dingtalk => serde_json::to_string(&json!({
            "msgtype": "markdown",
            "markdown": {
                "title": substitute(TITLE_LINE, alert),
                "text": substitute(DINGTALK_TEXT, alert),
            }
        }))?,
        Provider::Feishu => serde_json::to_string(&json!({
            "msg_type": "text",
            "content": { "text": substitute(FEISHU_TEXT, alert) }
        }))?,
        Provider::Wecom => serde_json::to_string(&json!({
            "msgtype": "markdown",
            "markdown": { "content": substitute(WECOM_TEXT, alert) }
        }))?,
        Provider::Slack => {
            serde_json::to_string(&json!({ "text": substitute(SLACK_TEXT, alert) }))?
        }
        Provider::Custom => match wh.template.as_deref() {
            Some(t) if !t.trim().is_empty() => substitute(t, alert),
            _ => bail!("provider = custom 的 webhook 缺少 template 配置"),
        },
    })
}

/// 计算 POST URL：钉钉配置了 secret 时追加 timestamp 与加签（PRD：钉钉加签）。
pub fn build_url(wh: &WebhookCfg) -> Result<String> {
    if wh.provider == Provider::Dingtalk
        && let Some(secret) = wh.secret.as_deref().filter(|s| !s.trim().is_empty())
    {
        let ts = chrono::Utc::now().timestamp_millis();
        let sign = dingtalk_sign(secret, ts);
        let sep = if wh.url.contains('?') { '&' } else { '?' };
        return Ok(format!(
            "{url}{sep}timestamp={ts}&sign={sign}",
            url = wh.url
        ));
    }
    Ok(wh.url.clone())
}

/// 钉钉加签：URL 编码( base64( HmacSHA256(key = secret, data = "{ts}\n{secret}" ) ) )。
pub fn dingtalk_sign(secret: &str, timestamp_millis: i64) -> String {
    let mut mac =
        Hmac::<sha2::Sha256>::new_from_slice(secret.as_bytes()).expect("HMAC 接受任意长度密钥");
    mac.update(format!("{timestamp_millis}\n{secret}").as_bytes());
    let signature = mac.finalize().into_bytes();
    utf8_percent_encode(
        &base64::engine::general_purpose::STANDARD.encode(signature),
        SIGN_SET,
    )
    .to_string()
}

/// base64 结果里需要百分号编码的字符。
const SIGN_SET: &AsciiSet = &CONTROLS.add(b'+').add(b'/').add(b'=').add(b'%');

/// 模板变量替换：`{{event_id}}` `{{level}}` `{{title}}` `{{body}}` `{{host}}` `{{time}}` `{{detector}}`。
pub fn substitute(template: &str, alert: &Alert) -> String {
    let vars = [
        ("event_id", alert.event_id.clone()),
        ("level", alert.level.to_string()),
        ("title", alert.title.clone()),
        ("body", alert.body.clone()),
        ("host", alert.host.clone()),
        ("time", alert.time.to_rfc3339()),
        ("detector", alert.detector.clone()),
    ];
    let mut out = template.to_string();
    for (name, value) in vars {
        out = out.replace(&format!("{{{{{name}}}}}"), &value);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alert::Level;

    fn webhook(provider: Provider, template: Option<&str>) -> WebhookCfg {
        WebhookCfg {
            provider,
            url: "https://example.invalid/hook".to_string(),
            secret: None,
            template: template.map(str::to_string),
        }
    }

    fn alert() -> Alert {
        Alert::new(
            Level::Critical,
            "ssh_bruteforce",
            "SSH 暴力破解",
            "来源 1.2.3.4\n失败 142 次",
        )
    }

    #[test]
    fn substitute_replaces_all_variables() {
        let out = substitute("{{event_id}}|{{level}}|{{title}}|{{detector}}", &alert());
        assert!(!out.contains("{{"), "不应残留变量占位：{out}");
        assert!(out.contains("critical"));
        assert!(out.contains("SSH 暴力破解"));
        assert!(out.contains("ssh_bruteforce"));
    }

    #[test]
    fn presets_render_valid_json_with_content() {
        for provider in [
            Provider::Dingtalk,
            Provider::Feishu,
            Provider::Wecom,
            Provider::Slack,
        ] {
            let body = render_body(&webhook(provider, None), &alert()).unwrap();
            let v: serde_json::Value =
                serde_json::from_str(&body).unwrap_or_else(|e| panic!("{provider}: {e}\n{body}"));
            let text = v.to_string();
            assert!(text.contains("SSH"), "{provider} 应包含标题内容");
            assert!(text.contains("142"), "{provider} 应包含正文内容");
        }
    }

    #[test]
    fn preset_json_escapes_newlines_in_body() {
        let body = render_body(&webhook(Provider::Feishu, None), &alert()).unwrap();
        assert!(
            !body.contains('\n') || body.matches('\\').count() >= 2,
            "换行应被转义"
        );
        serde_json::from_str::<serde_json::Value>(&body).expect("转义后仍应为合法 JSON");
    }

    #[test]
    fn custom_template_used_verbatim() {
        let wh = webhook(
            Provider::Custom,
            Some(r#"{"text":"[{{level}}] {{title}}"}"#),
        );
        let body = render_body(&wh, &alert()).unwrap();
        assert_eq!(body, r#"{"text":"[critical] SSH 暴力破解"}"#);
    }

    #[test]
    fn custom_without_template_rejected() {
        let err = render_body(&webhook(Provider::Custom, None), &alert());
        assert!(err.is_err());
    }

    #[test]
    fn dingtalk_signature_is_url_safe() {
        let sign = dingtalk_sign("SECtest", 1700000000000);
        assert!(
            sign.chars().all(|c| c.is_ascii_alphanumeric() || c == '%'),
            "签名应只含字母数字与百分号编码：{sign}"
        );
        assert!(!sign.is_empty());
    }

    #[test]
    fn build_url_appends_signature_only_for_dingtalk_with_secret() {
        let mut wh = webhook(Provider::Dingtalk, None);
        assert_eq!(build_url(&wh).unwrap(), wh.url, "无 secret 不加签");

        wh.secret = Some("SECtest".to_string());
        let url = build_url(&wh).unwrap();
        assert!(url.starts_with(&wh.url));
        assert!(url.contains("timestamp=") && url.contains("sign="), "{url}");

        let slack = webhook(Provider::Slack, None);
        assert_eq!(build_url(&slack).unwrap(), slack.url, "非钉钉不加签");
    }
}
