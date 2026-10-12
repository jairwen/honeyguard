//! 全链路 e2e：本地起一个最小 HTTP 服务，验证 custom 模板渲染与真实投递路径。
//! 覆盖：`webhook::http_client`（含 rustls provider 安装）→ 模板渲染 → HTTP POST → 2xx 判定。

use honeyguard::alert::{Alert, Level};
use honeyguard::config::{Provider, WebhookCfg};
use honeyguard::notify::webhook;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

/// 串行接收 3 个请求的最小 HTTP 服务器，返回 (url, body 接收通道)。
fn spawn_server() -> (String, mpsc::Receiver<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind 127.0.0.1:0");
    let addr = listener.local_addr().expect("local addr");
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        for _ in 0..3 {
            let Ok((mut stream, _)) = listener.accept() else {
                return;
            };
            let body = read_request(&mut stream);
            let _ = stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
            let _ = stream.flush();
            if tx.send(body).is_err() {
                return;
            }
        }
    });
    (format!("http://{addr}/hook"), rx)
}

/// 读取完整 HTTP 请求（含 Content-Length 指定的 body）。
fn read_request(stream: &mut TcpStream) -> String {
    let mut buf: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 4096];
    let header_end = loop {
        let n = stream.read(&mut chunk).expect("读取请求");
        if n == 0 {
            panic!("连接在请求头完成前关闭");
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break p;
        }
    };
    let head = String::from_utf8_lossy(&buf[..header_end]).to_string();
    let content_length: usize = head
        .lines()
        .find(|l| l.to_ascii_lowercase().starts_with("content-length"))
        .and_then(|l| l.rsplit(':').next())
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(0);
    while buf.len() < header_end + 4 + content_length {
        let n = stream.read(&mut chunk).expect("读取请求 body");
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
    }
    String::from_utf8_lossy(&buf[header_end + 4..]).into_owned()
}

#[tokio::test]
async fn delivers_custom_template_alerts_over_http() {
    let (url, rx) = spawn_server();
    let wh = WebhookCfg {
        provider: Provider::Custom,
        url,
        secret: None,
        template: Some(r#"{"text": "[{{level}}] {{title}} @{{host}} {{event_id}}"}"#.to_string()),
    };
    let client = webhook::http_client();

    let levels = [Level::Info, Level::Warning, Level::Critical];
    for level in levels {
        let alert = Alert::new(
            level,
            "e2e",
            "全链路测试",
            format!("级别 {level} 的测试内容"),
        );
        webhook::send_one(&client, &wh, &alert)
            .await
            .expect("本地服务器应返回 2xx，发送成功");
    }

    for level in levels {
        let body = rx
            .recv_timeout(Duration::from_secs(5))
            .expect("服务器应收到请求");
        let json: serde_json::Value = serde_json::from_str(&body)
            .unwrap_or_else(|e| panic!("body 应为合法 JSON：{e}\n{body}"));
        let text = json["text"].as_str().unwrap_or_default();
        assert!(
            text.contains(&format!("[{level}]")),
            "级别变量应展开：{text}"
        );
        assert!(text.contains("全链路测试"), "标题变量应展开：{text}");
        assert!(
            text.contains('@'),
            "host 变量应展开（hostname 含 @ 或 host 已展开）：{text}"
        );
        assert!(!text.contains("{{"), "不应残留未替换变量：{text}");
    }
}
