//! outbox 持久化投递 e2e（PRD ALR-05）：
//! 1. Webhook 首次投递失败 → outbox 重试 → 成功后清空；
//! 2. 投递失败期间进程"重启"（销毁并重建 Notifier，同一 SQLite）→ 积压自动补发。

use honeyguard::alert::{Alert, Level};
use honeyguard::config::{AlertCfg, Provider, WebhookCfg};
use honeyguard::notify::{Delivery, Notifier, webhook};
use honeyguard::store::Store;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

/// 可控 HTTP 服务器：请求序号 <= `fails_left` 的返回 500，其余 200；记录全部 body。
/// `fails_left` 可在运行中调整（模拟网络恢复）。
struct Server {
    fails_left: Arc<AtomicUsize>,
    bodies: Arc<Mutex<Vec<String>>>,
    url: String,
}

impl Server {
    fn spawn() -> Server {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        let fails_left = Arc::new(AtomicUsize::new(0));
        let bodies: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let server = Server {
            fails_left: fails_left.clone(),
            bodies: bodies.clone(),
            url: format!("http://{addr}/hook"),
        };
        let counter = Arc::new(AtomicUsize::new(0));
        thread::spawn(move || {
            for _ in 0..50 {
                let Ok((mut stream, _)) = listener.accept() else {
                    return;
                };
                let body = read_request(&mut stream);
                let no = counter.fetch_add(1, Ordering::SeqCst) + 1;
                let status = if no <= fails_left.load(Ordering::SeqCst) {
                    "500 Internal Server Error"
                } else {
                    "200 OK"
                };
                let _ = stream.write_all(
                    format!("HTTP/1.1 {status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                        .as_bytes(),
                );
                let _ = stream.flush();
                bodies.lock().unwrap().push(body);
            }
        });
        server
    }

    fn received(&self) -> Vec<String> {
        self.bodies.lock().unwrap().clone()
    }
}

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

fn target(url: &str) -> Vec<WebhookCfg> {
    vec![WebhookCfg {
        provider: Provider::Custom,
        url: url.to_string(),
        secret: None,
        template: Some(r#"{"text": "[{{level}}] {{title}} {{event_id}}"}"#.to_string()),
    }]
}

fn alert_cfg() -> AlertCfg {
    AlertCfg {
        min_level: Level::Info,
        rate_limit_per_min: 1000,
        // 大窗口 + 零静默：排除聚合/静默对断言的干扰
        aggregate_window_sec: 3600,
        silence_sec: 0,
        webhooks: vec![],
        ..Default::default()
    }
}

async fn wait_until(timeout: Duration, mut pred: impl FnMut() -> bool) -> bool {
    let start = Instant::now();
    while start.elapsed() < timeout {
        if pred() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    pred()
}

#[tokio::test]
async fn outbox_retries_after_failure_until_success() {
    let server = Server::spawn();
    server.fails_left.store(2, Ordering::SeqCst); // 前 2 次投递失败

    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(Store::open(&dir.path().join("state.db")).unwrap());
    let (notifier, done) = Notifier::start(
        alert_cfg(),
        target(&server.url),
        Delivery::Webhook(webhook::http_client()),
        Some(store.clone()),
    );

    notifier
        .publish(Alert::new(
            Level::Critical,
            "e2e",
            "outbox 重试测试",
            "首次投递会失败",
        ))
        .await
        .unwrap();

    // 重试节奏：立即失败 → worker 5s tick 重试再失败 → 下个 tick 成功；给足余量
    let ok = wait_until(Duration::from_secs(25), || {
        server.received().len() >= 3 && store.outbox_pending_count().unwrap() == 0
    })
    .await;
    assert!(
        ok,
        "应在重试后送达且 outbox 清空，收到 {} 条，积压 {} 条",
        server.received().len(),
        store.outbox_pending_count().unwrap()
    );
    assert!(
        server
            .received()
            .iter()
            .any(|b| b.contains("outbox 重试测试")),
        "{:?}",
        server.received()
    );

    drop(notifier);
    done.shutdown().await.unwrap();
}

#[tokio::test]
async fn outbox_backlog_survives_restart() {
    let server = Server::spawn();
    server.fails_left.store(1000, Ordering::SeqCst); // 第一阶段全部失败

    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("state.db");
    let store = Arc::new(Store::open(&db).unwrap());
    let (notifier, done) = Notifier::start(
        alert_cfg(),
        target(&server.url),
        Delivery::Webhook(webhook::http_client()),
        Some(store.clone()),
    );

    notifier
        .publish(Alert::new(
            Level::Critical,
            "e2e",
            "重启补发测试",
            "断网期间产生的告警",
        ))
        .await
        .unwrap();

    let queued = wait_until(Duration::from_secs(5), || {
        store.outbox_pending_count().unwrap() == 1
    })
    .await;
    assert!(queued, "失败的告警应留在 outbox");

    drop(notifier);
    done.shutdown().await.unwrap(); // 模拟进程重启

    assert!(Path::new(&db).exists());
    let store2 = Arc::new(Store::open(&db).unwrap());
    assert_eq!(
        store2.outbox_pending_count().unwrap(),
        1,
        "重启后积压应恢复"
    );

    server.fails_left.store(0, Ordering::SeqCst); // 网络恢复
    let (notifier2, done2) = Notifier::start(
        alert_cfg(),
        target(&server.url),
        Delivery::Webhook(webhook::http_client()),
        Some(store2.clone()),
    );

    let delivered = wait_until(Duration::from_secs(25), || {
        server.received().iter().any(|b| b.contains("重启补发测试"))
            && store2.outbox_pending_count().unwrap() == 0
    })
    .await;
    assert!(delivered, "重启后应自动补发积压告警");

    drop(notifier2); // 必须先释放发布端，分发器才会退出
    done2.shutdown().await.unwrap();
}
