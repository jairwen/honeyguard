use anyhow::{Context, Result, bail};
use clap::{ArgAction, Parser, Subcommand};
use honeyguard::alert::{self, Alert, Level};
use honeyguard::config::{self, Config};
use honeyguard::detectors;
use honeyguard::logging;
use honeyguard::notify::{Delivery, Notifier, webhook};
use honeyguard::whitelist::Whitelist;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

/// honeyguard — 轻量级 Linux VPS 入侵威胁检测与告警 Agent。
#[derive(Parser)]
#[command(
    name = "honeyguard",
    version,
    about = "轻量级 Linux VPS 入侵威胁检测与告警 Agent",
    disable_help_subcommand = true
)]
struct Cli {
    /// 配置文件路径（默认 $HONEYGUARD_CONFIG > /etc/honeyguard/config.toml > ./config.toml）
    #[arg(short, long, global = true, value_name = "FILE")]
    config: Option<PathBuf>,

    /// 提高日志详细度：-v 输出 debug，-vv 输出 trace
    #[arg(short, long, global = true, action = ArgAction::Count)]
    verbose: u8,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// 前台运行（生产环境由 systemd 以 honeyguard.service 拉起）
    Run,
    /// 校验配置并打印策略摘要后退出（检测器在 run 中持续运行）
    Once,
    /// 向已配置的 Webhook 发送三级测试告警
    TestAlert,
    /// 重建文件完整性与监听端口基线（当前状态视为正常，之后的变化才告警）
    Baseline {
        /// 无交互意义占位：update 本身即重建
        #[arg(long)]
        force: bool,
    },
    /// 环境自检：配置、权限、日志源、状态库、Webhook 连通性
    Doctor,
    /// 打印版本信息
    Version,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    logging::init(cli.verbose)?;
    match cli.command {
        Command::Run => cmd_run(&cli).await,
        Command::Once => cmd_once(&cli),
        Command::TestAlert => cmd_test_alert(&cli).await,
        Command::Baseline { .. } => cmd_baseline(&cli),
        Command::Doctor => cmd_doctor(&cli).await,
        Command::Version => {
            println!(
                "honeyguard {} ({} {})",
                env!("CARGO_PKG_VERSION"),
                std::env::consts::OS,
                std::env::consts::ARCH
            );
            Ok(())
        }
    }
}

fn load_config(path: &Option<PathBuf>) -> Result<Config> {
    let path = path
        .clone()
        .or_else(config::default_path)
        .context("未找到配置文件：请通过 --config 指定，或放置到 /etc/honeyguard/config.toml（示例见仓库根目录 config.example.toml）")?;
    let cfg = Config::load(&path)?;
    if let Some(host) = cfg.server.host.as_deref().filter(|h| !h.trim().is_empty()) {
        alert::set_host(host);
    }
    tracing::info!(config = %path.display(), "已加载配置");
    Ok(cfg)
}

async fn cmd_run(cli: &Cli) -> Result<()> {
    let cfg = load_config(&cli.config)?;
    let whitelist = Arc::new(Whitelist::from_cfg(&cfg.whitelist)?);
    let store = match honeyguard::store::Store::open_default() {
        Ok(store) => {
            tracing::info!(db = honeyguard::store::DEFAULT_DB_PATH, "状态数据库已打开");
            Some(Arc::new(store))
        }
        Err(err) => {
            tracing::warn!(
                error = %err,
                "状态数据库不可用：告警不持久化（断网恢复后不补发），new_ip 模式重启后重置"
            );
            None
        }
    };
    let client = webhook::http_client();
    let (notifier, done) = Notifier::start(
        cfg.alert.clone(),
        cfg.alert.webhooks.clone(),
        Delivery::Webhook(client),
        store.clone(),
    );
    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        host = %alert::host(),
        webhooks = cfg.alert.webhooks.len(),
        min_level = %cfg.alert.min_level,
        persist = store.is_some(),
        "honeyguard 已启动"
    );

    // 检测器注册：每个检测器由 supervised 监督，崩溃后自动重启（PRD NF-02）；
    // shutdown_token 负责让全部检测器释放 Notifier 克隆，分发器才能正常退出。
    let shutdown_token = tokio_util::sync::CancellationToken::new();
    let mut detector_tasks = Vec::new();
    let d = cfg.detector.clone();
    if d.ssh_bruteforce.enabled || d.ssh_login.enabled {
        let (brute, login) = (d.ssh_bruteforce.clone(), d.ssh_login.clone());
        let (wl, n, st) = (whitelist.clone(), notifier.clone(), store.clone());
        let token = shutdown_token.clone();
        detector_tasks.push(tokio::spawn(detectors::supervised(
            "ssh",
            token,
            move |t| {
                detectors::ssh::run(
                    brute.clone(),
                    login.clone(),
                    wl.clone(),
                    n.clone(),
                    st.clone(),
                    t,
                )
            },
        )));
    }
    if d.outbound.enabled {
        let outbound = d.outbound.clone();
        let (wl, n) = (whitelist.clone(), notifier.clone());
        let token = shutdown_token.clone();
        detector_tasks.push(tokio::spawn(detectors::supervised(
            "outbound",
            token,
            move |t| detectors::net::run(outbound.clone(), wl.clone(), n.clone(), t),
        )));
    }
    if d.process.enabled {
        let process = d.process.clone();
        let (wl, n) = (whitelist.clone(), notifier.clone());
        let token = shutdown_token.clone();
        detector_tasks.push(tokio::spawn(detectors::supervised(
            "process",
            token,
            move |t| detectors::process::run(process.clone(), wl.clone(), n.clone(), t),
        )));
    }
    if d.file_integrity.enabled {
        let fim = d.file_integrity.clone();
        let (wl, n, st) = (whitelist.clone(), notifier.clone(), store.clone());
        let token = shutdown_token.clone();
        detector_tasks.push(tokio::spawn(detectors::supervised(
            "file_integrity",
            token,
            move |t| detectors::fim::run(fim.clone(), wl.clone(), n.clone(), st.clone(), t),
        )));
    }
    if d.listen_ports.enabled {
        let ports = d.listen_ports.clone();
        let (n, st) = (notifier.clone(), store.clone());
        let token = shutdown_token.clone();
        detector_tasks.push(tokio::spawn(detectors::supervised(
            "listen_ports",
            token,
            move |t| detectors::ports::run(ports.clone(), n.clone(), st.clone(), t),
        )));
    }
    if cfg.alert.heartbeat.enabled || cfg.alert.digest.enabled {
        let (hb, dg) = (cfg.alert.heartbeat, cfg.alert.digest);
        let (n, st) = (notifier.clone(), store.clone());
        let token = shutdown_token.clone();
        detector_tasks.push(tokio::spawn(detectors::supervised(
            "report",
            token,
            move |t| detectors::report::run(hb, dg, n.clone(), st.clone(), t),
        )));
    }

    wait_for_shutdown().await;
    tracing::info!("收到退出信号，正在停止…");
    shutdown_token.cancel();
    for task in detector_tasks {
        let _ = task.await;
    }
    drop(notifier);
    done.shutdown().await?;
    Ok(())
}

fn cmd_baseline(cli: &Cli) -> Result<()> {
    let cfg = load_config(&cli.config)?;
    let store = honeyguard::store::Store::open_default()
        .context("状态数据库不可用，无法重建基线（以 root 运行？）")?;
    let (files, users, suid) =
        detectors::fim::rebuild_baseline(&cfg.detector.file_integrity, &store)?;
    let ports = detectors::ports::rebuild_baseline(&store)?;
    println!("基线已重建（当前状态视为正常）：");
    println!("  受控文件   : {files} 个");
    println!("  可登录用户 : {users} 个");
    println!("  SUID 文件  : {suid} 个");
    println!("  监听端口   : {ports} 个");
    Ok(())
}

async fn cmd_doctor(cli: &Cli) -> Result<()> {
    let mut ok = true;
    let mut check = |name: &str, pass: bool, detail: String| {
        ok &= pass;
        println!(
            "  [{}] {name:<14} {detail}",
            if pass { "OK " } else { "FAIL" }
        );
    };

    println!("honeyguard doctor");
    // 1. 配置
    match load_config(&cli.config) {
        Ok(cfg) => {
            check(
                "配置文件",
                true,
                format!("{} 个 webhook", cfg.alert.webhooks.len()),
            );
            // 2. root 权限
            let root = nix_uid() == 0;
            check(
                "root 权限",
                root,
                if root {
                    "以 root 运行".into()
                } else {
                    "非 root，部分检测器受限".into()
                },
            );
            // 3. 日志源
            let journalctl = which("journalctl");
            let auth_log = std::path::Path::new("/var/log/auth.log").exists();
            let log_ok = journalctl || auth_log;
            check(
                "SSH 日志源",
                log_ok,
                if journalctl {
                    "journald".into()
                } else if auth_log {
                    "/var/log/auth.log".into()
                } else {
                    "不可用（SSH 检测器不工作）".into()
                },
            );
            // 4. /proc
            let proc_ok = std::path::Path::new("/proc/net/tcp").exists();
            check(
                "procfs",
                proc_ok,
                if proc_ok {
                    "/proc/net 可读".into()
                } else {
                    "不可用（外连/进程/端口检测器不工作）".into()
                },
            );
            // 5. 状态库
            match honeyguard::store::Store::open_default() {
                Ok(store) => {
                    let pending = store.outbox_pending_count().unwrap_or(-1);
                    check("状态数据库", true, format!("可写，待发积压 {pending} 条"));
                }
                Err(err) => check("状态数据库", false, format!("{err}")),
            }
            // 6. Webhook 连通性（发送空 JSON，收到任意 HTTP 响应即视为可达）
            let client = webhook::http_client();
            for wh in &cfg.alert.webhooks {
                let reachable = client
                    .post(&wh.url)
                    .header("Content-Type", "application/json")
                    .body("{}")
                    .send()
                    .await;
                match reachable {
                    Ok(resp) => check(
                        "webhook",
                        true,
                        format!("{} 返回 HTTP {}", wh.provider, resp.status()),
                    ),
                    Err(err) => check("webhook", false, format!("{} 不可达：{err}", wh.provider)),
                }
            }
        }
        Err(err) => {
            check("配置文件", false, format!("{err:#}"));
        }
    }
    println!();
    if ok {
        println!("全部检查通过。");
        Ok(())
    } else {
        bail!("存在未通过的检查项，详见上方输出");
    }
}

fn nix_uid() -> u32 {
    // Linux：读 /proc/self/status 的 Uid 行（避免引入 libc）；其余平台退回环境变量
    if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
        for line in status.lines() {
            if let Some(rest) = line.strip_prefix("Uid:")
                && let Some(first) = rest.split_whitespace().next()
                && let Ok(uid) = first.parse::<u32>()
            {
                return uid;
            }
        }
    }
    std::env::var("UID")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(999)
}

fn which(bin: &str) -> bool {
    std::env::var_os("PATH")
        .map(|paths| std::env::split_paths(&paths).any(|dir| dir.join(bin).is_file()))
        .unwrap_or(false)
}

async fn wait_for_shutdown() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        match signal(SignalKind::terminate()) {
            Ok(mut terminate) => {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {}
                    _ = terminate.recv() => {}
                }
            }
            Err(_) => {
                let _ = tokio::signal::ctrl_c().await;
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

fn cmd_once(cli: &Cli) -> Result<()> {
    let cfg = load_config(&cli.config)?;
    let d = &cfg.detector;
    println!("honeyguard 配置检查通过：");
    println!("  主机名          : {}", alert::host());
    println!("  Webhook 数量    : {}", cfg.alert.webhooks.len());
    println!("  最低推送级别    : {}", cfg.alert.min_level);
    println!(
        "  限流            : {} 条/分钟（critical 不受限）",
        cfg.alert.rate_limit_per_min
    );
    println!(
        "  聚合窗口 / 静默 : {}s / {}s",
        cfg.alert.aggregate_window_sec, cfg.alert.silence_sec
    );
    println!("检测器：");
    println!(
        "  ssh_bruteforce  : enabled={} window={}s max_failures={}",
        d.ssh_bruteforce.enabled, d.ssh_bruteforce.window_sec, d.ssh_bruteforce.max_failures
    );
    println!(
        "  ssh_login       : enabled={} mode={:?}",
        d.ssh_login.enabled, d.ssh_login.mode
    );
    println!(
        "  outbound        : enabled={} interval={}s bad_ports={} 个",
        d.outbound.enabled,
        d.outbound.interval_sec,
        d.outbound.bad_ports.len()
    );
    println!(
        "  process         : enabled={} interval={}s cpu>={}% lasting={}s",
        d.process.enabled, d.process.interval_sec, d.process.cpu_threshold, d.process.duration_sec
    );
    Ok(())
}

async fn cmd_test_alert(cli: &Cli) -> Result<()> {
    let cfg = load_config(&cli.config)?;
    if cfg.alert.webhooks.is_empty() {
        bail!("配置中没有任何 [[alert.webhooks]]，请先在配置文件中配置推送目标");
    }
    let client = webhook::http_client();
    println!("发送测试告警到 {} 个 Webhook…\n", cfg.alert.webhooks.len());
    let mut failed = 0usize;
    for level in [Level::Info, Level::Warning, Level::Critical] {
        let alert = Alert::new(
            level,
            "test",
            format!("测试告警（{level}）"),
            format!(
                "这是 honeyguard test-alert 发出的 {level} 级测试推送，收到即代表该渠道工作正常。\nhost: {}",
                alert::host()
            ),
        );
        for wh in &cfg.alert.webhooks {
            // 测试命令用小退避快重试，避免长时间等待
            let result =
                webhook::send_with_retry(&client, wh, &alert, 3, Duration::from_millis(500)).await;
            match result {
                Ok(()) => println!("  [OK]   {:>8} | {level} | {}", wh.provider, alert.title),
                Err(err) => {
                    failed += 1;
                    println!(
                        "  [FAIL] {:>8} | {level} | {}：{err:#}",
                        wh.provider, alert.title
                    );
                }
            }
        }
    }
    println!();
    if failed == 0 {
        println!("全部测试告警发送成功。");
        Ok(())
    } else {
        bail!("{failed} 条测试告警发送失败，请检查 webhook 配置或网络");
    }
}
