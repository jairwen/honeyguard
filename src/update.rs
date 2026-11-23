//! 自更新（PRD DEP-03）：
//! 查询最新 Release → 下载对应架构产物 → sha256 校验 → 原子替换自身 → 重启服务。
//!
//! 两个入口共用同一套步骤：
//! - [`run`]：`honeyguard update` 手动执行，结果打印到终端；`--check` 只检查不更新（无需 root）。
//! - [`auto_run`]：常驻自动升级，`run` 期间按固定间隔检查，有新版即安装并重启服务，
//!   进展经告警管道推送。
//!
//! 仓库地址默认 `jairwen/honeyguard`，可用环境变量 `HONEYGUARD_REPO` 覆盖。

use crate::alert::{Alert, Level};
use crate::notify::Notifier;
use crate::store::Store;
use anyhow::{Context, Result, bail};
use sha2::{Digest, Sha256};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio_util::sync::CancellationToken;

const DEFAULT_REPO: &str = "jairwen/honeyguard";

pub fn repo() -> String {
    std::env::var("HONEYGUARD_REPO").unwrap_or_else(|_| DEFAULT_REPO.to_string())
}

/// "0.2.0" / "v0.2.0" → (0, 2, 0)；解析失败返回 None。
pub fn parse_version(tag: &str) -> Option<(u64, u64, u64)> {
    let tag = tag.trim().trim_start_matches('v');
    let mut parts = tag.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next().unwrap_or("0").parse().unwrap_or(0);
    let patch = parts.next().unwrap_or("0").parse().unwrap_or(0);
    Some((major, minor, patch))
}

/// latest 是否比 current 新。
pub fn is_newer(latest: &str, current: &str) -> Option<bool> {
    let l = parse_version(latest)?;
    let c = parse_version(current)?;
    Some(l > c)
}

/// 查询 GitHub 最新 Release 的版本号（已去除 v 前缀）。
/// 内置镜像候选链：直连优先，其后为国内可用的公共 GitHub 加速（前缀风格，
/// 拼接为 `{mirror}https://github.com/...`）。可用性随时间变化，均失败时可用
/// `HONEYGUARD_MIRROR` 或配置 `server.update_mirror` 指定自建镜像。
const BUILTIN_MIRRORS: &[&str] = &[
    "", // 直连
    "https://ghproxy.com/",
    "https://gh-proxy.com/",
    "https://ghfast.top/",
];

/// 解析镜像候选：显式指定（env > 配置）时只用该镜像，否则内置链。
pub fn mirror_candidates(configured: Option<&str>) -> Vec<String> {
    let explicit = std::env::var("HONEYGUARD_MIRROR")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .or_else(|| {
            configured
                .map(str::to_string)
                .filter(|s| !s.trim().is_empty())
        });
    match explicit {
        Some(mirror) => {
            let mirror = mirror.trim_end_matches('/').to_string();
            if mirror.is_empty() {
                BUILTIN_MIRRORS.iter().map(|s| s.to_string()).collect()
            } else {
                vec![format!("{mirror}/")]
            }
        }
        None => BUILTIN_MIRRORS.iter().map(|s| s.to_string()).collect(),
    }
}

/// 校验安装包内容：gzip 魔数（镜像可能返回 200 的 HTML 错误页）。
fn valid_gzip(bytes: &[u8]) -> bool {
    bytes.len() > 2 && bytes[0] == 0x1f && bytes[1] == 0x8b
}

/// 校验 sha256 文件内容：以 64 位十六进制摘要开头。
fn valid_sha_file(bytes: &[u8]) -> bool {
    bytes.len() >= 64 && bytes[..64].iter().all(|b| b.is_ascii_hexdigit())
}

/// 下载安装包/校验文件的单请求总超时，覆盖共享 client 的 10 秒（那是 webhook 告警的量级）：
/// 数 MB 的 musl 包经国内限速链路 10 秒内读不完 body，会被误判为源不可用。
const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(300);

/// 依次尝试候选 URL 下载（内容须通过 validator），任一成功即写入 dest。
async fn download_any(
    client: &reqwest::Client,
    urls: &[String],
    dest: &Path,
    validator: fn(&[u8]) -> bool,
    timeout: Duration,
) -> Result<()> {
    let mut errors = Vec::new();
    for url in urls {
        match client.get(url).timeout(timeout).send().await {
            Ok(resp) if resp.status().is_success() => {
                // 响应头 200 不代表 body 能读完（限速链路常在中途超时/中断），
                // 此处失败同样计入错误并切换下一个源，否则镜像回退永不触发。
                let bytes = match resp.bytes().await {
                    Ok(bytes) => bytes,
                    Err(err) => {
                        errors.push(format!("{url} → 读取内容失败: {err}"));
                        continue;
                    }
                };
                if !validator(&bytes) {
                    errors.push(format!("{url} → 内容不合法（镜像返回了错误页？）"));
                    continue;
                }
                std::fs::write(dest, &bytes)
                    .with_context(|| format!("写入 {} 失败", dest.display()))?;
                tracing::debug!(url, "下载成功");
                return Ok(());
            }
            Ok(resp) => errors.push(format!("{url} → HTTP {}", resp.status())),
            Err(err) => errors.push(format!("{url} → {err}")),
        }
    }
    bail!("全部下载源失败：{}", errors.join("；"));
}

async fn fetch_latest_version(
    client: &reqwest::Client,
    repo: &str,
    mirrors: &[String],
) -> Result<String> {
    let urls: Vec<String> = mirrors
        .iter()
        .map(|m| format!("{m}https://api.github.com/repos/{repo}/releases/latest"))
        .collect();
    let mut errors = Vec::new();
    for url in &urls {
        match client
            .get(url)
            .header("Accept", "application/vnd.github+json")
            .send()
            .await
        {
            Ok(resp) if resp.status().is_success() => {
                match resp.json::<serde_json::Value>().await {
                    // 镜像不健康时会返回 HTML/空体，解析失败计入错误继续回退
                    Ok(body) => {
                        let tag = body
                            .get("tag_name")
                            .and_then(|t| t.as_str())
                            .map(|s| s.trim().trim_start_matches('v').to_string())
                            .unwrap_or_default();
                        if tag.is_empty() {
                            errors.push(format!("{url} → 响应缺少 tag_name"));
                            continue;
                        }
                        return Ok(tag);
                    }
                    Err(err) => errors.push(format!("{url} → 响应非 JSON（镜像不健康？{err}）")),
                }
            }
            Ok(resp) => errors.push(format!("{url} → HTTP {}", resp.status())),
            Err(err) => errors.push(format!("{url} → {err}")),
        }
    }
    // 最后兜底：jsdelivr 数据源（国内可达，按 tag 列版本）
    if let Ok(tag) = fetch_latest_jsdelivr(client, repo).await {
        return Ok(tag);
    }
    bail!(
        "查询最新版本失败（可设置 HONEYGUARD_MIRROR 或 server.update_mirror 指定镜像）：{}",
        errors.join("；")
    );
}

/// jsdelivr 数据 API：https://data.jsdelivr.com/v1/packages/gh/{repo}
/// 返回 {"versions":[{"version":"v0.2.2",...},...]}（新版本在前）。
async fn fetch_latest_jsdelivr(client: &reqwest::Client, repo: &str) -> Result<String> {
    let url = format!("https://data.jsdelivr.com/v1/packages/gh/{repo}");
    let resp = client
        .get(&url)
        .send()
        .await
        .with_context(|| format!("请求 {url} 失败"))?;
    let status = resp.status();
    if !status.is_success() {
        bail!("jsdelivr 返回 {status}");
    }
    let body: serde_json::Value = resp.json().await.context("解析 jsdelivr 响应失败")?;
    let version = body
        .get("versions")
        .and_then(|v| v.get(0))
        .and_then(|v| v.get("version"))
        .and_then(|v| v.as_str())
        .map(|s| s.trim().trim_start_matches('v').to_string())
        .unwrap_or_default();
    if version.is_empty() {
        bail!("jsdelivr 响应无版本信息");
    }
    Ok(version)
}

fn sha256_hex(data: &[u8]) -> String {
    use std::fmt::Write as _;
    Sha256::digest(data)
        .iter()
        .fold(String::with_capacity(64), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}

/// 校验 .sha256 文件（首列为期望摘要）与实际文件是否一致。
fn verify_sha256(pkg: &Path, sha_file: &Path) -> Result<()> {
    let expected = std::fs::read_to_string(sha_file)
        .context("读取校验文件失败")?
        .split_whitespace()
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();
    let data = std::fs::read(pkg).context("读取安装包失败")?;
    let actual = sha256_hex(&data);
    if expected.is_empty() || expected != actual {
        bail!("sha256 校验失败（期望 {expected}，实际 {actual}）");
    }
    Ok(())
}

/// 从 tar.gz 中提取名为 `honeyguard` 的二进制成员到 dest。
fn extract_binary(archive: &Path, dest: &Path) -> Result<()> {
    let file = std::fs::File::open(archive).context("打开安装包失败")?;
    let gz = flate2::read::GzDecoder::new(file);
    let mut tar = tar::Archive::new(gz);
    for entry in tar.entries().context("读取 tar 内容失败")? {
        let mut entry = entry.context("读取 tar 条目失败")?;
        let path = entry.path().context("读取条目路径失败")?.to_path_buf();
        if path.file_name().is_some_and(|n| n == "honeyguard") {
            let mut bytes = Vec::new();
            entry
                .read_to_end(&mut bytes)
                .context("读取二进制内容失败")?;
            std::fs::write(dest, &bytes).context("写出二进制失败")?;
            return Ok(());
        }
    }
    bail!("安装包中未找到 honeyguard 二进制");
}

fn musl_target() -> Result<&'static str> {
    match std::env::consts::ARCH {
        "x86_64" => Ok("x86_64-unknown-linux-musl"),
        "aarch64" => Ok("aarch64-unknown-linux-musl"),
        other => bail!("不支持的架构: {other}"),
    }
}

/// 是否以 root 运行（读 /proc/self/status，非 Linux 回退环境变量）。
pub fn is_root() -> bool {
    if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
        for line in status.lines() {
            if let Some(rest) = line.strip_prefix("Uid:")
                && let Some(first) = rest.split_whitespace().next()
                && let Ok(uid) = first.parse::<u32>()
            {
                return uid == 0;
            }
        }
    }
    std::env::var("UID")
        .ok()
        .and_then(|s| s.parse::<u32>().ok())
        .is_some_and(|uid| uid == 0)
}

/// 自更新是否可用：替换系统路径下的二进制需要 Linux 与 root。
fn supported() -> bool {
    std::env::consts::OS.contains("linux") && is_root()
}

fn ensure_supported() -> Result<()> {
    if !std::env::consts::OS.contains("linux") {
        bail!("自更新仅支持 Linux（当前 {}）", std::env::consts::OS);
    }
    if !is_root() {
        bail!(
            "更新系统路径下的二进制需要 root，请 sudo 运行（仅检查可用 honeyguard update --check）"
        );
    }
    Ok(())
}

/// 二进制在运行中被替换后，`/proc/self/exe` 的路径带 " (deleted)" 后缀；去掉它才是磁盘上的
/// 真实路径——常驻进程二次自更新时若照原样 rename，会写出名为 "honeyguard (deleted)" 的新文件。
fn real_exe_path(exe: PathBuf) -> PathBuf {
    const DELETED: &str = " (deleted)";
    match exe.file_name().and_then(|n| n.to_str()) {
        Some(name) if name.ends_with(DELETED) => {
            exe.with_file_name(&name[..name.len() - DELETED.len()])
        }
        _ => exe,
    }
}

/// 原子替换 `exe`：写到同目录临时文件再 rename（同文件系统保证原子性）。
/// 临时文件名带 pid：手动 `honeyguard update` 与常驻自动升级并发时互不踩踏。
fn replace_binary(exe: &Path, new_binary: &Path) -> Result<()> {
    let staging = exe
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(format!(".honeyguard.update.tmp.{}", std::process::id()));
    std::fs::copy(new_binary, &staging).context("写出新版本失败")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&staging, std::fs::Permissions::from_mode(0o755))
            .context("设置可执行权限失败")?;
    }
    std::fs::rename(&staging, exe).with_context(|| format!("替换 {} 失败", exe.display()))?;
    Ok(())
}

/// 版本检查结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Status {
    /// 已是最新。
    UpToDate,
    /// 有比当前版本新的 Release。
    Available { latest: String },
}

fn status_of(latest: &str, current: &str) -> Result<Status> {
    match is_newer(latest, current) {
        Some(true) => Ok(Status::Available {
            latest: latest.to_string(),
        }),
        Some(false) => Ok(Status::UpToDate),
        None => bail!("无法比较版本: latest={latest} current={current}"),
    }
}

/// 查询最新 Release 并与当前版本比较。
pub async fn check(mirror: Option<&str>) -> Result<Status> {
    let client = crate::notify::webhook::http_client();
    let latest = fetch_latest_version(&client, &repo(), &mirror_candidates(mirror)).await?;
    status_of(&latest, env!("CARGO_PKG_VERSION"))
}

/// 下载安装包与校验文件、校验 sha256，并把二进制提取到 `work_dir`。
async fn fetch_binary(latest: &str, mirror: Option<&str>, work_dir: &Path) -> Result<PathBuf> {
    let client = crate::notify::webhook::http_client();
    let mirrors = mirror_candidates(mirror);
    let base = format!(
        "https://github.com/{}/releases/download/v{latest}/honeyguard-{}",
        repo(),
        musl_target()?
    );
    let pkg_urls: Vec<String> = mirrors
        .iter()
        .map(|m| format!("{m}{base}.tar.gz"))
        .collect();
    let sha_urls: Vec<String> = mirrors
        .iter()
        .map(|m| format!("{m}{base}.tar.gz.sha256"))
        .collect();
    let pkg = work_dir.join("pkg.tar.gz");
    let sha = work_dir.join("pkg.sha256");
    let binary = work_dir.join("honeyguard");
    download_any(&client, &pkg_urls, &pkg, valid_gzip, DOWNLOAD_TIMEOUT).await?;
    download_any(&client, &sha_urls, &sha, valid_sha_file, DOWNLOAD_TIMEOUT).await?;
    verify_sha256(&pkg, &sha)?;
    extract_binary(&pkg, &binary)?;
    Ok(binary)
}

/// 下载、校验并替换当前可执行文件（不重启服务）。返回被替换的二进制路径。
pub async fn install(latest: &str, mirror: Option<&str>) -> Result<PathBuf> {
    ensure_supported()?;
    let work_dir = std::env::temp_dir().join(format!("honeyguard-update-{}", std::process::id()));
    std::fs::create_dir_all(&work_dir).context("创建临时目录失败")?;
    let scope = RunScope(work_dir.clone());
    let binary = fetch_binary(latest, mirror, &work_dir).await?;
    let exe = real_exe_path(std::env::current_exe().context("获取当前二进制路径失败")?);
    replace_binary(&exe, &binary)?;
    drop(scope); // 清理临时目录
    Ok(exe)
}

/// 运行 systemctl 子命令；返回其是否成功退出（无 systemctl / 非 systemd 环境即 false）。
async fn systemctl(args: &[&str]) -> bool {
    tokio::process::Command::new("systemctl")
        .args(args)
        .status()
        .await
        .map(|status| status.success())
        .unwrap_or(false)
}

/// honeyguard 的 systemd 服务是否在运行。
pub async fn service_active() -> bool {
    systemctl(&["is-active", "--quiet", "honeyguard"]).await
}

/// 请求 systemd 重启 honeyguard 服务，使其加载新二进制；返回命令是否成功退出。
pub async fn restart_service() -> bool {
    systemctl(&["restart", "honeyguard"]).await
}

/// CLI 路径的重启：服务未由 systemd 托管时跳过并提示。
async fn restart_and_report() {
    if !service_active().await {
        println!("（未检测到运行中的 honeyguard systemd 服务，跳过重启；前台运行请手动重启）");
        return;
    }
    if restart_service().await {
        println!("已重启 honeyguard 服务。");
    } else {
        println!("服务重启失败，请手动执行: systemctl restart honeyguard");
    }
}

pub async fn run(check_only: bool, mirror: Option<&str>) -> Result<()> {
    let current = env!("CARGO_PKG_VERSION");
    println!("当前版本 v{current}，查询最新 Release（{}）…", repo());
    let latest = match check(mirror).await? {
        Status::UpToDate => {
            println!("已是最新版本（v{current}）。");
            return Ok(());
        }
        Status::Available { latest } => latest,
    };
    if check_only {
        println!("发现新版本 v{latest}（当前 v{current}）。执行更新：honeyguard update");
        return Ok(());
    }
    ensure_supported()?;
    println!(
        "下载 v{latest}（{}，直连失败自动切换镜像）…",
        musl_target()?
    );
    let installed = install(&latest, mirror).await?;
    println!("sha256 校验通过");
    println!("已更新到 v{latest}（{}）", installed.display());
    restart_and_report().await;
    Ok(())
}

// ---- 常驻自动升级 ----

/// 自动升级检查间隔下限：再密会撞 GitHub API 匿名限流（60 次/小时/IP）。
const MIN_INTERVAL: Duration = Duration::from_secs(300);
/// 距首次（或重启后已到期的）检查的等待：让开机后的网络与 DNS 先稳定。
const STARTUP_DELAY: Duration = Duration::from_secs(60);
/// 检查/安装失败后的重试间隔：断网、Release 产物尚未就绪都是暂时的，不必等满一个周期。
const RETRY_DELAY: Duration = Duration::from_secs(1800);
/// 请求重启后等待自身被停止的宽限：systemctl 可能先于 SIGTERM 送达就返回。
const RESTART_GRACE: Duration = Duration::from_secs(3);
/// 同一新版本连续安装失败达到该次数才上报（容忍瞬时故障），且每个版本只上报一次。
const FAILURE_STREAK: u32 = 2;
/// 上次成功检查（含“已是最新”）的时刻，持久化在 store.runtime。
const KEY_CHECKED_AT: &str = "update_checked_at";
const DETECTOR: &str = "upgrade";

/// 距下一次检查的等待时长。进程重启不打断检查周期：按上次成功检查的时刻续算；
/// 从未检查或已过期间隔则等 [`STARTUP_DELAY`]。
fn next_check_delay(last_checked_at: Option<i64>, now: i64, interval: Duration) -> Duration {
    let interval_sec = interval.as_secs();
    match last_checked_at {
        Some(last) => {
            let due = (last.max(0) as u64).saturating_add(interval_sec);
            match due.checked_sub(now.max(0) as u64) {
                // 时钟回拨时也最多等一个周期
                Some(remaining) if remaining > 0 => {
                    Duration::from_secs(remaining.min(interval_sec))
                }
                _ => STARTUP_DELAY,
            }
        }
        None => STARTUP_DELAY,
    }
}

fn unix_now() -> i64 {
    chrono::Utc::now().timestamp()
}

fn last_checked_at(store: Option<&Store>) -> Option<i64> {
    store?
        .runtime_get(KEY_CHECKED_AT)
        .ok()
        .flatten()
        .and_then(|v| v.parse().ok())
}

/// 安装失败的上报去重（仅进程内，重启即重置）。
#[derive(Default)]
struct Failures {
    version: Option<String>,
    streak: u32,
    notified: bool,
}

impl Failures {
    /// 记一次失败；返回是否应当上报。
    fn record(&mut self, latest: &str) -> bool {
        if self.version.as_deref() != Some(latest) {
            *self = Self {
                version: Some(latest.to_string()),
                ..Default::default()
            };
        }
        self.streak += 1;
        if self.streak >= FAILURE_STREAK && !self.notified {
            self.notified = true;
            return true;
        }
        false
    }
}

/// 通知里的错误摘要：完整错误链会罗列全部镜像 URL，截断到可读长度。
fn brief(err: &anyhow::Error) -> String {
    const MAX: usize = 300;
    let text = format!("{err:#}");
    if text.chars().count() <= MAX {
        return text;
    }
    let mut head: String = text.chars().take(MAX).collect();
    head.push('…');
    head
}

fn failed_alert(latest: &str, err: &anyhow::Error) -> Alert {
    Alert::new(
        Level::Warning,
        DETECTOR,
        "honeyguard 自动升级失败",
        format!(
            "发现新版本 v{latest}（当前 v{}），但连续多次安装失败：\n{}\n可手动执行: sudo honeyguard update",
            env!("CARGO_PKG_VERSION"),
            brief(err)
        ),
    )
    .with_key(latest)
    .always_send()
}

/// 常驻自动升级任务（由 `detectors::supervised` 监督）：定时检查 Release，有新版即下载、
/// 校验、替换二进制并重启服务。失败只在日志里记一笔并按 [`RETRY_DELAY`] 重试，不返回 Err。
pub async fn auto_run(
    interval_sec: u64,
    mirror: Option<String>,
    notifier: Notifier,
    store: Option<Arc<Store>>,
    token: CancellationToken,
) -> Result<()> {
    if !supported() {
        tracing::warn!(
            "自动升级不可用：替换二进制需要 Linux 与 root，任务不启动（手动升级同样受限）"
        );
        return Ok(());
    }
    let mut interval = Duration::from_secs(interval_sec);
    if interval < MIN_INTERVAL {
        tracing::warn!(
            configured_sec = interval_sec,
            min_sec = MIN_INTERVAL.as_secs(),
            "server.auto_update.interval_sec 过小，已抬到下限"
        );
        interval = MIN_INTERVAL;
    }
    let mut updater = AutoUpdater {
        interval,
        mirror,
        notifier,
        store,
        token,
        pending_restart: None,
        failures: Failures::default(),
    };
    tracing::info!(
        interval_sec = interval.as_secs(),
        "auto_update 任务已启动（定时检查 Release，有新版本自动升级并重启）"
    );
    let mut wait = next_check_delay(
        last_checked_at(updater.store.as_deref()),
        unix_now(),
        updater.interval,
    );
    loop {
        tokio::select! {
            _ = tokio::time::sleep(wait) => {}
            _ = updater.token.cancelled() => return Ok(()),
        }
        wait = updater.cycle().await;
    }
}

struct AutoUpdater {
    interval: Duration,
    mirror: Option<String>,
    notifier: Notifier,
    store: Option<Arc<Store>>,
    token: CancellationToken,
    /// 已落盘但本进程尚未重启加载的版本。
    pending_restart: Option<String>,
    failures: Failures,
}

impl AutoUpdater {
    /// 执行一轮检查，返回距下一轮的等待时长。
    async fn cycle(&mut self) -> Duration {
        let latest = match check(self.mirror.as_deref()).await {
            Ok(Status::UpToDate) => {
                tracing::debug!("自动升级：已是最新版本");
                self.mark_checked();
                return self.interval;
            }
            Ok(Status::Available { latest }) => latest,
            Err(err) => {
                tracing::warn!(error = format!("{err:#}"), "自动升级：查询最新版本失败");
                return RETRY_DELAY;
            }
        };
        // 这个版本上次已经装好、只是进程还没重启加载：不重复下载安装
        if self.pending_restart.as_deref() == Some(latest.as_str()) {
            tracing::debug!(version = %latest, "自动升级：新版本已安装，等待进程重启生效");
            self.mark_checked();
            return self.interval;
        }
        match install(&latest, self.mirror.as_deref()).await {
            Ok(path) => {
                tracing::info!(
                    version = %latest,
                    binary = %path.display(),
                    "自动升级：二进制已替换"
                );
                self.mark_checked();
                self.failures = Failures::default();
                self.pending_restart = Some(latest.clone());
                self.restart_or_notify(&latest).await;
                self.interval
            }
            Err(err) => {
                tracing::warn!(
                    version = %latest,
                    error = format!("{err:#}"),
                    "自动升级：安装新版本失败"
                );
                if self.failures.record(&latest) {
                    self.publish(failed_alert(&latest, &err)).await;
                }
                RETRY_DELAY
            }
        }
    }

    fn mark_checked(&self) {
        let Some(store) = &self.store else {
            return;
        };
        if let Err(err) = store.runtime_set(KEY_CHECKED_AT, &unix_now().to_string()) {
            tracing::warn!(error = %err, "自动升级：记录检查时间失败");
        }
    }

    async fn publish(&self, alert: Alert) {
        if let Err(err) = self.notifier.publish(alert).await {
            tracing::warn!(error = %err, "自动升级：通知发布失败");
        }
    }

    /// 通知升级结果并请求重启。systemctl restart 会把同 cgroup 的本进程一并停掉：
    /// 收到停止信号即成功路径（之后的启动上报接力）；命令返回而本进程还在才是没重启成。
    async fn restart_or_notify(&self, latest: &str) {
        let managed = service_active().await;
        let effect = if managed {
            "服务正在重启以加载新版本"
        } else {
            "当前进程不由 systemd 托管，重启 honeyguard 后生效"
        };
        self.publish(
            Alert::new(
                Level::Info,
                DETECTOR,
                "honeyguard 已自动升级",
                format!("v{} → v{latest}\n{effect}", env!("CARGO_PKG_VERSION")),
            )
            .with_key(latest)
            .always_send(),
        )
        .await;
        if !managed {
            return;
        }
        tokio::select! {
            _ = self.token.cancelled() => return,
            _ = restart_service() => {}
        }
        if tokio::time::timeout(RESTART_GRACE, self.token.cancelled())
            .await
            .is_err()
        {
            tracing::warn!("自动升级：已请求重启但服务未被重启，需手动重启");
            self.publish(
                Alert::new(
                    Level::Warning,
                    DETECTOR,
                    "honeyguard 升级后未自动重启",
                    format!(
                        "二进制已更新到 v{latest}，但服务没有重启，当前仍在运行旧版本。\n请手动执行: systemctl restart honeyguard"
                    ),
                )
                .with_key(latest)
                .always_send(),
            )
            .await;
        }
    }
}

/// RAII 清理临时目录。
struct RunScope(PathBuf);
impl Drop for RunScope {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_parsing_and_comparison() {
        assert_eq!(parse_version("0.2.0"), Some((0, 2, 0)));
        assert_eq!(parse_version("v1.0"), Some((1, 0, 0)));
        assert_eq!(parse_version("abc"), None);
        assert_eq!(is_newer("0.2.1", "0.2.0"), Some(true));
        assert_eq!(is_newer("0.2.0", "0.2.0"), Some(false));
        assert_eq!(
            is_newer("0.10.0", "0.9.9"),
            Some(true),
            "数值比较而非字符串"
        );
        assert_eq!(is_newer("v1.0.0", "0.2.0"), Some(true));
    }

    #[test]
    fn mirror_candidates_configuration() {
        let auto = mirror_candidates(None);
        assert_eq!(
            auto.first().map(String::as_str),
            Some(""),
            "自动模式直连优先"
        );
        assert!(auto.len() >= 3, "应内置至少两个公共镜像回退");
        let fixed = mirror_candidates(Some("https://my.proxy.com"));
        assert_eq!(
            fixed,
            vec!["https://my.proxy.com/".to_string()],
            "显式指定只用该镜像"
        );
        let trimmed = mirror_candidates(Some("https://my.proxy.com//"));
        assert_eq!(
            trimmed,
            vec!["https://my.proxy.com/".to_string()],
            "结尾斜杠归一"
        );
    }

    #[test]
    fn content_validators_reject_html_pages() {
        let html = b"<!DOCTYPE html><html>blocked</html>";
        assert!(!valid_gzip(html), "HTML 不是合法安装包");
        assert!(!valid_sha_file(html), "HTML 不是合法校验文件");
        let gz = [0x1f, 0x8b, 0x08, 0x00];
        assert!(valid_gzip(&gz));
        let sha = b"94176d686473f905c7e64a2ef0a5a52e7194e02b7b8442b4ba7c941f10d589db  pkg";
        assert!(valid_sha_file(sha));
        assert!(!valid_sha_file(b"short"));
    }

    #[test]
    fn sha256_verify_matches() {
        let dir = tempfile::tempdir().unwrap();
        let pkg = dir.path().join("pkg");
        let sha = dir.path().join("pkg.sha256");
        std::fs::write(&pkg, b"honeyguard-payload").unwrap();
        let digest = sha256_hex(b"honeyguard-payload");
        std::fs::write(&sha, format!("{digest}  pkg.tar.gz\n")).unwrap();
        assert!(verify_sha256(&pkg, &sha).is_ok());
        std::fs::write(&sha, "deadbeef  pkg.tar.gz\n").unwrap();
        assert!(verify_sha256(&pkg, &sha).is_err());
    }

    #[test]
    fn extracts_binary_from_tar_gz() {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("pkg.tar.gz");
        // 构造与 CI 产物同构的 tar.gz：honeyguard-<target>/honeyguard
        let payload = b"#!/bin/sh\n#honeyguard-bin";
        let file = std::fs::File::create(&archive).unwrap();
        let enc = flate2::write::GzEncoder::new(file, flate2::Compression::default());
        let mut builder = tar::Builder::new(enc);
        let mut header = tar::Header::new_gnu();
        header.set_size(payload.len() as u64);
        header.set_mode(0o755);
        header.set_cksum();
        builder
            .append_data(
                &mut header,
                "honeyguard-x86_64-unknown-linux-musl/honeyguard",
                &payload[..],
            )
            .unwrap();
        let enc = builder.into_inner().unwrap();
        enc.finish().unwrap();

        let out = dir.path().join("extracted");
        extract_binary(&archive, &out).unwrap();
        assert_eq!(std::fs::read(&out).unwrap(), payload);
    }

    /// 一次性 HTTP 响应器：读完请求头后发送 head + body，再保持连接 hold 时长后关闭。
    /// body 短于 Content-Length 且 hold 足够长时，即模拟「响应头 200、body 卡死」。
    fn spawn_responder(head: String, body: Vec<u8>, hold: Duration) -> String {
        use std::io::{BufRead, BufReader, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/pkg.tar.gz", listener.local_addr().unwrap());
        std::thread::spawn(move || {
            let Ok((mut conn, _)) = listener.accept() else {
                return;
            };
            let mut reader = BufReader::new(conn.try_clone().unwrap());
            loop {
                let mut line = String::new();
                if reader.read_line(&mut line).unwrap_or(0) == 0 || line.trim_end().is_empty() {
                    break;
                }
            }
            let _ = conn.write_all(head.as_bytes());
            let _ = conn.write_all(&body);
            std::thread::sleep(hold);
            let _ = conn.shutdown(std::net::Shutdown::Both);
        });
        url
    }

    #[tokio::test]
    async fn download_falls_back_when_body_stalls() {
        let gzip = vec![0x1f, 0x8b, 0x08, 0x00, 0x00];
        // 第一个源：响应头 200 但只发出一部分 body 便卡住（国内直连 release-assets 的典型表现）
        let stalled = spawn_responder(
            "HTTP/1.1 200 OK\r\nContent-Length: 1000\r\nConnection: close\r\n\r\n".to_string(),
            gzip.clone(),
            Duration::from_secs(6),
        );
        // 第二个源：完整返回合法内容
        let healthy = spawn_responder(
            format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                gzip.len()
            ),
            gzip.clone(),
            Duration::ZERO,
        );

        let client = crate::notify::webhook::http_client();
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("pkg.tar.gz");
        download_any(
            &client,
            &[stalled, healthy],
            &dest,
            valid_gzip,
            Duration::from_secs(2),
        )
        .await
        .expect("body 卡死的源应计入错误并回退到下一个镜像，而非整体失败");
        assert_eq!(std::fs::read(&dest).unwrap(), gzip);
    }

    #[tokio::test]
    async fn download_reports_every_failed_source() {
        let stalled = spawn_responder(
            "HTTP/1.1 200 OK\r\nContent-Length: 1000\r\nConnection: close\r\n\r\n".to_string(),
            vec![0x1f, 0x8b],
            Duration::from_secs(6),
        );
        let html = spawn_responder(
            "HTTP/1.1 200 OK\r\nContent-Length: 14\r\nConnection: close\r\n\r\n".to_string(),
            b"<html>x</html>".to_vec(),
            Duration::ZERO,
        );

        let client = crate::notify::webhook::http_client();
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("pkg.tar.gz");
        let err = download_any(
            &client,
            &[stalled.clone(), html.clone()],
            &dest,
            valid_gzip,
            Duration::from_secs(2),
        )
        .await
        .expect_err("全部源失败应返回错误");
        let msg = err.to_string();
        assert!(msg.contains("全部下载源失败"), "{msg}");
        assert!(
            msg.contains(&stalled) && msg.contains("读取内容失败"),
            "{msg}"
        );
        assert!(msg.contains(&html) && msg.contains("内容不合法"), "{msg}");
        assert!(!dest.exists(), "失败时不应落盘");
    }

    #[test]
    fn status_against_current_version() {
        assert_eq!(
            status_of("0.2.1", "0.2.0").unwrap(),
            Status::Available {
                latest: "0.2.1".to_string()
            }
        );
        assert_eq!(status_of("0.2.0", "0.2.0").unwrap(), Status::UpToDate);
        assert_eq!(
            status_of("0.1.9", "0.2.0").unwrap(),
            Status::UpToDate,
            "远端版本更低时不降级"
        );
        assert!(status_of("abc", "0.2.0").is_err());
    }

    #[test]
    fn check_delay_resumes_from_last_success() {
        let interval = Duration::from_secs(6 * 3600);
        // 从未检查：启动后稍等再查
        assert_eq!(next_check_delay(None, 1_000_000, interval), STARTUP_DELAY);
        // 1 小时前查过：只等剩余的 5 小时（服务重启不打断周期）
        assert_eq!(
            next_check_delay(Some(1_000_000 - 3600), 1_000_000, interval),
            Duration::from_secs(5 * 3600)
        );
        assert_eq!(
            next_check_delay(Some(999_990), 1_000_000, interval),
            interval - Duration::from_secs(10)
        );
        // 早已过期间隔（停机很久）：启动后稍等再查
        assert_eq!(
            next_check_delay(Some(1_000_000 - 7 * 3600), 1_000_000, interval),
            STARTUP_DELAY
        );
        // 时钟回拨：最多等一个周期
        assert_eq!(
            next_check_delay(Some(1_000_000 + 999 * 3600), 1_000_000, interval),
            interval
        );
    }

    #[test]
    fn failure_report_needs_streak_and_happens_once_per_version() {
        let mut failures = Failures::default();
        assert!(!failures.record("9.9.9"), "首次失败不上报（容忍瞬时故障）");
        assert!(failures.record("9.9.9"), "连续失败达到阈值才上报");
        assert!(!failures.record("9.9.9"), "同一版本只上报一次");
        // 换了新版本重新计数
        assert!(!failures.record("9.9.10"));
        assert!(failures.record("9.9.10"));
    }

    #[test]
    fn failure_alert_is_actionable_and_bypasses_min_level() {
        let err = anyhow::anyhow!("sha256 校验失败");
        let alert = failed_alert("9.9.9", &err);
        assert_eq!(alert.level, Level::Warning);
        assert!(alert.always_send);
        assert_eq!(alert.detector, DETECTOR);
        assert!(alert.title.contains("自动升级失败"));
        assert!(alert.body.contains("v9.9.9") && alert.body.contains("sha256 校验失败"));
        assert!(
            alert.body.contains("honeyguard update"),
            "应给出手动处理入口"
        );
        assert_eq!(alert.aggregate_key(), format!("{DETECTOR}:9.9.9"));

        // 过长的错误链截断，不撑爆通知
        let long = anyhow::anyhow!("{}", "x".repeat(1000));
        let body = failed_alert("9.9.9", &long).body;
        assert!(
            body.contains('…') && !body.contains(&"x".repeat(400)),
            "应截断到可读长度：{} 字符",
            body.chars().count()
        );
        assert!(body.contains("可手动执行"), "截断后仍保留处理入口");
    }

    #[test]
    fn real_exe_path_drops_deleted_suffix() {
        assert_eq!(
            real_exe_path(PathBuf::from("/usr/local/bin/honeyguard (deleted)")),
            PathBuf::from("/usr/local/bin/honeyguard")
        );
        assert_eq!(
            real_exe_path(PathBuf::from("/usr/local/bin/honeyguard")),
            PathBuf::from("/usr/local/bin/honeyguard")
        );
        // 只有文件名本身带该后缀才算
        assert_eq!(
            real_exe_path(PathBuf::from("/opt/app (deleted)/honeyguard")),
            PathBuf::from("/opt/app (deleted)/honeyguard")
        );
    }

    #[test]
    fn replace_binary_swaps_content_and_leaves_no_staging_file() {
        let dir = tempfile::tempdir().unwrap();
        let exe = dir.path().join("honeyguard");
        let new = dir.path().join("new");
        std::fs::write(&exe, b"old").unwrap();
        std::fs::write(&new, b"new-binary").unwrap();
        replace_binary(&exe, &new).unwrap();
        assert_eq!(std::fs::read(&exe).unwrap(), b"new-binary");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&exe).unwrap().permissions().mode() & 0o777,
                0o755
            );
        }
        let leftovers: Vec<String> = std::fs::read_dir(dir.path())
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.starts_with(".honeyguard.update"))
            .collect();
        assert!(leftovers.is_empty(), "不应残留临时文件：{leftovers:?}");
    }

    /// 按请求路径后缀路由的最小 HTTP 服务器（充当镜像源）：`routes` 为 (后缀, 响应体)，
    /// 依次处理 `requests` 个连接后退出。返回镜像前缀（如 `http://127.0.0.1:12345`）。
    fn spawn_mirror(routes: Vec<(&'static str, Vec<u8>)>, requests: usize) -> String {
        use std::io::{BufRead, BufReader, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let mirror = format!("http://{}", listener.local_addr().unwrap());
        std::thread::spawn(move || {
            for _ in 0..requests {
                let Ok((mut conn, _)) = listener.accept() else {
                    return;
                };
                let mut reader = BufReader::new(conn.try_clone().unwrap());
                let mut line = String::new();
                if reader.read_line(&mut line).unwrap_or(0) == 0 {
                    return;
                }
                let path = line.split_whitespace().nth(1).unwrap_or("");
                loop {
                    let mut header = String::new();
                    if reader.read_line(&mut header).unwrap_or(0) == 0
                        || header.trim_end().is_empty()
                    {
                        break;
                    }
                }
                let (status, body) = match routes.iter().find(|(suffix, _)| path.ends_with(suffix))
                {
                    Some((_, body)) => ("200 OK", body.clone()),
                    None => ("404 Not Found", b"not found".to_vec()),
                };
                let _ = write!(
                    conn,
                    "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = conn.write_all(&body);
                let _ = conn.flush();
            }
        });
        mirror
    }

    /// 与 CI 产物同构的安装包（`honeyguard-<target>/honeyguard`）及其 sha256 文本。
    fn build_package() -> (Vec<u8>, String) {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("pkg.tar.gz");
        let payload = b"#!/bin/sh\n#honeyguard-bin";
        let file = std::fs::File::create(&archive).unwrap();
        let enc = flate2::write::GzEncoder::new(file, flate2::Compression::default());
        let mut builder = tar::Builder::new(enc);
        let mut header = tar::Header::new_gnu();
        header.set_size(payload.len() as u64);
        header.set_mode(0o755);
        header.set_cksum();
        builder
            .append_data(
                &mut header,
                "honeyguard-x86_64-unknown-linux-musl/honeyguard",
                &payload[..],
            )
            .unwrap();
        builder.into_inner().unwrap().finish().unwrap();
        let pkg = std::fs::read(&archive).unwrap();
        (pkg.clone(), format!("{}  pkg.tar.gz\n", sha256_hex(&pkg)))
    }

    #[tokio::test]
    async fn check_fetches_latest_version_through_mirror() {
        // 镜像前缀指向本地服务器：查询 URL = {mirror}/https://api.github.com/repos/{repo}/releases/latest
        let mirror = spawn_mirror(
            vec![("releases/latest", br#"{"tag_name":"v9.9.9"}"#.to_vec())],
            1,
        );
        assert_eq!(
            check(Some(&mirror)).await.unwrap(),
            Status::Available {
                latest: "9.9.9".to_string()
            }
        );

        let same = format!(r#"{{"tag_name":"v{}"}}"#, env!("CARGO_PKG_VERSION"));
        let mirror = spawn_mirror(vec![("releases/latest", same.into_bytes())], 1);
        assert_eq!(check(Some(&mirror)).await.unwrap(), Status::UpToDate);
    }

    #[tokio::test]
    async fn fetch_binary_downloads_verifies_and_extracts() {
        let (pkg, sha) = build_package();
        let mirror = spawn_mirror(
            vec![
                (".tar.gz.sha256", sha.into_bytes()),
                (".tar.gz", pkg.clone()),
            ],
            2,
        );
        let work = tempfile::tempdir().unwrap();
        let binary = fetch_binary("9.9.9", Some(&mirror), work.path())
            .await
            .unwrap();
        assert_eq!(
            std::fs::read(&binary).unwrap(),
            b"#!/bin/sh\n#honeyguard-bin"
        );

        // 校验文件对不上则拒绝（镜像返回了损坏/被替换的包）
        let bogus = format!("{}  pkg.tar.gz\n", sha256_hex(b"something else"));
        let mirror = spawn_mirror(
            vec![(".tar.gz.sha256", bogus.into_bytes()), (".tar.gz", pkg)],
            2,
        );
        let work = tempfile::tempdir().unwrap();
        let err = fetch_binary("9.9.9", Some(&mirror), work.path())
            .await
            .expect_err("sha256 不一致必须失败");
        assert!(err.to_string().contains("sha256 校验失败"), "{err:#}");
        assert!(
            !work.path().join("honeyguard").exists(),
            "校验失败不得落盘二进制"
        );
    }
}
