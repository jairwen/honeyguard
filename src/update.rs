//! 自更新（PRD DEP-03）：`honeyguard update` 一条命令完成
//! 查询最新 Release → 下载对应架构产物 → sha256 校验 → 原子替换自身 → 重启服务。
//!
//! 仓库地址默认 `jairwen/honeyguard`，可用环境变量 `HONEYGUARD_REPO` 覆盖。
//! `--check` 只检查不更新（无需 root）。

use anyhow::{Context, Result, bail};
use sha2::{Digest, Sha256};
use std::io::Read;
use std::path::{Path, PathBuf};

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

/// 依次尝试候选 URL 下载（内容须通过 validator），任一成功即写入 dest。
async fn download_any(
    client: &reqwest::Client,
    urls: &[String],
    dest: &Path,
    validator: fn(&[u8]) -> bool,
) -> Result<()> {
    let mut errors = Vec::new();
    for url in urls {
        match client.get(url).send().await {
            Ok(resp) if resp.status().is_success() => {
                let bytes = resp
                    .bytes()
                    .await
                    .with_context(|| format!("读取下载内容失败: {url}"))?;
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

/// 原子替换自身：写到同目录临时文件再 rename（同文件系统保证原子性）。
fn replace_self(new_binary: &Path) -> Result<PathBuf> {
    let exe = std::env::current_exe().context("获取当前二进制路径失败")?;
    let staging = exe
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(".honeyguard.update.tmp");
    std::fs::copy(new_binary, &staging).context("写出新版本失败")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&staging, std::fs::Permissions::from_mode(0o755))
            .context("设置可执行权限失败")?;
    }
    std::fs::rename(&staging, &exe).with_context(|| format!("替换 {} 失败", exe.display()))?;
    Ok(exe)
}

/// systemd 服务在运行则重启，使其加载新二进制。
fn restart_service() {
    let ok = std::process::Command::new("systemctl")
        .args(["is-active", "--quiet", "honeyguard"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !ok {
        println!("（未检测到运行中的 honeyguard systemd 服务，跳过重启；前台运行请手动重启）");
        return;
    }
    let restarted = std::process::Command::new("systemctl")
        .args(["restart", "honeyguard"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if restarted {
        println!("已重启 honeyguard 服务。");
    } else {
        println!("服务重启失败，请手动执行: systemctl restart honeyguard");
    }
}

pub async fn run(check_only: bool, mirror: Option<&str>) -> Result<()> {
    let repo = repo();
    let current = env!("CARGO_PKG_VERSION");
    let client = crate::notify::webhook::http_client();
    let mirrors = mirror_candidates(mirror);

    println!("当前版本 v{current}，查询最新 Release（{repo}）…");
    let latest = fetch_latest_version(&client, &repo, &mirrors).await?;
    let newer = is_newer(&latest, current)
        .with_context(|| format!("无法比较版本: latest={latest} current={current}"))?;
    if !newer {
        println!("已是最新版本（v{current}）。");
        return Ok(());
    }
    if check_only {
        println!("发现新版本 v{latest}（当前 v{current}）。执行更新：honeyguard update");
        return Ok(());
    }
    if !std::env::consts::OS.contains("linux") {
        bail!("自更新仅支持 Linux（当前 {}）", std::env::consts::OS);
    }
    if !is_root() {
        bail!(
            "更新系统路径下的二进制需要 root，请 sudo 运行（仅检查可用 honeyguard update --check）"
        );
    }

    let target = musl_target()?;
    let base = format!("https://github.com/{repo}/releases/download/v{latest}/honeyguard-{target}");
    let pkg_urls: Vec<String> = mirrors
        .iter()
        .map(|m| format!("{m}{base}.tar.gz"))
        .collect();
    let sha_urls: Vec<String> = mirrors
        .iter()
        .map(|m| format!("{m}{base}.tar.gz.sha256"))
        .collect();
    let work_dir = std::env::temp_dir().join(format!("honeyguard-update-{}", std::process::id()));
    std::fs::create_dir_all(&work_dir).context("创建临时目录失败")?;
    let scope = RunScope(work_dir.clone());

    let pkg = work_dir.join("pkg.tar.gz");
    let sha = work_dir.join("pkg.sha256");
    let binary = work_dir.join("honeyguard");

    println!("下载 v{latest}（{target}，直连失败自动切换镜像）…");
    download_any(&client, &pkg_urls, &pkg, valid_gzip).await?;
    download_any(&client, &sha_urls, &sha, valid_sha_file).await?;
    verify_sha256(&pkg, &sha)?;
    println!("sha256 校验通过");
    extract_binary(&pkg, &binary)?;
    let installed = replace_self(&binary)?;
    println!("已更新到 v{latest}（{}）", installed.display());
    restart_service();
    drop(scope); // 清理临时目录
    Ok(())
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
}
