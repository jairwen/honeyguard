//! DET-05 文件完整性与持久化痕迹检测（PRD §5.1）。
//!
//! 以周期全量扫描实现（默认 60s，受控文件均为小文本，开销毫秒级；比 PRD 的
//! “inotify + 10 分钟兜底”方案检测延迟更低且无内核依赖）：
//!
//! - 受控路径（glob）SHA-256 与基线比对：新增/修改/删除 → 分级告警并更新基线；
//! - /etc/passwd 出现新的可登录用户（UID=0 或 UID≥1000 且 shell 可登录）→ critical；
//! - 配置目录出现新增 SUID 文件 → warning。
//!
//! 首次运行只建基线不告警；`honeyguard baseline update` 重建基线。
//! 依赖 SQLite 基线持久化，无状态库时不启动。

use crate::alert::{Alert, Level};
use crate::config::FileIntegrityCfg;
use crate::notify::Notifier;
use crate::store::Store;
use crate::whitelist::Whitelist;
use anyhow::Result;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio_util::sync::CancellationToken;

pub async fn run(
    cfg: FileIntegrityCfg,
    whitelist: Arc<Whitelist>,
    notifier: Notifier,
    store: Option<Arc<Store>>,
    token: CancellationToken,
) -> Result<()> {
    if !Path::new("/proc").exists() {
        tracing::warn!("file_integrity 检测器：/proc 不可用（非 Linux？），不启动");
        return Ok(());
    }
    let Some(store) = store else {
        tracing::warn!("file_integrity 检测器：状态数据库不可用，无法建立基线，不启动");
        return Ok(());
    };
    let interval = Duration::from_secs(cfg.interval_sec.max(1));
    tracing::info!(
        interval_sec = cfg.interval_sec,
        "file_integrity 检测器已启动"
    );
    loop {
        tokio::select! {
            _ = tokio::time::sleep(interval) => {}
            _ = token.cancelled() => {
                tracing::info!("file_integrity 检测器退出");
                return Ok(());
            }
        }
        if let Err(err) = scan(&cfg, &whitelist, &notifier, &store).await {
            tracing::warn!(error = %err, "file_integrity 扫描出错");
        }
    }
}

/// 一轮扫描：建基线或比对告警。返回产生的告警数（0 = 建基线或无变化）。
pub async fn scan(
    cfg: &FileIntegrityCfg,
    whitelist: &Whitelist,
    notifier: &Notifier,
    store: &Store,
) -> Result<usize> {
    let baseline = store.fim_load()?;
    let first_run = baseline.is_empty();

    let mut alerts = 0usize;
    // ---- 受控文件 ----
    let mut current_files: HashMap<String, String> = HashMap::new();
    for path in expand_globs(&effective_watch(cfg)) {
        let Ok(meta) = std::fs::metadata(&path) else {
            continue;
        };
        if !meta.is_file() {
            continue;
        }
        let path_str = path.to_string_lossy().into_owned();
        let Some(sha) = hash_file(&path) else {
            continue;
        }; // 短暂竞态：文件消失则跳过
        current_files.insert(path_str.clone(), sha.clone());
        if first_run {
            continue;
        }
        match baseline.get(&path_str) {
            Some(entry) if entry.1 == "file" => {
                if entry.0 != sha && !whitelist.allows_path(&path_str) {
                    let alert = file_alert(
                        path_level(&path_str),
                        &path_str,
                        "已修改",
                        format!("内容指纹变化（{} → {}）", &entry.0[..8], &sha[..8]),
                    );
                    if notifier.publish(alert).await.is_ok() {
                        alerts += 1;
                    }
                }
            }
            _ => {
                // 不在基线中的新文件（含基线缺失场景）
                if !whitelist.allows_path(&path_str) {
                    let alert = file_alert(
                        path_level(&path_str),
                        &path_str,
                        "新增",
                        format!("内容指纹 {}", &sha[..8]),
                    );
                    if notifier.publish(alert).await.is_ok() {
                        alerts += 1;
                    }
                }
            }
        }
    }

    if !first_run {
        // 基线中已消失的文件
        for (path, (_, kind)) in &baseline {
            if kind == "file" && !current_files.contains_key(path) && !whitelist.allows_path(path) {
                let alert = file_alert(path_level(path), path, "已删除", String::new());
                if notifier.publish(alert).await.is_ok() {
                    alerts += 1;
                }
            }
        }
    }

    // ---- 可登录用户 ----
    let current_users = login_users("/etc/passwd");
    for user in &current_users {
        let key = format!("user:{user}");
        if first_run {
            continue;
        }
        if !baseline.contains_key(&key) {
            let alert = Alert::new(
                Level::Critical,
                "file_integrity",
                "新增可登录用户",
                format!(
                    "/etc/passwd 出现新的可登录用户 {user}（UID=0 或可登录 shell）。\n若非管理员操作，请立即检查：usermod -L {user} 并排查创建来源。"
                ),
            )
            .with_key(key.clone());
            if notifier.publish(alert).await.is_ok() {
                alerts += 1;
            }
        }
    }

    // ---- SUID 文件 ----
    let mut current_suid: HashSet<String> = HashSet::new();
    for dir in &cfg.suid_dirs {
        for path in walk(Path::new(dir), 3) {
            if let Ok(meta) = std::fs::metadata(&path) {
                use std::os::unix::fs::PermissionsExt;
                if meta.is_file() && meta.permissions().mode() & 0o4000 != 0 {
                    current_suid.insert(path.to_string_lossy().into_owned());
                }
            }
        }
    }
    for path in &current_suid {
        let key = format!("suid:{path}");
        if first_run || baseline.contains_key(&key) {
            continue;
        }
        if !whitelist.allows_path(path) {
            let alert = Alert::new(
                Level::Warning,
                "file_integrity",
                "新增 SUID 文件",
                format!("{path} 被设置了 SUID 位。常见于提权后门，确认来源：ls -l {path} && dpkg -S {path}"),
            )
            .with_key(key.clone());
            if notifier.publish(alert).await.is_ok() {
                alerts += 1;
            }
        }
    }

    // ---- 更新基线（无论是否告警，状态推进到当前事实） ----
    for (path, sha) in &current_files {
        store.fim_put(path, sha, "file")?;
    }
    for (path, (_, kind)) in &baseline {
        if kind == "file" && !current_files.contains_key(path) {
            store.fim_delete(path)?;
        }
    }
    for user in &current_users {
        store.fim_put(&format!("user:{user}"), user, "user")?;
    }
    for path in &current_suid {
        store.fim_put(&format!("suid:{path}"), path, "suid")?;
    }

    if first_run {
        tracing::info!(
            files = current_files.len(),
            users = current_users.len(),
            suid = current_suid.len(),
            "file_integrity 基线已建立"
        );
    } else if alerts > 0 {
        tracing::warn!(alerts, "file_integrity 检测到变化");
    }
    Ok(alerts)
}

/// `honeyguard baseline update`：清空并重建基线（不产生告警）。
pub fn rebuild_baseline(cfg: &FileIntegrityCfg, store: &Store) -> Result<(usize, usize, usize)> {
    store.fim_clear()?;
    // 复用 scan 但用哑 notifier 会发告警——不可行；这里静默重建：
    let files: HashMap<String, String> = expand_globs(&effective_watch(cfg))
        .into_iter()
        .filter_map(|p| hash_file(&p).map(|sha| (p.to_string_lossy().into_owned(), sha)))
        .collect();
    for (path, sha) in &files {
        store.fim_put(path, sha, "file")?;
    }
    let users = login_users("/etc/passwd");
    for user in &users {
        store.fim_put(&format!("user:{user}"), user, "user")?;
    }
    let mut suid = HashSet::new();
    for dir in &cfg.suid_dirs {
        for path in walk(Path::new(dir), 3) {
            if let Ok(meta) = std::fs::metadata(&path) {
                use std::os::unix::fs::PermissionsExt;
                if meta.is_file() && meta.permissions().mode() & 0o4000 != 0 {
                    suid.insert(path.to_string_lossy().into_owned());
                }
            }
        }
    }
    for path in &suid {
        store.fim_put(&format!("suid:{path}"), path, "suid")?;
    }
    Ok((files.len(), users.len(), suid.len()))
}

fn effective_watch(cfg: &FileIntegrityCfg) -> Vec<String> {
    let base = if cfg.watch.is_empty() {
        crate::config::DEFAULT_FIM_WATCH
            .iter()
            .map(|s| s.to_string())
            .collect()
    } else {
        cfg.watch.clone()
    };
    let mut all = base;
    all.extend(cfg.extra_watch.iter().cloned());
    all
}

fn expand_globs(patterns: &[String]) -> Vec<PathBuf> {
    let mut out = HashSet::new();
    for pattern in patterns {
        match glob::glob(pattern) {
            Ok(paths) => {
                for path in paths.flatten() {
                    out.insert(path);
                }
            }
            Err(err) => tracing::warn!(pattern, error = %err, "fim watch 路径表达式无效，已跳过"),
        }
    }
    out.into_iter().collect()
}

fn hash_file(path: &Path) -> Option<String> {
    let bytes = std::fs::read(path).ok()?;
    Some(hex(&Sha256::digest(&bytes)))
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}

/// 解析 /etc/passwd 中的可登录用户：UID=0 或（UID≥1000 且 shell 非 nologin/false）。
fn login_users(passwd_path: &str) -> HashSet<String> {
    let mut out = HashSet::new();
    let Ok(content) = std::fs::read_to_string(passwd_path) else {
        return out;
    };
    for line in content.lines() {
        let fields: Vec<&str> = line.split(':').collect();
        if fields.len() < 7 {
            continue;
        }
        let Ok(uid) = fields[2].parse::<u32>() else {
            continue;
        };
        let shell = fields[6];
        let shell_login = !shell.contains("nologin")
            && !shell.contains("false")
            && shell != "/bin/sync"
            && !shell.is_empty();
        if uid == 0 || (uid >= 1000 && shell_login) {
            out.insert(fields[0].to_string());
        }
    }
    out
}

/// 受控路径的严重级别：入口与提权相关为 critical（PRD 附录 C）。
fn file_alert(level: Level, path: &str, event: &str, detail: String) -> Alert {
    let hint = if path.ends_with("authorized_keys") {
        "。authorized_keys 变更若非本人操作，请立即检查并清除！"
    } else if path.contains("shadow") || path.contains("sudoers") {
        "。请确认是否为管理员操作。"
    } else {
        "。"
    };
    let detail_line = if detail.is_empty() {
        String::new()
    } else {
        format!("\n{detail}")
    };
    Alert::new(
        level,
        "file_integrity",
        format!("受控文件{event}"),
        format!("路径：{path}{detail_line}{hint}"),
    )
    .with_key(path.to_string())
}

/// 受控路径的严重级别：入口与提权相关为 critical（PRD 附录 C）。
fn path_level(path: &str) -> Level {
    let critical = path.ends_with("authorized_keys")
        || path == "/etc/shadow"
        || path == "/etc/ld.so.preload"
        || path.contains("sudoers");
    if critical {
        Level::Critical
    } else {
        Level::Warning
    }
}

/// 受限深度递归遍历（跳过符号链接，防环）。
fn walk(dir: &Path, depth: u8) -> Vec<PathBuf> {
    let mut out = Vec::new();
    if depth == 0 {
        return out;
    }
    let Ok(entries) = std::fs::read_dir(dir) else {
        return out;
    };
    for entry in entries.flatten() {
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        let path = entry.path();
        if file_type.is_symlink() {
            continue;
        }
        if file_type.is_dir() {
            out.extend(walk(&path, depth - 1));
        } else {
            out.push(path);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alert::Level as L;
    use crate::config::AlertCfg;
    use crate::notify::{Delivery, Notifier as NotifierImpl};

    fn notifier() -> (Arc<std::sync::Mutex<Vec<Alert>>>, Notifier) {
        let recorded = Arc::new(std::sync::Mutex::new(Vec::new()));
        let (n, _) = NotifierImpl::start(
            AlertCfg {
                min_level: L::Info,
                rate_limit_per_min: 1000,
                ..Default::default()
            },
            vec![],
            Delivery::Mock(recorded.clone()),
            None,
        );
        (recorded, n)
    }

    async fn settle() {
        for _ in 0..4 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    fn cfg_with(dir: &std::path::Path) -> FileIntegrityCfg {
        let watch = dir.join("**").join("*").to_string_lossy().into_owned();
        FileIntegrityCfg {
            enabled: true,
            interval_sec: 60,
            watch: vec![watch],
            extra_watch: vec![],
            suid_dirs: vec![dir.join("suid").to_string_lossy().into_owned()],
        }
    }

    #[tokio::test]
    async fn first_scan_builds_baseline_without_alerts() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("app.conf"), "v1").unwrap();
        let (recorded, notifier) = notifier();
        let store = Store::open(Path::new(":memory:")).unwrap();
        let cfg = cfg_with(dir.path());
        let alerts = scan(&cfg, &Whitelist::default(), &notifier, &store)
            .await
            .unwrap();
        assert_eq!(alerts, 0, "首轮只建基线");
        assert!(recorded.lock().unwrap().is_empty());
        assert_eq!(
            store
                .fim_load()
                .unwrap()
                .iter()
                .filter(|(_, (_, k))| k == "file")
                .count(),
            1
        );
    }

    #[tokio::test]
    async fn modification_deletion_and_new_file_alert() {
        let dir = tempfile::tempdir().unwrap();
        let keep = dir.path().join("keep.conf");
        let gone = dir.path().join("gone.conf");
        std::fs::write(&keep, "v1").unwrap();
        std::fs::write(&gone, "x").unwrap();
        let (recorded, notifier) = notifier();
        let store = Store::open(Path::new(":memory:")).unwrap();
        let cfg = cfg_with(dir.path());
        scan(&cfg, &Whitelist::default(), &notifier, &store)
            .await
            .unwrap();

        std::fs::write(&keep, "v2").unwrap();
        std::fs::remove_file(&gone).unwrap();
        std::fs::write(dir.path().join("new.conf"), "n").unwrap();
        let alerts = scan(&cfg, &Whitelist::default(), &notifier, &store)
            .await
            .unwrap();
        settle().await;

        assert_eq!(alerts, 3, "修改 + 删除 + 新增各一条");
        let got = recorded.lock().unwrap().clone();
        let titles: Vec<&str> = got.iter().map(|a| a.title.as_str()).collect();
        assert!(titles.contains(&"受控文件已修改"), "{titles:?}");
        assert!(titles.contains(&"受控文件已删除"), "{titles:?}");
        assert!(titles.contains(&"受控文件新增"), "{titles:?}");
        assert!(
            got.iter().all(|a| a.level == L::Warning),
            "普通路径应为 warning"
        );
    }

    #[tokio::test]
    async fn authorized_keys_change_is_critical() {
        let dir = tempfile::tempdir().unwrap();
        let ssh_dir = dir.path().join(".ssh");
        std::fs::create_dir(&ssh_dir).unwrap();
        std::fs::write(ssh_dir.join("authorized_keys"), "ssh-ed25519 AAA").unwrap();
        let (recorded, notifier) = notifier();
        let store = Store::open(Path::new(":memory:")).unwrap();
        let cfg = cfg_with(dir.path());
        scan(&cfg, &Whitelist::default(), &notifier, &store)
            .await
            .unwrap();

        std::fs::write(ssh_dir.join("authorized_keys"), "ssh-ed25519 BBB").unwrap();
        scan(&cfg, &Whitelist::default(), &notifier, &store)
            .await
            .unwrap();
        settle().await;
        let got = recorded.lock().unwrap().clone();
        assert_eq!(got.len(), 1);
        assert_eq!(
            got[0].level,
            L::Critical,
            "authorized_keys 变更应为 critical"
        );
        assert!(got[0].body.contains("立即检查"));
    }

    #[test]
    fn login_users_parsing() {
        let dir = tempfile::tempdir().unwrap();
        let passwd = dir.path().join("passwd");
        std::fs::write(
            &passwd,
            "root:x:0:0:root:/root:/bin/bash\n\
             daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n\
             ubuntu:x:1000:1000::/home/ubuntu:/bin/bash\n\
             svc:x:999:999::/home/svc:/usr/sbin/nologin\n\
             backdoor:x:0:0::/tmp:/bin/sh\n",
        )
        .unwrap();
        let users = login_users(passwd.to_str().unwrap());
        assert!(users.contains("root"));
        assert!(users.contains("ubuntu"));
        assert!(users.contains("backdoor"), "UID=0 的新用户必须算可登录");
        assert!(!users.contains("daemon"));
        assert!(!users.contains("svc"), "高 UID 但 nologin 不算");
    }

    #[test]
    fn suid_detection() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let suid_dir = dir.path().join("suid");
        std::fs::create_dir(&suid_dir).unwrap();
        let suid_file = suid_dir.join("payload");
        std::fs::write(&suid_file, b"#!/bin/sh").unwrap();
        let mut perms = std::fs::metadata(&suid_file).unwrap().permissions();
        perms.set_mode(0o4755);
        std::fs::set_permissions(&suid_file, perms).unwrap();
        let normal = suid_dir.join("normal");
        std::fs::write(&normal, b"x").unwrap();

        let found: Vec<PathBuf> = walk(&suid_dir, 3)
            .into_iter()
            .filter(|p| {
                std::fs::metadata(p)
                    .map(|m| m.permissions().mode() & 0o4000 != 0)
                    .unwrap_or(false)
            })
            .collect();
        assert_eq!(found, vec![suid_file.clone()], "只有 SUID 文件命中");
    }
}
