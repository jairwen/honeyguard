//! 配置模型与加载（TOML）。字段与默认值见仓库根目录 `config.example.toml` 与 docs/PRD.md 附录 A。
//!
//! 所有结构体 `deny_unknown_fields`：配置里的拼写错误在加载时立即暴露，而不是被静默忽略。

use crate::alert::Level;
use anyhow::{Context, Result, bail};
use serde::Deserialize;
use std::env;
use std::fmt;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Config {
    pub server: ServerCfg,
    pub alert: AlertCfg,
    pub detector: DetectorCfg,
    pub whitelist: WhitelistCfg,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct ServerCfg {
    /// 展示用主机名，留空取系统主机名。
    pub host: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct AlertCfg {
    /// 最低推送级别，低于该级别的只记日志不推送。
    pub min_level: Level,
    /// 每分钟最大出站条数（critical 不受限流约束，PRD ALR-04）。
    pub rate_limit_per_min: u32,
    /// 同类事件聚合窗口（秒）。
    pub aggregate_window_sec: u64,
    /// 同类告警推送后的静默期（秒），0 = 关闭。
    pub silence_sec: u64,
    pub webhooks: Vec<WebhookCfg>,
    /// 心跳报平安（PRD ALR-08）。
    pub heartbeat: HeartbeatCfg,
    /// 每日摘要（PRD ALR-09）。
    pub digest: DigestCfg,
}

impl Default for AlertCfg {
    fn default() -> Self {
        Self {
            min_level: Level::Warning,
            rate_limit_per_min: 10,
            aggregate_window_sec: 300,
            silence_sec: 1800,
            webhooks: Vec::new(),
            heartbeat: HeartbeatCfg::default(),
            digest: DigestCfg::default(),
        }
    }
}

/// 心跳与摘要这类主动通知会绕过 `min_level` 过滤（显式开启即为想要收到）。
#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct HeartbeatCfg {
    pub enabled: bool,
    pub interval_sec: u64,
}

impl Default for HeartbeatCfg {
    fn default() -> Self {
        Self {
            enabled: false,
            interval_sec: 86400,
        }
    }
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct DigestCfg {
    pub enabled: bool,
    /// 每天几点（本地时区，0-23）发送摘要。
    pub at_hour: u8,
}

impl Default for DigestCfg {
    fn default() -> Self {
        Self {
            enabled: false,
            at_hour: 8,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebhookCfg {
    pub provider: Provider,
    pub url: String,
    /// 钉钉加签密钥（仅 dingtalk 使用）。
    #[serde(default)]
    pub secret: Option<String>,
    /// 自定义 JSON body 模板（仅 provider = "custom" 必填）。
    #[serde(default)]
    pub template: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Provider {
    Dingtalk,
    Feishu,
    Wecom,
    Slack,
    Custom,
}

impl fmt::Display for Provider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Provider::Dingtalk => "dingtalk",
            Provider::Feishu => "feishu",
            Provider::Wecom => "wecom",
            Provider::Slack => "slack",
            Provider::Custom => "custom",
        })
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct DetectorCfg {
    pub ssh_bruteforce: SshBruteforceCfg,
    pub ssh_login: SshLoginCfg,
    pub outbound: OutboundCfg,
    pub process: ProcessCfg,
    pub file_integrity: FileIntegrityCfg,
    pub listen_ports: ListenPortsCfg,
    pub behavior: BehaviorCfg,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct SshBruteforceCfg {
    pub enabled: bool,
    /// 统计时间窗口（秒）。
    pub window_sec: u64,
    /// 窗口内同一来源 IP 认证失败阈值。
    pub max_failures: u32,
}

impl Default for SshBruteforceCfg {
    fn default() -> Self {
        Self {
            enabled: true,
            window_sec: 600,
            max_failures: 20,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct SshLoginCfg {
    pub enabled: bool,
    pub mode: SshLoginMode,
}

impl Default for SshLoginCfg {
    fn default() -> Self {
        Self {
            enabled: true,
            mode: SshLoginMode::All,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SshLoginMode {
    /// 每次登录成功都通知。
    All,
    /// 仅首次出现的来源 IP 通知。
    NewIp,
    Off,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct OutboundCfg {
    pub enabled: bool,
    pub interval_sec: u64,
    /// 矿池/stratum 等可疑端口黑名单。
    pub bad_ports: Vec<u16>,
    /// 本地恶意 IP/CIDR 黑名单文件路径。
    pub blocklist_files: Vec<PathBuf>,
}

impl Default for OutboundCfg {
    fn default() -> Self {
        Self {
            enabled: true,
            interval_sec: 30,
            bad_ports: vec![3333, 4444, 5555, 7777, 8888, 14433, 14444],
            blocklist_files: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct ProcessCfg {
    pub enabled: bool,
    pub interval_sec: u64,
    /// CPU 占用率阈值（%）。
    pub cpu_threshold: u8,
    /// 持续时长阈值（秒）。
    pub duration_sec: u64,
}

impl Default for ProcessCfg {
    fn default() -> Self {
        Self {
            enabled: true,
            interval_sec: 30,
            cpu_threshold: 80,
            duration_sec: 300,
        }
    }
}

/// PRD DET-05 默认受控路径（账户/入口/持久化）。
pub const DEFAULT_FIM_WATCH: &[&str] = &[
    "/etc/passwd",
    "/etc/shadow",
    "/etc/sudoers",
    "/etc/sudoers.d/*",
    "/etc/ssh/sshd_config",
    "/root/.ssh/authorized_keys",
    "/home/*/.ssh/authorized_keys",
    "/etc/crontab",
    "/etc/cron.d/*",
    "/var/spool/cron/crontabs/*",
    "/etc/systemd/system/*",
    "/etc/init.d/*",
    "/etc/ld.so.preload",
];

pub const DEFAULT_SUID_DIRS: &[&str] = &[
    "/usr/bin",
    "/usr/sbin",
    "/usr/local/bin",
    "/usr/local/sbin",
    "/tmp",
    "/var/tmp",
    "/dev/shm",
];

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct FileIntegrityCfg {
    pub enabled: bool,
    /// 全量扫描周期（秒）。
    pub interval_sec: u64,
    /// 受控路径（glob 语法）；留空使用内置默认清单 [`DEFAULT_FIM_WATCH`]。
    pub watch: Vec<String>,
    /// 在默认清单之外追加的路径。
    pub extra_watch: Vec<String>,
    /// SUID 新增扫描目录。
    pub suid_dirs: Vec<String>,
}

impl Default for FileIntegrityCfg {
    fn default() -> Self {
        Self {
            enabled: true,
            interval_sec: 60,
            watch: DEFAULT_FIM_WATCH.iter().map(|s| s.to_string()).collect(),
            extra_watch: Vec::new(),
            suid_dirs: DEFAULT_SUID_DIRS.iter().map(|s| s.to_string()).collect(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct ListenPortsCfg {
    pub enabled: bool,
    pub interval_sec: u64,
}

impl Default for ListenPortsCfg {
    fn default() -> Self {
        Self {
            enabled: true,
            interval_sec: 60,
        }
    }
}

/// DET-09 行为基线：通过长期观测构建进程通信关系画像，发现异常通信习惯。
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct BehaviorCfg {
    pub enabled: bool,
    pub interval_sec: u64,
    /// 每个进程的学习期（秒）：期内只记录其通信对象，不告警。默认 3 天。
    pub learn_sec: u64,
    /// 远端 IP 去重数达到该阈值即判为“广泛连接型”（P2P/BT 等），
    /// 之后陌生 IP 不再告警，改为监控并发激增。
    pub p2p_ip_threshold: u32,
    /// 并发外连超过历史峰值 N 倍触发告警（广泛连接型专用）。
    pub spike_factor: u32,
    /// 触发并发激增告警的绝对下限（避免小基数误报）。
    pub spike_min: u32,
}

impl Default for BehaviorCfg {
    fn default() -> Self {
        Self {
            enabled: true,
            interval_sec: 60,
            learn_sec: 3 * 86400,
            p2p_ip_threshold: 50,
            spike_factor: 4,
            spike_min: 40,
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct WhitelistCfg {
    /// CIDR 白名单，如 "203.0.113.0/24"（M1 生效）。
    pub ips: Vec<String>,
    pub users: Vec<String>,
    pub paths: Vec<String>,
    pub processes: Vec<String>,
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("读取配置文件失败: {}", path.display()))?;
        let cfg: Config = toml::from_str(&raw)
            .with_context(|| format!("解析配置文件失败: {}", path.display()))?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn validate(&self) -> Result<()> {
        if self.alert.rate_limit_per_min == 0 {
            bail!("alert.rate_limit_per_min 不能为 0");
        }
        if self.alert.digest.at_hour >= 24 {
            bail!("alert.digest.at_hour 必须在 0-23 之间");
        }
        for wh in &self.alert.webhooks {
            if wh.url.trim().is_empty() {
                bail!("alert.webhooks 存在空 url（provider: {}）", wh.provider);
            }
            if wh.provider == Provider::Custom
                && wh
                    .template
                    .as_deref()
                    .map(str::trim)
                    .unwrap_or("")
                    .is_empty()
            {
                bail!("provider = custom 的 webhook 必须提供 template");
            }
            if wh.provider != Provider::Dingtalk && wh.secret.is_some() {
                tracing::warn!(provider = %wh.provider, "secret 仅对 provider = dingtalk 生效，已忽略");
            }
        }
        Ok(())
    }

    /// 内置示例配置（与仓库根目录 config.example.toml 保持同步，测试校验其可解析）。
    pub fn example() -> &'static str {
        include_str!("../config.example.toml")
    }
}

/// 配置文件查找顺序：$HONEYGUARD_CONFIG > /etc/honeyguard/config.toml > ./config.toml。
pub fn default_path() -> Option<PathBuf> {
    if let Ok(p) = env::var("HONEYGUARD_CONFIG") {
        return Some(PathBuf::from(p));
    }
    let etc = PathBuf::from("/etc/honeyguard/config.toml");
    if etc.is_file() {
        return Some(etc);
    }
    let local = PathBuf::from("config.toml");
    if local.is_file() {
        return Some(local);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn example_config_parses_and_validates() {
        let cfg = toml::from_str::<Config>(Config::example()).expect("示例配置应可解析");
        cfg.validate().expect("示例配置应通过校验");
        assert_eq!(cfg.detector.ssh_bruteforce.max_failures, 20);
        assert_eq!(cfg.detector.outbound.bad_ports.len(), 7);
        assert!(matches!(cfg.detector.ssh_login.mode, SshLoginMode::All));
        assert_eq!(cfg.alert.min_level, Level::Warning);
    }

    #[test]
    fn missing_sections_fall_back_to_defaults() {
        let cfg = toml::from_str::<Config>("[alert]\nwebhooks = []\n").unwrap();
        assert!(cfg.detector.ssh_bruteforce.enabled);
        assert_eq!(cfg.alert.rate_limit_per_min, 10);
        assert_eq!(cfg.alert.silence_sec, 1800);
    }

    #[test]
    fn unknown_fields_rejected() {
        let err = toml::from_str::<Config>("[aleert]\nmin_level = \"info\"\n");
        assert!(err.is_err(), "拼写错误的段应被拒绝");
        let err = toml::from_str::<Config>("[alert]\nmin_lvl = \"info\"\n");
        assert!(err.is_err(), "拼写错误的字段应被拒绝");
    }

    #[test]
    fn custom_without_template_fails_validation() {
        let cfg = toml::from_str::<Config>(
            "[[alert.webhooks]]\nprovider = \"custom\"\nurl = \"https://x.example\"\n",
        )
        .unwrap();
        assert!(cfg.validate().is_err());
    }
}
