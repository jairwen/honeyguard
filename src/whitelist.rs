//! 白名单（PRD ALR-06）：命中的事件不推送，仅记录本地日志。
//!
//! 支持维度：IP/CIDR（精确解析，配置错误直接失败）、用户（全等）、
//! 进程与路径（极简 glob：仅前缀/后缀 `*`，如 `python*`、`/var/lib/*`）。

use crate::config::WhitelistCfg;
use anyhow::{Context, Result, bail};
use ipnet::IpNet;
use std::net::IpAddr;
use std::str::FromStr;

#[derive(Debug, Default)]
pub struct Whitelist {
    nets: Vec<IpNet>,
    users: Vec<String>,
    processes: Vec<String>,
    paths: Vec<String>,
}

impl Whitelist {
    pub fn from_cfg(cfg: &WhitelistCfg) -> Result<Self> {
        let mut nets = Vec::with_capacity(cfg.ips.len());
        for entry in &cfg.ips {
            let net = parse_net(entry.trim())
                .with_context(|| format!("whitelist.ips 存在无法解析的 IP/CIDR: {entry}"))?;
            nets.push(net);
        }
        if !cfg.users.is_empty() || !cfg.processes.is_empty() || !cfg.paths.is_empty() {
            tracing::info!(
                ips = nets.len(),
                users = cfg.users.len(),
                processes = cfg.processes.len(),
                paths = cfg.paths.len(),
                "已加载白名单"
            );
        }
        Ok(Self {
            nets,
            users: cfg.users.clone(),
            processes: cfg.processes.clone(),
            paths: cfg.paths.clone(),
        })
    }

    /// 校验辅助：所有条目必须可解析，用于配置加载阶段提前失败。
    pub fn validate(cfg: &WhitelistCfg) -> Result<()> {
        for entry in &cfg.ips {
            if parse_net(entry.trim()).is_none() {
                bail!("whitelist.ips 存在无法解析的 IP/CIDR: {entry}");
            }
        }
        Ok(())
    }

    pub fn allows_ip(&self, ip: IpAddr) -> bool {
        self.nets.iter().any(|n| n.contains(&ip))
    }

    pub fn allows_user(&self, user: &str) -> bool {
        self.users.iter().any(|u| u == user)
    }

    pub fn allows_process(&self, name_or_path: &str) -> bool {
        self.processes.iter().any(|p| glob_match(p, name_or_path))
    }

    pub fn allows_path(&self, path: &str) -> bool {
        self.paths.iter().any(|p| glob_match(p, path))
    }
}

/// 解析 "a.b.c.d/nn"、IPv6 CIDR，或裸 IP（视为 /32 或 /128 主机掩码）。
fn parse_net(s: &str) -> Option<IpNet> {
    if let Ok(net) = IpNet::from_str(s) {
        return Some(net);
    }
    match IpAddr::from_str(s) {
        Ok(IpAddr::V4(v4)) => ipnet::Ipv4Net::new(v4, 32).ok().map(IpNet::V4),
        Ok(IpAddr::V6(v6)) => ipnet::Ipv6Net::new(v6, 128).ok().map(IpNet::V6),
        Err(_) => None,
    }
}

/// 极简 glob：仅支持尾部 `*`（前缀匹配）或头部 `*`（后缀匹配），其余全等。
fn glob_match(pattern: &str, target: &str) -> bool {
    if let Some(prefix) = pattern.strip_suffix('*') {
        target.starts_with(prefix)
    } else if let Some(suffix) = pattern.strip_prefix('*') {
        target.ends_with(suffix)
    } else {
        pattern == target
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wl(ips: &[&str], users: &[&str], processes: &[&str]) -> Whitelist {
        Whitelist {
            nets: ips.iter().map(|s| parse_net(s).unwrap()).collect(),
            users: users.iter().map(|s| s.to_string()).collect(),
            processes: processes.iter().map(|s| s.to_string()).collect(),
            paths: vec![],
        }
    }

    #[test]
    fn ip_cidr_matching() {
        let w = wl(
            &["203.0.113.0/24", "2001:db8::/32", "198.51.100.7"],
            &[],
            &[],
        );
        let ip = |s: &str| IpAddr::from_str(s).unwrap();
        assert!(w.allows_ip(ip("203.0.113.45")));
        assert!(w.allows_ip(ip("203.0.113.255")));
        assert!(w.allows_ip(ip("2001:db8::1")));
        assert!(w.allows_ip(ip("198.51.100.7")), "裸 IP 应视为 /32");
        assert!(!w.allows_ip(ip("203.0.114.1")));
        assert!(!w.allows_ip(ip("192.0.2.1")));
    }

    #[test]
    fn user_and_process_matching() {
        let w = wl(&[], &["deploy"], &["kube-*", "python3"]);
        assert!(w.allows_user("deploy"));
        assert!(!w.allows_user("root"));
        assert!(w.allows_process("kube-proxy"));
        assert!(w.allows_process("python3"));
        assert!(!w.allows_process("python3.10"));
        assert!(!w.allows_process("xmrig"));
    }

    #[test]
    fn invalid_cidr_rejected() {
        assert!(
            Whitelist::validate(&WhitelistCfg {
                ips: vec!["not-a-cidr".to_string()],
                ..Default::default()
            })
            .is_err()
        );
    }
}
