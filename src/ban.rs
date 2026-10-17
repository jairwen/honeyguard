//! 自动封禁（响应层）：检测器判定攻击行为后，把来源 IP 写入防火墙封禁。
//!
//! 后端自动检测：优先 iptables（含 iptables-nft），不可用时回退 nftables。
//! 规则全部放在专用链/表里，不污染用户已有防火墙配置：
//! - iptables：`iptables -I INPUT 1 -j HONEYGUARD`，链内逐 IP DROP（v4/v6 同构）
//! - nftables：inet 表 honeyguard，input 钩子（priority -10）查 banned4/banned6 集合
//!
//! 封禁记录持久化在状态库（bans 表），服务/机器重启后恢复未到期封禁，到期自动解封。
//! 安全约束：白名单在检测层已过滤；回环/链路本地/组播/广播地址永不封禁；
//! 内网/ULA 地址默认拒绝封禁（防误封网关/跳板机把自己锁在外面），可配置放开。

use anyhow::{Context, Result, bail};
use std::future::Future;
use std::net::IpAddr;
use std::pin::Pin;
use std::process::Stdio;
use std::str::FromStr;
use std::time::Duration;

/// 防火墙后端抽象：生产实现为 iptables/nftables，测试注入 mock。
pub trait Firewall: Send + Sync {
    fn name(&self) -> &'static str;
    /// 初始化链/表（幂等）；[`detect`] 已隐式调用。
    fn ensure(&self) -> Pin<Box<dyn Future<Output = Result<()>> + Send + '_>>;
    /// 封禁；返回 Ok(false) 表示规则已存在（幂等）。
    fn ban(&self, ip: IpAddr) -> Pin<Box<dyn Future<Output = Result<bool>> + Send + '_>>;
    /// 解封；返回 Ok(false) 表示本就没有该规则（幂等）。
    fn unban(&self, ip: IpAddr) -> Pin<Box<dyn Future<Output = Result<bool>> + Send + '_>>;
    /// 当前封禁的 IP 列表（对账与 CLI 展示）。
    fn list(&self) -> Pin<Box<dyn Future<Output = Result<Vec<IpAddr>>> + Send + '_>>;
}

/// 探测可用后端：iptables → nft，初始化验证通过才算可用。
pub async fn detect() -> Result<Box<dyn Firewall>> {
    match IptablesBackend::detect_backend().await {
        Ok(ipt) => Ok(Box::new(ipt)),
        Err(e1) => {
            tracing::debug!(error = %e1, "iptables 后端不可用，尝试 nftables");
            let nft = NftBackend;
            match nft.ensure().await {
                Ok(()) => Ok(Box::new(nft)),
                Err(e2) => bail!(
                    "无可用防火墙后端：iptables（{e1:#}）；nftables（{e2:#}）。需要 root 权限且安装两者之一"
                ),
            }
        }
    }
}

/// 封禁该地址是否被安全规则拒绝；Some(原因) 表示拒绝封禁。
pub fn ban_refusal(ip: IpAddr, allow_private: bool) -> Option<&'static str> {
    match ip {
        IpAddr::V4(v4) => {
            if v4.is_loopback() {
                Some("回环地址")
            } else if v4.is_unspecified() {
                Some("未指定地址")
            } else if v4.is_link_local() {
                Some("链路本地地址")
            } else if v4.is_broadcast() {
                Some("广播地址")
            } else if v4.is_multicast() {
                Some("组播地址")
            } else if v4.is_private() && !allow_private {
                Some("内网地址（如确需封禁内网来源，设置 allow_private = true）")
            } else {
                None
            }
        }
        IpAddr::V6(v6) => {
            if v6.is_loopback() {
                Some("回环地址")
            } else if v6.is_unspecified() {
                Some("未指定地址")
            } else if v6.is_unicast_link_local() {
                Some("链路本地地址")
            } else if v6.is_multicast() {
                Some("组播地址")
            } else if v6.is_unique_local() && !allow_private {
                Some("内网地址（如确需封禁内网来源，设置 allow_private = true）")
            } else {
                None
            }
        }
    }
}

// ---- 命令执行辅助 ----

struct CmdOutput {
    code: Option<i32>,
    stdout: String,
    stderr: String,
}

impl CmdOutput {
    fn failed(&self) -> bool {
        !matches!(self.code, Some(0))
    }

    /// 非零退出转为 Err（附 stderr 摘要）。
    fn ok(self, ctx: &str) -> Result<()> {
        if self.failed() {
            bail!("{ctx} 失败：{}", first_line(&self.stderr));
        }
        Ok(())
    }
}

fn first_line(s: &str) -> String {
    s.lines()
        .rev()
        .find(|l| !l.trim().is_empty())
        .unwrap_or("(无输出)")
        .trim()
        .to_string()
}

async fn run(bin: &str, args: &[&str], stdin: Option<&str>) -> Result<CmdOutput> {
    let mut cmd = tokio::process::Command::new(bin);
    cmd.args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    cmd.stdin(if stdin.is_some() {
        Stdio::piped()
    } else {
        Stdio::null()
    });
    let out = tokio::time::timeout(Duration::from_secs(10), async {
        let mut child = cmd
            .spawn()
            .with_context(|| format!("执行 {bin} 失败（未安装或不在 PATH）"))?;
        if let Some(script) = stdin
            && let Some(mut si) = child.stdin.take()
        {
            use tokio::io::AsyncWriteExt;
            let _ = si.write_all(script.as_bytes()).await; // 写失败由命令退出码体现
        }
        let out = child
            .wait_with_output()
            .await
            .with_context(|| bin.to_string())?;
        Ok::<CmdOutput, anyhow::Error>(CmdOutput {
            code: out.status.code(),
            stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        })
    })
    .await
    .with_context(|| format!("{bin} 执行超时（10s）"))??;
    Ok(out)
}

// ---- iptables 后端 ----

const IPT_CHAIN: &str = "HONEYGUARD";

/// iptables / ip6tables 专用链实现。`v6` 标记 ip6tables 是否可用（构造时探测）。
#[derive(Debug, Clone, Copy)]
struct IptablesBackend {
    v6: bool,
}

impl IptablesBackend {
    /// 探测并初始化：v4 必须可用（否则视为后端不可用），v6 尽力而为。
    async fn detect_backend() -> Result<Self> {
        iptables_ensure_family(false).await?;
        let v6 = match iptables_ensure_family(true).await {
            Ok(()) => true,
            Err(e) => {
                tracing::warn!(error = %e, "ip6tables 不可用，IPv6 地址将无法封禁");
                false
            }
        };
        Ok(Self { v6 })
    }
}

fn family_bin(v6: bool) -> &'static str {
    if v6 { "ip6tables" } else { "iptables" }
}

async fn iptables_ensure_family(v6: bool) -> Result<()> {
    let bin = family_bin(v6);
    // 专用链不存在则创建（-nL 查询失败 = 不存在）
    if run(bin, &["-w", "2", "-nL", IPT_CHAIN], None)
        .await?
        .failed()
    {
        run(bin, &["-w", "2", "-N", IPT_CHAIN], None)
            .await?
            .ok(&format!("{bin} -N {IPT_CHAIN}"))?;
    }
    // INPUT 顶部跳转到专用链，保证封禁规则优先于用户已有规则
    if run(bin, &["-w", "2", "-C", "INPUT", "-j", IPT_CHAIN], None)
        .await?
        .failed()
    {
        run(bin, &["-w", "2", "-I", "INPUT", "1", "-j", IPT_CHAIN], None)
            .await?
            .ok(&format!("{bin} -I INPUT 1 -j {IPT_CHAIN}"))?;
    }
    Ok(())
}

impl Firewall for IptablesBackend {
    fn name(&self) -> &'static str {
        "iptables"
    }

    fn ensure(&self) -> Pin<Box<dyn Future<Output = Result<()>> + Send + '_>> {
        Box::pin(async move {
            iptables_ensure_family(false).await?;
            if self.v6 {
                iptables_ensure_family(true).await?;
            }
            Ok(())
        })
    }

    fn ban(&self, ip: IpAddr) -> Pin<Box<dyn Future<Output = Result<bool>> + Send + '_>> {
        Box::pin(async move {
            let v6 = ip.is_ipv6();
            if v6 && !self.v6 {
                bail!("ip6tables 不可用，无法封禁 IPv6 地址 {ip}");
            }
            let bin = family_bin(v6);
            let addr = ip.to_string();
            let ctx = format!("{bin} -I {IPT_CHAIN} -s {addr} -j DROP");
            // -C 检查避免重复插入（服务重启恢复时会对已封 IP 重放）
            if !run(
                bin,
                &["-w", "2", "-C", IPT_CHAIN, "-s", &addr, "-j", "DROP"],
                None,
            )
            .await?
            .failed()
            {
                return Ok(false);
            }
            run(
                bin,
                &["-w", "2", "-I", IPT_CHAIN, "1", "-s", &addr, "-j", "DROP"],
                None,
            )
            .await?
            .ok(&ctx)?;
            Ok(true)
        })
    }

    fn unban(&self, ip: IpAddr) -> Pin<Box<dyn Future<Output = Result<bool>> + Send + '_>> {
        Box::pin(async move {
            let v6 = ip.is_ipv6();
            if v6 && !self.v6 {
                bail!("ip6tables 不可用，无法解封 IPv6 地址 {ip}");
            }
            let bin = family_bin(v6);
            let addr = ip.to_string();
            let out = run(
                bin,
                &["-w", "2", "-D", IPT_CHAIN, "-s", &addr, "-j", "DROP"],
                None,
            )
            .await?;
            if !out.failed() {
                return Ok(true);
            }
            // 规则本就不存在视为幂等成功
            if out.stderr.contains("Bad rule") {
                return Ok(false);
            }
            bail!(
                "{bin} -D {IPT_CHAIN} -s {addr} -j DROP 失败：{}",
                first_line(&out.stderr)
            );
        })
    }

    fn list(&self) -> Pin<Box<dyn Future<Output = Result<Vec<IpAddr>>> + Send + '_>> {
        Box::pin(async move {
            let mut ips = Vec::new();
            let v4 = run("iptables", &["-w", "2", "-S", IPT_CHAIN], None).await?;
            if !v4.failed() {
                ips.extend(parse_iptables_rules(&v4.stdout, false));
            }
            if self.v6 {
                let v6 = run("ip6tables", &["-w", "2", "-S", IPT_CHAIN], None).await?;
                if !v6.failed() {
                    ips.extend(parse_iptables_rules(&v6.stdout, true));
                }
            }
            Ok(ips)
        })
    }
}

/// 解析 `iptables -S HONEYGUARD` 输出中的 DROP 规则来源地址。
/// 行形如 `-A HONEYGUARD -s 203.0.113.7/32 -j DROP`；非主机掩码的手动规则跳过。
fn parse_iptables_rules(text: &str, v6: bool) -> Vec<IpAddr> {
    text.lines()
        .filter_map(|line| {
            let mut it = line.split_whitespace();
            if it.next()? != "-A" || it.next()? != IPT_CHAIN || it.next()? != "-s" {
                return None;
            }
            let source = it.next()?;
            if it.next()? != "-j" || it.next()? != "DROP" || it.next().is_some() {
                return None;
            }
            // 只收主机规则：无掩码，或 v4 /32、v6 /128；其他掩码的手动 CIDR 规则跳过
            let (host, mask) = match source.split_once('/') {
                None => (source, None),
                Some((h, m)) => (h, Some(m)),
            };
            let host_mask = if v6 { "128" } else { "32" };
            if mask.is_some_and(|m| m != host_mask) {
                return None;
            }
            IpAddr::from_str(host).ok().filter(|ip| ip.is_ipv6() == v6)
        })
        .collect()
}

// ---- nftables 后端 ----

const NFT_TABLE: &str = "honeyguard";

const NFT_CREATE_SCRIPT: &str = "\
add table inet honeyguard
add chain inet honeyguard input { type filter hook input priority -10; policy accept; }
add set inet honeyguard banned4 { type ipv4_addr; }
add set inet honeyguard banned6 { type ipv6_addr; }
add rule inet honeyguard input ip saddr @banned4 drop
add rule inet honeyguard input ip6 saddr @banned6 drop
";

/// nftables inet 表实现；所有变更经 `nft -f -` 从 stdin 送入，避免 argv 引号问题。
#[derive(Debug, Clone, Copy)]
struct NftBackend;

impl Firewall for NftBackend {
    fn name(&self) -> &'static str {
        "nftables"
    }

    fn ensure(&self) -> Pin<Box<dyn Future<Output = Result<()>> + Send + '_>> {
        Box::pin(async move {
            let listing = run("nft", &["list", "table", "inet", NFT_TABLE], None).await?;
            if listing.failed() {
                // 表不存在：整体创建
                return run("nft", &["-f", "-"], Some(NFT_CREATE_SCRIPT))
                    .await?
                    .ok("nft 建表 honeyguard");
            }
            // 表已存在：补齐缺失的 set/chain/rule（用户可能清过部分对象）
            let text = &listing.stdout;
            let mut script = String::new();
            if !text.contains("set banned4") {
                script.push_str("add set inet honeyguard banned4 { type ipv4_addr; }\n");
            }
            if !text.contains("set banned6") {
                script.push_str("add set inet honeyguard banned6 { type ipv6_addr; }\n");
            }
            if !text.contains("chain input") {
                script.push_str(
                    "add chain inet honeyguard input { type filter hook input priority -10; policy accept; }\n",
                );
            }
            if !text.contains("@banned4 drop") {
                script.push_str("add rule inet honeyguard input ip saddr @banned4 drop\n");
            }
            if !text.contains("@banned6 drop") {
                script.push_str("add rule inet honeyguard input ip6 saddr @banned6 drop\n");
            }
            if script.is_empty() {
                return Ok(());
            }
            run("nft", &["-f", "-"], Some(&script))
                .await?
                .ok("nft 补齐 honeyguard 表对象")
        })
    }

    fn ban(&self, ip: IpAddr) -> Pin<Box<dyn Future<Output = Result<bool>> + Send + '_>> {
        Box::pin(async move {
            let set = if ip.is_ipv6() { "banned6" } else { "banned4" };
            let script = format!("add element inet {NFT_TABLE} {set} {{ {ip} }}\n");
            let out = run("nft", &["-f", "-"], Some(&script)).await?;
            if !out.failed() {
                return Ok(true);
            }
            // 元素已存在视为幂等成功
            if out.stderr.contains("exists") {
                return Ok(false);
            }
            bail!(
                "nft add element {set} {ip} 失败：{}",
                first_line(&out.stderr)
            );
        })
    }

    fn unban(&self, ip: IpAddr) -> Pin<Box<dyn Future<Output = Result<bool>> + Send + '_>> {
        Box::pin(async move {
            let set = if ip.is_ipv6() { "banned6" } else { "banned4" };
            let script = format!("delete element inet {NFT_TABLE} {set} {{ {ip} }}\n");
            let out = run("nft", &["-f", "-"], Some(&script)).await?;
            if !out.failed() {
                return Ok(true);
            }
            // 元素本就不存在视为幂等成功
            if out.stderr.contains("No such file") {
                return Ok(false);
            }
            bail!(
                "nft delete element {set} {ip} 失败：{}",
                first_line(&out.stderr)
            );
        })
    }

    fn list(&self) -> Pin<Box<dyn Future<Output = Result<Vec<IpAddr>>> + Send + '_>> {
        Box::pin(async move {
            let mut ips = Vec::new();
            for set in ["banned4", "banned6"] {
                let out = run("nft", &["list", "set", "inet", NFT_TABLE, set], None).await?;
                if out.failed() {
                    continue; // set 尚未创建 = 空
                }
                ips.extend(parse_nft_elements(&out.stdout));
            }
            Ok(ips)
        })
    }
}

/// 解析 `nft list set ...` 输出的 elements 行（大集合会折行，取 `elements = {` 到匹配 `}` 全段）。
fn parse_nft_elements(text: &str) -> Vec<IpAddr> {
    let Some(start) = text.find("elements = {") else {
        return Vec::new();
    };
    let rest = &text[start + "elements = {".len()..];
    let Some(end) = rest.find('}') else {
        return Vec::new();
    };
    rest[..end]
        .split(',')
        .filter_map(|tok| IpAddr::from_str(tok.trim()).ok())
        .collect()
}

// ---- 测试 ----

/// 检测器测试用的防火墙 mock。
#[cfg(test)]
pub(crate) mod testutil {
    use super::*;
    use std::collections::HashSet;
    use std::sync::Mutex;

    #[derive(Default)]
    pub struct MockFirewall {
        pub banned: Mutex<HashSet<IpAddr>>,
        /// 置 true 后 ban/unban 返回错误。
        pub fail: bool,
    }

    impl Firewall for MockFirewall {
        fn name(&self) -> &'static str {
            "mock"
        }

        fn ensure(&self) -> Pin<Box<dyn Future<Output = Result<()>> + Send + '_>> {
            Box::pin(async { Ok(()) })
        }

        fn ban(&self, ip: IpAddr) -> Pin<Box<dyn Future<Output = Result<bool>> + Send + '_>> {
            Box::pin(async move {
                if self.fail {
                    bail!("mock ban 失败");
                }
                Ok(self.banned.lock().unwrap().insert(ip))
            })
        }

        fn unban(&self, ip: IpAddr) -> Pin<Box<dyn Future<Output = Result<bool>> + Send + '_>> {
            Box::pin(async move {
                if self.fail {
                    bail!("mock unban 失败");
                }
                Ok(self.banned.lock().unwrap().remove(&ip))
            })
        }

        fn list(&self) -> Pin<Box<dyn Future<Output = Result<Vec<IpAddr>>> + Send + '_>> {
            Box::pin(async move { Ok(self.banned.lock().unwrap().iter().copied().collect()) })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        IpAddr::from_str(s).unwrap()
    }

    #[test]
    fn refusal_blocks_special_and_private_addresses() {
        for addr in [
            "127.0.0.1",
            "0.0.0.0",
            "169.254.1.1",
            "224.0.0.1",
            "255.255.255.255",
        ] {
            assert!(ban_refusal(ip(addr), false).is_some(), "{addr} 应拒绝");
            assert!(
                ban_refusal(ip(addr), true).is_some(),
                "{addr} 任何配置都应拒绝"
            );
        }
        for addr in ["::1", "::", "fe80::1", "ff02::1"] {
            assert!(ban_refusal(ip(addr), false).is_some(), "{addr} 应拒绝");
        }
        // 公网地址始终可封
        assert!(ban_refusal(ip("203.0.113.7"), false).is_none());
        assert!(ban_refusal(ip("2001:db8::1"), false).is_none());
        // 内网默认拒绝、显式放开后允许
        assert!(ban_refusal(ip("192.168.1.5"), false).is_some());
        assert!(ban_refusal(ip("10.0.0.8"), false).is_some());
        assert!(ban_refusal(ip("172.16.0.9"), false).is_some());
        assert!(ban_refusal(ip("fd00::1"), false).is_some());
        assert!(ban_refusal(ip("192.168.1.5"), true).is_none());
        assert!(ban_refusal(ip("fd00::1"), true).is_none());
    }

    #[test]
    fn parses_iptables_save_rules() {
        let text = "\
-A HONEYGUARD -s 203.0.113.7/32 -j DROP
-A HONEYGUARD -s 198.51.100.2/32 -j DROP
-A HONEYGUARD -s 0.0.0.0/0 -j ACCEPT
-A HONEYGUARD -s 203.0.113.0/24 -j DROP
-P INPUT ACCEPT
";
        let got = parse_iptables_rules(text, false);
        assert_eq!(got, vec![ip("203.0.113.7"), ip("198.51.100.2")]);

        let v6 = "-A HONEYGUARD -s 2001:db8::1/128 -j DROP\n";
        assert_eq!(parse_iptables_rules(v6, true), vec![ip("2001:db8::1")]);
        assert!(
            parse_iptables_rules(v6, false).is_empty(),
            "v4 输出不应收 v6 地址"
        );
    }

    #[test]
    fn parses_nft_elements_with_wrapping() {
        let single = "set banned4 {\n    type ipv4_addr\n    elements = { 203.0.113.7 }\n}\n";
        assert_eq!(parse_nft_elements(single), vec![ip("203.0.113.7")]);

        let wrapped = "set banned4 {\n    type ipv4_addr\n    elements = { 1.2.3.4, 5.6.7.8,\n        9.10.11.12 }\n}\n";
        assert_eq!(parse_nft_elements(wrapped).len(), 3);

        let empty = "set banned4 {\n    type ipv4_addr\n}\n";
        assert!(parse_nft_elements(empty).is_empty());
    }
}
