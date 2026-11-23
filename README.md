# honeyguard

轻量级 Linux VPS 入侵威胁检测与告警 Agent（Rust）。单二进制部署，持续检测 SSH 爆破、异常登录、可疑外连、挖矿进程等入侵迹象，通过 Webhook（钉钉 / 飞书 / 企业微信 / Slack / 自定义）即时推送分级告警。

> 产品需求与路线图见 [docs/PRD.md](docs/PRD.md)。当前进度：**M1（MVP）**——四个 P0 检测器 + 告警管道 + 一键安装已就绪。

## 特性（规划与状态）

| 能力 | 状态 |
|---|---|
| 告警分级 info / warning / critical | ✅ |
| 聚合窗口 + 静默期 + 令牌桶限流（防告警轰炸，critical 不受限） | ✅ |
| Webhook 预置模板（钉钉含加签、飞书、企业微信、Slack）+ 自定义模板 | ✅ |
| 白名单（IP/CIDR、用户、进程前缀） | ✅ |
| DET-01 SSH 暴力破解检测（journald / auth.log 双日志源） | ✅ |
| 响应动作：达到爆破阈值自动封禁来源 IP（iptables/nftables 自动检测，专用链隔离；持久化 + 到期自动解封 + 内网防误封；`bans` / `ban` / `unban` 命令管理） | ✅ |
| DET-02 SSH 登录成功通知（all / new_ip 模式，已见 IP 持久化） | ✅ |
| DET-03 可疑出站连接（恶意 IP 黑名单 / 可疑长连接 + 进程归属） | ✅ |
| DET-04 挖矿/高 CPU 进程检测（/proc 差分采样 + 特征库 + 可疑路径） | ✅ |
| 检测器崩溃自愈（supervised 指数退避重启） | ✅ |
| 告警 outbox 持久化（SQLite，断网重试/重启补发，critical 不丢） | ✅ |
| DET-05 文件完整性（authorized_keys/shadow/cron/systemd 基线、新增可登录用户、新增 SUID） | ✅ |
| DET-06 新增监听端口告警（含归属进程） | ✅ |
| DET-09 行为基线：长期学习进程通信画像，陌生通信对象/新进程外连告警，P2P 类自动识别并转为并发激增监控 | ✅ |
| 心跳报平安 + 每日摘要 | ✅ |
| 启动/重启上报：每次进程启动推送一条（首次启动 / 服务重启 / 机器重启 / 异常退出后拉起，附版本变化） | ✅ |
| 自动升级（默认每 6 小时检查 Release，下载校验后替换二进制并重启服务） | ✅ |
| `baseline` 重建基线 / `doctor` 环境自检 / `update` 自更新 | ✅ |
| eBPF 实时审计（exec / connect / DNS） | M3 |

## 开发

```bash
cargo build
cargo test                                # 单元 + e2e 测试
cargo run -- --help

# 校验配置并打印策略摘要
cargo run -- once --config config.example.toml

# 测试推送（先把 config.example.toml 里的 webhook 换成你的真实地址）
cargo run -- test-alert --config config.example.toml
```

## 配置

默认路径查找顺序：`$HONEYGUARD_CONFIG` → `/etc/honeyguard/config.toml` → `./config.toml`，可用 `--config` 覆盖。完整带注释示例见 [config.example.toml](config.example.toml)，字段说明见 PRD 附录 A。

## 部署（Linux VPS）

一条命令安装（musl 静态二进制 + systemd 托管 + sha256 校验）：

```bash
curl -fsSL https://raw.githubusercontent.com/jairwen/honeyguard/main/install.sh | bash
```

安装脚本会：识别架构 → 下载并校验 → 安装 `/usr/local/bin/honeyguard` → 生成 `/etc/honeyguard/config.toml`（已存在则保留）→ 注册 systemd 服务并启动。卸载：`./install.sh --uninstall`（加 `--purge` 连配置一起删）。

装完三步走：

```bash
vim /etc/honeyguard/config.toml        # 1. 填入你的 Webhook
honeyguard test-alert                  # 2. 验证推送通道
journalctl -u honeyguard -f            # 3. 观察日志
```

**升级**：默认开启**自动升级**——服务常驻期间每 6 小时（`[server.auto_update] interval_sec`）检查一次最新 Release，有新版即下载 → sha256 校验 → 原子替换 → 自动重启服务，并推送「已自动升级」通知；不想自动升级就 `enabled = false`，改用 `sudo honeyguard update` 手动执行（步骤相同，结果打印在终端）。`honeyguard update --check` 只看有没有新版。国内节点直连 GitHub 不通时会自动回退公共加速镜像；也可显式配置 `server.update_mirror`（或环境变量 `HONEYGUARD_MIRROR`，如 `https://ghproxy.com/`），自建反代更稳更安全（sha256 校验防传输损坏，但镜像本身是信任点——自动升级同样沿用这条镜像链）。

**启动/重启上报**：honeyguard 每次启动都会推送一条通知，不受 `min_level` 影响：区分首次启动、服务重启、机器重启（boot_id 变化）与「上次运行未正常退出后被拉起」（后者为 warning），并写出版本变化（如 `版本 v0.3.3（上次运行 v0.3.2）`）和离线期间积压的告警数。正常重启始终逐条上报；崩溃循环（异常退出后被反复拉起）时 5 分钟内只推送第一条，其余只计数并并入下一条上报，不刷屏。

**自动封禁（SSH 爆破响应）**：在 `[detector.ssh_bruteforce.ban]` 里 `enabled = true` 即启用——`window_sec` 内同一 IP 认证失败达到 `max_failures` 次时，除 critical 告警外自动把该 IP 写入防火墙（默认封 1 小时，`duration_sec` 可改，0 为永久）。规则放在 `HONEYGUARD` 专用链 / `honeyguard` 专用表，不与 ufw/firewalld 等已有配置冲突；封禁记录持久化，机器重启后自动恢复未到期封禁。回环/内网地址默认拒绝封禁（`allow_private` 可放开），建议先把自己的常用 IP 加进 `whitelist.ips` 防锁门。管理命令：`honeyguard bans`（列表对账）、`honeyguard unban <IP>`（应急解封，误伤自救）、`honeyguard ban <IP>`（手动封禁）。

也可以从源码构建：`cargo build --release`（CI 会在打 `v*` tag 时自动构建双架构产物并发 Release）。

## License

MIT
