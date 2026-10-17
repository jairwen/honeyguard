# PRD：honeyguard — 轻量级 Linux VPS 入侵威胁检测与告警 Agent

| 项 | 内容 |
|---|---|
| 版本 | v0.1（草案） |
| 日期 | 2026-10-12 |
| 状态 | 待评审 |
| 形态 | 纯单机 Agent（无服务端），Rust 实现 |
| 定位 | 个人自用 + 开源发布 |

---

## 1. 背景与问题

公网 VPS 每天都会遭遇 SSH 暴力破解、扫描、挖矿木马植入、后门留置等攻击。个人开发者通常只有 1~N 台低配 VPS（1 核 1G 居多），现有方案对其都不友好：

- **fail2ban**：只覆盖 SSH 爆破一类场景，规则基于正则 + Python 实现，配置繁琐，且不做告警推送。
- **Wazuh / OSSEC**：功能全面但需要 Agent + Server 架构，资源占用高，个人 VPS 跑不起也没必要。
- **云厂商告警**：绑定单一厂商，不跨平台，且以资源指标为主，缺少入侵语义。

**结论**：需要一个单二进制、低资源占用、5 分钟部署完成、开箱即用的单机入侵检测 Agent，检测到威胁后通过 Webhook 即时推送到手机/群聊。

## 2. 产品定位

> 一句话：部署在 Linux VPS 上的 Rust 单机安全 Agent，持续检测入侵迹象（爆破、异常登录、可疑外连、挖矿、留后门），通过通用 Webhook 即时推送分级告警。

### 2.1 目标用户

- 个人开发者 / 独立运维，持有 1~N 台公网 VPS，系统以 Ubuntu 20.04/22.04/24.04 为主。
- 有基本 Linux 操作能力，能看懂 TOML 配置，希望"装完就忘、出事才响"。

### 2.2 典型场景

1. 半夜有人对 22 端口爆破 → 手机收到 critical 告警（含来源 IP、尝试次数）。
2. 服务器被植入挖矿程序，对外连接矿池 → 收到可疑外连 + 高 CPU 进程告警。
3. 攻击者爆破成功后写入 `authorized_keys` / 新建用户 / 添加 systemd timer 持久化 → 收到文件变更与持久化痕迹告警。
4. 任意一次 SSH 登录成功 → 收到登录通知（IP、用户、方式），异地登录立刻察觉。

## 3. 目标与非目标

### 3.1 目标

- **G1** 一条命令完成安装，5 分钟内从零到收到第一条测试告警。
- **G2** 覆盖 VPS 上最常见的入侵场景（见 §5.1，MVP 覆盖爆破/登录/外连/挖矿四类）。
- **G3** 告警即时送达（Webhook），带分级、聚合、防轰炸，重启不丢待发告警。
- **G4** 常驻资源占用：内存 < 50MB，CPU 平均 < 1%（1C1G 可用）。
- **G5** 零依赖单二进制（musl 静态链接），x86_64 + aarch64。

### 3.2 非目标（明确不做）

- 不做文件实时查杀 / 病毒库（不是杀毒软件）。
- 不做流量深度包检测（DPI）。
- **MVP 不做主动阻断**（封 IP、断连接）——误封导致失联的风险高，阻断作为远期可选项。
- 不做云端面板、多机集中管理、账号体系（如后续有需求另立 PRD）。
- 不支持 Windows / macOS 作为被保护主机。

## 4. 总体架构（概要）

```
┌─────────────────────────────── honeyguard (root) ───────────────────────────────┐
│                                                                                  │
│  采集层 Collectors                检测层 Detectors              告警层 Notifier    │
│  ┌──────────────────┐   event  ┌──────────────────┐   alert  ┌────────────────┐ │
│  │ journald/auth.log│ ───────▶ │ SSH 爆破/登录检测 │ ───────▶ │ 分级 info/     │ │
│  │ (SSH 事件流)      │          ├──────────────────┤          │ warn/critical  │ │
│  ├──────────────────┤          │ 可疑外连检测      │          ├────────────────┤ │
│  │ /proc/net/tcp(6) │ ───────▶ ├──────────────────┤          │ 聚合 + 限流     │ │
│  │ /proc/[pid]/*    │          │ 可疑进程/挖矿检测 │          ├────────────────┤ │
│  ├──────────────────┤          ├──────────────────┤          │ 白名单过滤     │ │
│  │ 关键文件基线扫描  │ ───────▶ │ 文件完整性/持久化 │          ├────────────────┤ │ │
│  └──────────────────┘          └──────────────────┘          │ Webhook 出站   │ │
│                                                                │ 重试+持久化队列 │ │
│                                                                └────────────────┘ │
│  状态：SQLite（基线哈希 / 聚合计数 / 待发告警 outbox）                              │
└──────────────────────────────────────────────────────────────────────────────────┘
```

三条流水线解耦：采集器只产出统一的 `Event`，检测器消费 `Event`（或自行轮询）产出 `Alert`，Notifier 负责分级、白名单、聚合、限流、投递。每个检测器是独立的 tokio task，单个检测器崩溃不影响整体（进程级由 systemd `Restart=always` 兜底）。

## 5. 功能需求

优先级定义：**P0** = MVP 必须；**P1** = 第二迭代（v0.2）；**P2** = 远期。

### 5.1 检测能力

| ID | 检测项 | 数据源 | 优先级 |
|---|---|---|---|
| DET-01 | SSH 暴力破解检测 | journald / auth.log | P0 |
| DET-02 | SSH 登录成功通知 | journald / auth.log | P0 |
| DET-03 | 可疑出站连接（矿池端口 / 恶意 IP / 可疑长连接） | /proc/net/tcp{,6} | P0 |
| DET-04 | 可疑进程（持续高 CPU + 挖矿/伪装特征） | /proc/[pid]/* | P0 |
| DET-05 | 关键文件完整性与持久化痕迹 | 文件基线扫描 + notify | P1 |
| DET-06 | 新增监听端口 | /proc/net/tcp{,6}（LISTEN） | P1 |
| DET-07 | eBPF 实时审计（exec / connect / DNS） | aya (eBPF) | P2 |
| DET-08 | 入站端口扫描检测 | eBPF / conntrack | P2 |
| DET-09 | 行为基线（进程通信画像：长期学习通信关系，异常通信/P2P 识别） | /proc/net + /proc/[pid] | P1 |

**DET-09 行为基线 / 进程通信画像（P1）**
- 通过长期观测构建两层画像（SQLite 持久化）：进程画像（exe 为身份：首次出现时间、历史并发外连峰值、是否广泛连接型）与通信关系（exe, 远端 IP 粒度）。
- 首次运行为**普查**：存量进程与通信关系静默入档，不产生告警风暴。
- 每个进程有**学习期**（默认 3 天，可配）：期内只记录不告警；学习期满后连接未见过的远端 IP → `warning`（告警一次后关系转正，不重复打扰）。
- **新进程**首次出现在出站连接中 → `warning`（新落地的程序在对外通信，进入学习期观测）。
- **广泛连接型识别**（P2P/BT/种子类）：远端 IP 去重数达到阈值（默认 50，可配）即自动标记——这类进程连海量陌生节点是其本性，陌生 IP 不再告警，改为监控**并发激增**（当前并发 ≥ 历史峰值 N 倍且 ≥ 绝对下限，默认 4 倍/40 条）→ `warning`（识别被滥用做扫描/DDoS）。峰值带迟滞回落，长期静默后不会误报。
- `honeyguard baseline` 清空行为画像重新学习。
- 已知局限（后续优化）：进程身份以 exe 路径为准，脚本/解释器类程序（python 跑不同脚本）共享同一身份。

**DET-01 SSH 暴力破解检测（P0）**
- 数据源自适应：优先 systemd journal（`journalctl -f -o json _COMM=sshd`），无 journald 环境回退 `/var/log/auth.log` tail；两者统一抽象为一个 `LogSource`。
- 触发规则（可配置）：时间窗口 `window`（默认 10 分钟）内，同一来源 IP 认证失败次数 ≥ `max_failures`（默认 20 次）→ `critical` 告警。
- 聚合：窗口内同一 IP 只发一条，告警内容含累计失败次数、尝试的用户名 Top5、窗口起止。
- 覆盖 `Failed password` / `Invalid user` / `Connection closed by authenticating user` / `max startups` 等常见模式。

**DET-02 SSH 登录成功通知（P0）**
- 任意 `Accepted password/publickey` 事件 → `info` 告警，内容含用户、来源 IP、端口、认证方式、时间。
- 模式可配置：`all`（每次登录都通知，默认）/ `new_ip`（仅首次出现的 IP）/ `off`。IP 首次记录持久化在 SQLite。

**DET-03 可疑出站连接检测（P0）**
- 每 `interval`（默认 30s）解析 `/proc/net/tcp`、`/proc/net/tcp6`（含 UDP）。
- 规则：
  - 目的端口命中内置矿池/可疑端口列表（3333、4444、5555、7777、8888、14444、14433 等，列表外置可配置）→ `critical`。
  - 目的 IP 命中恶意 IP 集合（P0 支持本地配置文件导入，P2 支持在线 feed 如 firehol/abuse.ch）→ `critical`。
  - 非 80/443 的非常用端口上的长连接（ESTABLISHED，持续 ≥ N 个周期）→ `warning`。与 DET-09 行为基线联动去噪：连接可归属且归属进程已被行为画像跟踪（含学习期与广泛连接型）时不触发，由 DET-09 负责其通信异常判定；无法归属进程的连接仍适用本规则。
- 告警内容含本地进程归属（通过 `/proc/[pid]/fd` 的 socket inode 反查，MVP 若反查开销大可只报 IP:port，进程归属允许降级到 P1）。

**DET-04 可疑进程检测（P0）**
- 每 `interval`（默认 30s）对 `/proc/[pid]/stat` 做差分，得到各进程 CPU 占用率。
- 触发规则：
  - 进程 CPU 持续 ≥ `cpu_threshold`（默认 80%）超过 `duration`（默认 5 分钟），且命中挖矿特征库（进程名/路径/命令行正则，如 `kdevtmpfsi`、`kinsing`、`xmrig`、`stratum+tcp`、`--donate-level` 等，特征库外置）→ `critical`。
  - 同样资源条件下不命中特征库 → `info`（仅记录，默认不推送，可开关）。
- 告警内容含 PID、进程名、完整命令行、工作目录、父进程链（向上追溯至 PID 1）。

**DET-05 关键文件完整性与持久化痕迹（P1）**
- 基线机制：首次运行（或 `baseline update` 命令）对受控文件列表计算 SHA-256 存入 SQLite 作为基线；之后 inotify（`notify` crate）实时监听 + 每 10 分钟全量扫描兜底。
- 受控对象（默认集，可增删）：
  - 账户与提权：`/etc/passwd`、`/etc/shadow`、`/etc/sudoers`、`/etc/sudoers.d/*`
  - 入口：`/root/.ssh/authorized_keys`、`/home/*/.ssh/authorized_keys`、`/etc/ssh/sshd_config`
  - 持久化：`/etc/cron*`、`/var/spool/cron/crontabs/*`、`/etc/systemd/system/*`、`/etc/init.d/*`、`/etc/ld.so.preload`
- 触发规则：
  - 上述文件内容变更/新增/删除 → `critical`（`authorized_keys`、`shadow`、`ld.so.preload`）/ `warning`（其余）。
  - 新增 UID ≥ 1000 的可登录用户，或任何 UID=0 的新用户 → `critical`。
  - 全盘（可配置目录范围）新增 SUID 文件 → `warning`。
- 告警内容含变更类型（新增/修改/删除）、旧哈希新哈希（可只报前 8 位）、diff 摘要（行级，敏感文件默认脱敏）。

**DET-06 新增监听端口（P1）**
- 周期扫描 LISTEN socket，与 SQLite 基线对比；新增监听端口 → `warning`（后门/反弹 shell 常见前置动作）。首次运行建基线不告警。

**DET-07 eBPF 实时审计（P2）**
- 基于 aya：`execve` 事件、`connect` 事件、DNS 查询捕获。
- 启动时探测内核（BTF 可用性、版本 ≥ 5.4，建议 ≥ 5.8）；不支持则自动降级回 /proc 轮询方案并记录日志，**绝不因 eBPF 不可用而启动失败**。

**DET-08 入站端口扫描检测（P2）**
- 依赖 eBPF 或 conntrack：短窗口内同一源 IP 触及 ≥ N 个未开放端口 → `warning`。

### 5.2 告警系统

| ID | 需求 | 优先级 |
|---|---|---|
| ALR-01 | 通用 Webhook 通道（自定义 URL/头部/JSON 模板） | P0 |
| ALR-02 | 预置模板：钉钉、飞书、企业微信、Slack | P0 |
| ALR-03 | 告警分级 info / warning / critical | P0 |
| ALR-04 | 聚合与限流（防轰炸） | P0 |
| ALR-05 | 投递重试 + 持久化队列（重启不丢） | P0 |
| ALR-06 | 白名单（IP / 用户 / 文件路径 / 进程） | P0 |
| ALR-07 | `test-alert` 手动测试推送 | P0 |
| ALR-08 | 心跳报平安（可开关） | P1 |
| ALR-09 | 每日摘要 | P1 |
| ALR-10 | 多 Webhook 目标并发投递 | P1 |

**ALR-01/02 Webhook 通道**
- `POST` 用户配置的 URL，Content-Type: application/json。
- 预置模板覆盖钉钉（markdown + 加签）、飞书（card）、企业微信（markdown）、Slack（text）；并提供 `custom` 模板：用户直接写含 `{{title}}`、`{{level}}`、`{{body}}`、`{{host}}`、`{{time}}`、`{{event_id}}` 变量的 JSON body 字符串（简单字符串替换，不引入模板引擎依赖）。
- 超时 10s；非 2xx 视为失败进入重试。

**ALR-03 分级**
- `critical`：爆破命中、成功登录（new_ip 模式下）、矿池外连、挖矿进程、authorized_keys/shadow 变更、新增 root 用户。
- `warning`：可疑长连接、新增监听端口、一般文件变更、新增 SUID。
- `info`：登录通知（all 模式）、高 CPU 无特征进程。
- 用户可为每类事件覆写级别，并设最低推送级别（如只推 warning 以上）。

**ALR-04 聚合与限流**
- 聚合：按 `检测器 + 关键主体（如来源 IP / 文件路径 / PID）` 为 key，窗口内（默认 5 分钟）合并为一条，内容含累计计数。
- 限流：令牌桶，默认每分钟最多 10 条出站；超限部分记入日志与每日摘要，**critical 级别不受限流约束**（但仍受聚合约束）。
- 静默期：同一 key 告警后默认静默 30 分钟（可配，0 关闭）。

**ALR-05 送达保证**
- 待发告警先写入 SQLite outbox 再投递；成功（2xx）后标记删除。
- 失败重试：指数退避（1s/2s/4s…上限 5 分钟），连续失败 10 次后进入冷却，恢复后补发积压；积压超过 100 条时丢弃 info/warning，只补发 critical（防止恢复瞬间被打爆）。

**ALR-06 白名单**
- 维度：来源/目的 IP（支持 CIDR）、SSH 用户、文件路径（glob）、进程名/路径（glob）。
- 命中白名单的事件不产生告警，但仍在本地事件日志中记录。

**ALR-08 心跳（P1）**
- 可开关，默认关。开启后每 24h 推送一条 `info`：Agent 存活、运行时长、过去 24h 事件计数。用于反向发现"Agent 被杀死/机器失联"。

**ALR-09 每日摘要（P1）**
- 每日固定时间（默认 08:00 本机时区）推送前 24h 各类事件统计与 Top 来源 IP。

### 5.3 配置与 CLI

| ID | 需求 | 优先级 |
|---|---|---|
| CFG-01 | `/etc/honeyguard/config.toml`，默认配置全量注释、开箱即用 | P0 |
| CFG-02 | 配置热重载（SIGHUP + 文件监听，二选一即可） | P1 |
| CFG-03 | CLI 子命令（见下） | P0 |

CLI 设计（clap）：

```
honeyguard run           # 前台运行（调试用；生产由 systemd 以 honeyguard.service 拉起）
honeyguard once          # 跑一轮全量检测立即退出（调试/验证用）
honeyguard test-alert    # 向已配置的 Webhook 发送三级测试告警
honeyguard baseline update [--force]   # 重建文件/端口基线（P1）
honeyguard doctor        # 环境自检：日志源、权限、网络、Webhook 连通性（P1）
honeyguard update [--check]  # 自更新到最新 Release；--check 只检查不更新（P1）
honeyguard status        # 通过 Unix socket 查询运行状态与统计（P1）
honeyguard version
```

- 运行日志输出到 journald（`journalctl -u honeyguard -f` 可查），级别可配，默认 info。
- 自身日志中 **绝不打印 Webhook URL 与密钥**。

### 5.4 安装与部署

| ID | 需求 | 优先级 |
|---|---|---|
| DEP-01 | musl 静态单二进制：x86_64 + aarch64，GitHub Releases 分发 | P0 |
| DEP-02 | `install.sh` 一键安装：`curl -fsSL ... | bash` | P0 |
| DEP-03 | 升级路径：`honeyguard update` 自更新（查最新 Release → 下载 → sha256 校验 → 原子替换 → 重启服务）；`--check` 只检查；或重跑 install.sh | P1 |
| DEP-04 | 干净卸载：`install.sh --uninstall`（停服务、删二进制/配置可选保留） | P0 |

- install.sh 职责：识别架构 → 下载对应二进制（校验 sha256）→ 安装到 `/usr/local/bin/honeyguard` → 生成带注释的默认配置（不覆盖已存在配置）→ 安装 systemd unit（`Restart=always`，`After=network-online.target`）→ `systemctl enable --now honeyguard` → 提示 `test-alert` 验证。
- 命名约定：二进制 `honeyguard`，systemd 服务 `honeyguard.service`，配置目录 `/etc/honeyguard/`，状态数据库 `/var/lib/honeyguard/state.db`。
- 运行要求：root（需读 shadow、auth.log、/proc 全量）。
- 兼容性矩阵（承诺支持）：Ubuntu 20.04 / 22.04 / 24.04（主要），Debian 11 / 12。其他发行版"尽力而为"不作承诺。

## 6. 非功能需求

| ID | 需求 |
|---|---|
| NF-01 性能 | 常驻 RSS < 50MB；CPU 平均 < 1%（1C1G 场景可长期运行）；单轮 /proc 全量扫描 < 100ms |
| NF-02 可靠性 | 检测器 panic 被捕获并重启该 task；进程异常退出由 systemd 自动拉起；状态持久化使其重启后不重复告警、不丢待发告警 |
| NF-03 安全 | 配置文件权限 0600；不外传任何数据（除用户配置的 Webhook 地址）；提供告警内容脱敏开关（隐藏 IP 末段/用户名） |
| NF-04 可维护性 | 检测规则（端口黑名单、挖矿特征、文件清单、白名单）与代码分离，均可在配置/规则文件中增删 |
| NF-05 可观测 | 结构化日志（tracing → journald），关键路径有耗时可观测点 |
| NF-06 构建 | GitHub Actions CI：test + 多目标交叉编译 + release 产物自动打包（二进制 + sha256 + install.sh） |

## 7. 技术选型（概要，详细设计另出 TDD）

| 领域 | 选择 | 理由 |
|---|---|---|
| 运行时 | tokio | 异步多 task 架构的天然选择 |
| 配置 | serde + toml | Rust 生态标准 |
| HTTP 客户端 | reqwest（rustls） | 纯 Rust TLS，静态编译友好 |
| 存储 | rusqlite（SQLite，bundled） | 零外部依赖的状态持久化 |
| 文件监听 | notify | inotify 封装 |
| 日志源 | 优先 `journalctl -f -o json` 子进程；回退 auth.log 文件 tail | 子进程方式最简单可靠，免 libsystemd 链接问题 |
| CLI / 日志 | clap / tracing + tracing-journald | 标准组合 |
| eBPF（P2） | aya | 纯 Rust eBPF，无 libbpf 依赖 |
| 错误处理 | anyhow（应用）+ thiserror（库错误） | 标准实践 |

工程结构：单 crate 即可（`src/collectors/`、`src/detectors/`、`src/notifier/`、`src/store/`、`src/config/`），检测器以 trait `Detector` 插件化注册，后续加检测项不改主干。

## 8. 里程碑

按顺序推进，不设死线，以质量门（CI 全绿 + 验收用例通过）为发布条件。

| 里程碑 | 内容 | 产出 |
|---|---|---|
| M0 骨架 | 工程搭建、配置加载、日志、Webhook 通道 + test-alert、CI | 可安装可推送的空壳 Agent |
| M1 MVP | DET-01~04、ALR-01~07、DEP-01/02/04、NF 全线 | **v0.1 发布**（GitHub Release + README 快速开始） |
| M2 加固 | DET-05/06、ALR-08~10、CFG-02、DEP-03、doctor/status | v0.2 发布 |
| M3 实时 | DET-07/08、恶意 IP feed 在线更新、（评估）主动阻断 | v0.3 发布 |

## 9. 成功指标（验收）

- 1C1G Ubuntu 22.04：从执行 install.sh 到手机收到三级测试告警 ≤ 5 分钟。
- hydra 模拟 SSH 爆破 10 分钟：≤ 3 分钟内收到 critical 告警；持续 1 小时爆破，出站告警 ≤ 5 条（聚合生效）。
- 手动写入 `authorized_keys`：1 分钟内收到 critical（M2 起验收）。
- Webhook 目标断网 1 小时后恢复：积压 critical 告警全部补发，无丢失。
- 连续运行 30 天：无重启、无 panic，RSS < 50MB，CPU 平均 < 1%。
- 误报：正常使用（apt 升级、用户自己 ssh 登录、跑编译任务）不产生 critical 告警。

## 10. 风险与开放问题

### 10.1 风险与缓解

| 风险 | 缓解 |
|---|---|
| journald / auth.log 双日志源格式差异大 | 统一 `LogSource` 抽象 + 事件归一化层；CI 中用真实日志样本做解析回归 |
| /proc 扫描的进程归属反查（inode → pid）开销 | MVP 允许降级只报 IP:port；P1 做 inode 映射缓存 + 增量维护 |
| 各 Webhook 平台格式随时间漂移 | 模板外置在配置中可自定义，预置模板仅是默认值 |
| 误报轰炸导致用户关闭推送 | 分级 + 聚合 + 白名单三道闸；默认只推 warning 以上 |
| eBPF 内核兼容性（P2） | 启动探测 + 自动降级，绝不因此启动失败 |
| Agent 本身被攻击者杀死 | systemd 拉起 + 心跳报平安（P1）；systemd unit 防篡改（P2 评估 immutable/attrs） |

### 10.2 开放问题（待决策）

1. **主动阻断**：是否在 M3 提供“检测到爆破自动 iptables 封禁”可选能力（对齐 fail2ban）？风险与收益需再评估。
2. **Alpine/musl 无 journald**：是否承诺支持（需纯 syslog 文件方案）？
3. **恶意 IP feed 源选择**：firehol（IPs by abuse）与 abuse.ch 的授权、更新频率、失败回退策略。

## 附录 A：config.toml 默认配置示例

```toml
# /etc/honeyguard/config.toml
[server]
host = ""            # 留空自动取 hostname
egress_ip = true     # 告警主机名追加出口公网 IP：NODEA(1.2.3.4)

[alert]
min_level = "warning"        # 只推送该级别以上：info | warning | critical
rate_limit_per_min = 10      # 每分钟最大出站条数（critical 不受限）
aggregate_window_sec = 300   # 同类事件聚合窗口
silence_sec = 1800           # 同 key 告警后静默期，0 = 关闭

[[alert.webhooks]]
provider = "dingtalk"        # dingtalk | feishu | wecom | slack | custom
url = "https://oapi.dingtalk.com/robot/send?access_token=xxx"
secret = ""                  # 钉钉加签用，可空
# provider = "custom" 时的自定义模板：
# template = '{"text": "[{{level}}] {{title}} {{body}}"}'

[detector.ssh_bruteforce]
enabled = true
window_sec = 600
max_failures = 20            # 窗口内同 IP 失败阈值；开启 ban 后同阈值触发封禁

[detector.ssh_bruteforce.ban]
enabled = false              # 达到阈值自动封禁来源 IP（iptables/nftables）
duration_sec = 3600          # 封禁时长，到期自动解封；0 = 永久
allow_private = false        # 内网地址默认拒绝封禁（防误封网关/跳板机）

[detector.ssh_login]
mode = "all"                 # all | new_ip | off

[detector.outbound]
interval_sec = 30
bad_ports = [3333, 4444, 5555, 7777, 8888, 14444, 14433]
blocklist_files = []         # 本地恶意 IP 文件路径（每行一个 CIDR）

[detector.process]
interval_sec = 30
cpu_threshold = 80           # %
duration_sec = 300

# 完整可运行的最新示例以仓库根目录 config.example.toml 为准
#（另含 file_integrity / listen_ports / behavior / heartbeat / digest 段）

[whitelist]
ips = []                     # CIDR，如 ["203.0.113.0/24"]
users = []
paths = []                   # glob，如 ["/var/lib/*/tmp/*"]
processes = []
```

## 附录 B：告警字段（custom 模板可用变量）

```json
{
  "event_id": "a1b2c3d4",
  "level": "critical",
  "title": "SSH 暴力破解",
  "body": "来源 203.0.113.7 在 10 分钟内失败 142 次，尝试用户: root, admin, test",
  "host": "vps-01",
  "time": "2026-10-12T03:14:15+08:00",
  "detector": "ssh_bruteforce"
}
```

## 附录 C：告警分级对照

| 级别 | 事件 |
|---|---|
| critical | 爆破命中、可疑外连（矿池/恶意 IP）、挖矿进程、authorized_keys/shadow/sudoers 变更、新增 root 用户、new_ip 模式下的陌生登录 |
| warning | 可疑长连接、新增监听端口、一般受控文件变更、新增 SUID、端口扫描（P2） |
| info | 登录通知（all 模式）、高 CPU 无特征进程、心跳、每日摘要 |
