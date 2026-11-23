//! honeyguard — 轻量级 Linux VPS 入侵威胁检测与告警 Agent。
//!
//! 模块划分（对应 docs/PRD.md §4/§7）：
//! - [`alert`]：告警模型（级别、事件对象）。
//! - [`config`]：TOML 配置加载与校验。
//! - [`lifecycle`]：启动/重启上报（判定首次启动、服务重启、机器重启、异常退出）。
//! - [`logging`]：tracing 初始化（stderr，systemd 下自动进入 journald）。
//! - [`notify`]：告警出站管道（分级/聚合/静默/限流/Webhook 投递）。
//! - `collectors` / `detectors` / `store`：M1/M2 落地。
//! - [`update`]：自更新（手动 `honeyguard update` 与常驻自动升级）。

pub mod alert;
pub mod ban;
pub mod collectors;
pub mod config;
pub mod detectors;
pub mod egress;
pub mod lifecycle;
pub mod logging;
pub mod notify;
pub mod store;
pub mod update;
pub mod whitelist;
