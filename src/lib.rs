//! honeyguard — 轻量级 Linux VPS 入侵威胁检测与告警 Agent。
//!
//! 模块划分（对应 docs/PRD.md §4/§7）：
//! - [`alert`]：告警模型（级别、事件对象）。
//! - [`config`]：TOML 配置加载与校验。
//! - [`logging`]：tracing 初始化（stderr，systemd 下自动进入 journald）。
//! - [`notify`]：告警出站管道（分级/聚合/静默/限流/Webhook 投递）。
//! - `collectors` / `detectors` / `store`：M1/M2 落地。

pub mod alert;
pub mod collectors;
pub mod config;
pub mod detectors;
pub mod logging;
pub mod notify;
pub mod store;
pub mod whitelist;
