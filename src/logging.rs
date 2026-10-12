//! 日志初始化：输出到 stderr（systemd 下由 unit 的 StandardError=journal 接管进入 journald）。

use anyhow::Result;
use tracing_subscriber::EnvFilter;

/// 初始化全局 tracing。
///
/// verbosity：0 = info（默认），1 = debug，>=2 = trace；环境变量 RUST_LOG 可覆盖。
/// 必须在任何 `tracing` 事件产生前调用（main 入口处）。
pub fn init(verbosity: u8) -> Result<()> {
    let default = match verbosity {
        0 => "info",
        1 => "debug",
        _ => "trace",
    };
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .with_target(false)
        .init();
    Ok(())
}
