//! 生命周期上报（PRD ALR-11）：进程每次启动都推送一条通知——无论是首次启动、服务重启、
//! 机器重启，还是崩溃/被杀后被 systemd 拉起。
//!
//! 判定依据持久化在状态库 `runtime.last_run`：启动时 [`record_start`] 写入本次记录（没有
//! 停止时刻 = “运行中”），正常退出前 [`record_stop`] 补上停止时刻。下次启动若读到的记录
//! 仍无停止时刻，说明上次没能正常退出；记录里的 boot_id 与本次不同，说明机器重启过。
//!
//! 上报绕过 `min_level` 过滤（启动/重启必须让用户看到）。正常重启（上次正常停止）永远
//! 逐条上报；崩溃循环则要防刷屏——告警管道的聚合/静默状态在进程内存里，重启即失，拦不住
//! 跨进程的风暴，所以“异常退出后重启”的合并计数落在状态库：5 分钟内已推送过同类上报时，
//! 后续的只累计次数，由下一条上报一并带出。

use crate::alert::{Alert, Level};
use crate::detectors::report::human_duration;
use crate::store::Store;
use serde::{Deserialize, Serialize};
use std::time::Duration;

const DETECTOR: &str = "lifecycle";
const KEY_LAST_RUN: &str = "last_run";
/// 上次推送“异常退出后重启”上报的时刻。
const KEY_STORM_ANCHOR: &str = "lifecycle_storm_anchor_at";
/// 落在风暴窗口内、未单独推送的重启次数（并入下一条上报）。
const KEY_SUPPRESSED: &str = "lifecycle_suppressed";
/// 两次“异常退出后重启”上报的最小间隔：崩溃循环（systemd RestartSec=5）下每小时至多 12 条。
const STORM_WINDOW: Duration = Duration::from_secs(300);

/// 上一次运行留下的记录。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LastRun {
    /// 上次启动时刻（unix 秒）。
    pub started_at: i64,
    /// 正常退出时刻（unix 秒）；None = 上次运行没能正常退出。
    pub stopped_at: Option<i64>,
    pub version: String,
    /// 上次运行时的机器 boot_id。
    pub boot_id: Option<String>,
}

/// 本次启动时掌握的历史。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum History {
    /// 状态数据库不可用或记录损坏，无从判断。
    Unavailable,
    /// 没有历史记录：首次安装，或状态库被清空。
    First,
    Previous(LastRun),
}

/// 启动原因。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    FirstStart,
    /// 上次正常停止后再次启动（systemctl restart / 手动重启 / 升级后重启）。
    Restart,
    /// 机器重启后启动（boot_id 变化）。
    Reboot,
    /// 上次运行没能正常退出（崩溃、被杀、OOM），由服务管理器拉起。
    UnexpectedExit,
    /// 无从判断。
    Unknown,
}

/// 本次启动的判定结果与上报决定。
#[derive(Debug, Clone)]
pub struct Startup {
    pub history: History,
    pub reason: Reason,
    /// 需要推送的上报；None = 落在重启风暴窗口内，本次只计数、不单独推送。
    pub alert: Option<Alert>,
}

/// 本次开机的 boot_id（`/proc/sys/kernel/random/boot_id`；读不到为 None）。
pub fn boot_id() -> Option<String> {
    std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// 根据历史与本次 boot_id 判定启动原因。
fn classify(history: &History, boot_id: Option<&str>) -> Reason {
    match history {
        History::Unavailable => Reason::Unknown,
        History::First => Reason::FirstStart,
        History::Previous(p) => {
            if let (Some(previous), Some(current)) = (p.boot_id.as_deref(), boot_id)
                && previous != current
            {
                Reason::Reboot
            } else if p.stopped_at.is_some() {
                Reason::Restart
            } else {
                Reason::UnexpectedExit
            }
        }
    }
}

/// 上次运行是否没能正常退出（升级为 warning 的依据）。
fn abnormal_exit(history: &History) -> bool {
    matches!(history, History::Previous(p) if p.stopped_at.is_none())
}

fn read_last_run(store: &Store) -> History {
    match store.runtime_get(KEY_LAST_RUN) {
        Ok(None) => History::First,
        Ok(Some(json)) => serde_json::from_str::<LastRun>(&json)
            .map(History::Previous)
            .unwrap_or_else(|err| {
                tracing::warn!(error = %err, "上次运行记录损坏，无法判断启动原因");
                History::Unavailable
            }),
        Err(err) => {
            tracing::warn!(error = %err, "读取上次运行记录失败");
            History::Unavailable
        }
    }
}

fn read_number(store: Option<&Store>, key: &str) -> Option<i64> {
    store?.runtime_get(key).ok().flatten()?.parse().ok()
}

fn write(store: Option<&Store>, key: &str, value: &str) {
    let Some(store) = store else {
        return;
    };
    if let Err(err) = store.runtime_set(key, value) {
        tracing::warn!(error = %err, key, "写入运行状态失败");
    }
}

fn save(store: &Store, run: &LastRun) {
    match serde_json::to_string(run) {
        Ok(json) => write(Some(store), KEY_LAST_RUN, &json),
        Err(err) => tracing::warn!(error = %err, "序列化运行记录失败"),
    }
}

/// 记录本次启动（覆盖为“运行中”），并给出启动原因与要推送的上报。
pub fn record_start(store: Option<&Store>, boot_id: Option<&str>, now: i64) -> Startup {
    let Some(store) = store else {
        return decide(None, History::Unavailable, boot_id, now);
    };
    let history = read_last_run(store);
    save(
        store,
        &LastRun {
            started_at: now,
            stopped_at: None,
            version: env!("CARGO_PKG_VERSION").to_string(),
            boot_id: boot_id.map(str::to_string),
        },
    );
    decide(Some(store), history, boot_id, now)
}

/// 判定启动原因，并决定本次是否推送（重启风暴合并）。
fn decide(store: Option<&Store>, history: History, boot_id: Option<&str>, now: i64) -> Startup {
    let reason = classify(&history, boot_id);
    let mut suppressed = read_number(store, KEY_SUPPRESSED)
        .unwrap_or(0)
        .clamp(0, u32::MAX as i64) as u32;
    let storm = reason == Reason::UnexpectedExit
        && read_number(store, KEY_STORM_ANCHOR)
            .is_some_and(|anchor| now.saturating_sub(anchor) < STORM_WINDOW.as_secs() as i64);
    if storm {
        suppressed += 1;
        write(store, KEY_SUPPRESSED, &suppressed.to_string());
        tracing::warn!(
            suppressed,
            "5 分钟内再次异常退出后重启：并入下一条启动上报，不单独推送"
        );
        return Startup {
            history,
            reason,
            alert: None,
        };
    }
    let pending = store
        .and_then(|s| s.outbox_pending_count().ok())
        .unwrap_or(0);
    let alert = startup_alert(&history, boot_id, pending, now, suppressed);
    write(store, KEY_SUPPRESSED, "0");
    if reason == Reason::UnexpectedExit {
        write(store, KEY_STORM_ANCHOR, &now.to_string());
    }
    Startup {
        history,
        reason,
        alert: Some(alert),
    }
}

/// 正常退出前调用：补上停止时刻，下次启动据此识别为“服务重启”而非异常退出。
pub fn record_stop(store: Option<&Store>, now: i64) {
    let Some(store) = store else {
        return;
    };
    if let History::Previous(mut run) = read_last_run(store) {
        run.stopped_at = Some(now);
        save(store, &run);
    }
}

/// 构造启动上报。
fn startup_alert(
    history: &History,
    boot_id: Option<&str>,
    pending_outbox: i64,
    now: i64,
    suppressed: u32,
) -> Alert {
    let reason = classify(history, boot_id);
    let abnormal = abnormal_exit(history);
    let current = env!("CARGO_PKG_VERSION");

    let mut lines = vec![match history {
        History::Previous(p) if p.version != current => {
            format!("版本 v{current}（上次运行 v{}）", p.version)
        }
        _ => format!("版本 v{current}"),
    }];
    lines.push(format!("启动原因：{}", describe(history, reason, now)));
    if pending_outbox > 0 {
        lines.push(format!("离线期间积压告警 {pending_outbox} 条，正在补发"));
    }
    if suppressed > 0 {
        lines.push(format!(
            "另有 {suppressed} 次重启落在重启风暴窗口内，未单独上报"
        ));
    }
    if abnormal {
        lines.push("若非人为操作，请检查: journalctl -u honeyguard -n 100".to_string());
    }

    Alert::new(
        if abnormal {
            Level::Warning
        } else {
            Level::Info
        },
        DETECTOR,
        if abnormal {
            "honeyguard 已重启（上次运行未正常退出）"
        } else {
            "honeyguard 已启动"
        },
        lines.join("\n"),
    )
    .with_key("startup")
    .always_send()
}

/// “启动原因”一行的说明文字。
fn describe(history: &History, reason: Reason, now: i64) -> String {
    let History::Previous(p) = history else {
        return match reason {
            Reason::FirstStart => "首次启动（无历史运行记录）".to_string(),
            _ => "状态数据库不可用，无法判断启动原因".to_string(),
        };
    };
    match (reason, p.stopped_at) {
        (Reason::Restart, Some(stopped)) => format!(
            "服务重启（上次运行 v{}，{}前正常停止）",
            p.version,
            ago(now, stopped)
        ),
        (Reason::Reboot, Some(stopped)) => format!(
            "机器重启后启动（上次运行 v{}，{}前正常停止）",
            p.version,
            ago(now, stopped)
        ),
        (Reason::Reboot, None) => format!(
            "机器重启后启动，且上次运行未正常退出（v{}，{}前启动），可能是断电或系统崩溃",
            p.version,
            ago(now, p.started_at)
        ),
        (_, None) => format!(
            "上次运行未正常退出（v{}，{}前启动；疑似崩溃、被杀或内存不足），已被重新拉起",
            p.version,
            ago(now, p.started_at)
        ),
        // classify 不会对同一份历史给出与 stopped_at 矛盾的原因
        _ => "服务重启".to_string(),
    }
}

/// 距 `ts` 的时长描述，如 `3 分钟`。
fn ago(now: i64, ts: i64) -> String {
    human_duration(Duration::from_secs(now.saturating_sub(ts).max(0) as u64))
}

#[cfg(test)]
mod tests {
    use super::*;

    const BOOT: &str = "boot-a";

    fn run(started_at: i64, stopped_at: Option<i64>, boot_id: &str) -> LastRun {
        LastRun {
            started_at,
            stopped_at,
            version: "0.1.0".to_string(),
            boot_id: Some(boot_id.to_string()),
        }
    }

    fn mem() -> Store {
        Store::open(std::path::Path::new(":memory:")).unwrap()
    }

    #[test]
    fn classify_distinguishes_start_types() {
        assert_eq!(classify(&History::First, Some(BOOT)), Reason::FirstStart);
        assert_eq!(classify(&History::Unavailable, Some(BOOT)), Reason::Unknown);
        assert_eq!(
            classify(&History::Previous(run(100, Some(200), BOOT)), Some(BOOT)),
            Reason::Restart
        );
        // 上次没有正常退出
        assert_eq!(
            classify(&History::Previous(run(100, None, BOOT)), Some(BOOT)),
            Reason::UnexpectedExit
        );
        // boot_id 变化优先于退出方式
        assert_eq!(
            classify(
                &History::Previous(run(100, Some(200), BOOT)),
                Some("boot-b")
            ),
            Reason::Reboot
        );
        assert_eq!(
            classify(&History::Previous(run(100, None, BOOT)), Some("boot-b")),
            Reason::Reboot
        );
        // 任一侧读不到 boot_id（容器 / 非 Linux）就只看退出方式
        assert_eq!(
            classify(&History::Previous(run(100, None, BOOT)), None),
            Reason::UnexpectedExit
        );
        let no_boot = LastRun {
            boot_id: None,
            ..run(100, Some(200), BOOT)
        };
        assert_eq!(
            classify(&History::Previous(no_boot), Some("boot-b")),
            Reason::Restart
        );
    }

    #[test]
    fn abnormal_exit_escalates_to_warning() {
        let alert = startup_alert(
            &History::Previous(run(1000, None, BOOT)),
            Some(BOOT),
            0,
            1012,
            0,
        );
        assert_eq!(alert.level, Level::Warning);
        assert!(alert.always_send, "启动/重启上报不受 min_level 过滤");
        assert!(alert.title.contains("未正常退出"), "{}", alert.title);
        assert_eq!(alert.detector, DETECTOR);
        assert_eq!(alert.aggregate_key(), "lifecycle:startup");
        assert!(
            alert.body.contains("启动原因：上次运行未正常退出"),
            "{}",
            alert.body
        );
        assert!(alert.body.contains("12 秒前启动"), "{}", alert.body);
        assert!(
            alert.body.contains("journalctl"),
            "异常退出应给出排查入口：{}",
            alert.body
        );
    }

    #[test]
    fn normal_start_is_info_and_reports_version_change() {
        let alert = startup_alert(&History::First, Some(BOOT), 0, 5000, 0);
        assert_eq!(alert.level, Level::Info);
        assert!(alert.always_send);
        assert_eq!(alert.title, "honeyguard 已启动");
        assert!(
            alert
                .body
                .contains(&format!("版本 v{}", env!("CARGO_PKG_VERSION"))),
            "{}",
            alert.body
        );
        assert!(alert.body.contains("首次启动"), "{}", alert.body);
        assert!(!alert.body.contains("积压告警"), "{}", alert.body);

        // 版本变化（升级后重启）与积压告警都要显式写出
        let upgraded = History::Previous(run(1000, Some(4000), BOOT));
        let alert = startup_alert(&upgraded, Some(BOOT), 2, 5000, 0);
        assert_eq!(alert.level, Level::Info);
        assert_eq!(alert.title, "honeyguard 已启动");
        assert!(
            alert.body.contains(&format!(
                "版本 v{}（上次运行 v0.1.0）",
                env!("CARGO_PKG_VERSION")
            )),
            "{}",
            alert.body
        );
        assert!(
            alert
                .body
                .contains("服务重启（上次运行 v0.1.0，16 分钟前正常停止）"),
            "{}",
            alert.body
        );
        assert!(alert.body.contains("积压告警 2 条"), "{}", alert.body);
    }

    #[test]
    fn reboot_is_reported_regardless_of_how_last_run_ended() {
        let clean = startup_alert(
            &History::Previous(run(1000, Some(2000), BOOT)),
            Some("boot-b"),
            0,
            3000,
            0,
        );
        assert_eq!(clean.level, Level::Info);
        assert!(clean.body.contains("机器重启后启动"), "{}", clean.body);

        let crashed = startup_alert(
            &History::Previous(run(1000, None, BOOT)),
            Some("boot-b"),
            0,
            3000,
            0,
        );
        assert_eq!(crashed.level, Level::Warning);
        assert!(
            crashed
                .body
                .contains("机器重启后启动，且上次运行未正常退出"),
            "{}",
            crashed.body
        );
    }

    /// 模拟一次“启动 → 崩溃”（没有 record_stop）。
    fn crash(store: &Store, now: i64) -> Startup {
        record_start(Some(store), Some(BOOT), now)
    }

    #[test]
    fn crash_loop_is_merged_across_restarts() {
        let store = mem();
        assert!(
            record_start(Some(&store), Some(BOOT), 100).alert.is_some(),
            "首次启动上报"
        );

        // 首次异常退出后拉起：立即上报（warning），不受之前上报影响
        let first = crash(&store, 110);
        assert_eq!(first.reason, Reason::UnexpectedExit);
        let alert = first.alert.expect("首次异常退出必须立即上报");
        assert_eq!(alert.level, Level::Warning);
        assert!(!alert.body.contains("未单独上报"), "{}", alert.body);

        // 紧接着的崩溃循环：每个进程的聚合状态都是空的，必须靠状态库拦住——5 分钟内只计数
        for i in 0..5 {
            let again = crash(&store, 120 + i * 5);
            assert_eq!(again.reason, Reason::UnexpectedExit);
            assert!(
                again.alert.is_none(),
                "风暴窗口内的重启不应单独上报（第 {} 次）",
                i + 1
            );
        }

        // 窗口过后仍在循环：恢复上报，并把此前合并的次数带出来
        let after = crash(&store, 110 + 301);
        let alert = after.alert.expect("窗口过后应恢复上报");
        assert_eq!(alert.level, Level::Warning);
        assert!(alert.body.contains("另有 5 次重启"), "{}", alert.body);
        assert_eq!(
            store.runtime_get(KEY_SUPPRESSED).unwrap().as_deref(),
            Some("0"),
            "带出后计数清零"
        );

        // 机器重启不是崩溃循环：即使在风暴窗口内也照常上报
        let reboot = record_start(Some(&store), Some("boot-b"), 420);
        assert_eq!(reboot.reason, Reason::Reboot);
        assert!(reboot.alert.is_some());
    }

    #[test]
    fn clean_restarts_are_never_merged() {
        let store = mem();
        record_start(Some(&store), Some(BOOT), 100);
        for i in 0..3 {
            record_stop(Some(&store), 105 + i * 10);
            let restart = record_start(Some(&store), Some(BOOT), 110 + i * 10);
            assert_eq!(
                restart.reason,
                Reason::Restart,
                "正常停止后再启动 = 服务重启"
            );
            assert!(
                restart.alert.is_some(),
                "正常重启间隔再近也要逐条上报（第 {} 次）",
                i + 1
            );
        }
    }

    #[test]
    fn crash_right_after_manual_restart_is_reported() {
        let store = mem();
        record_start(Some(&store), Some(BOOT), 100);
        record_stop(Some(&store), 150);
        let manual = record_start(Some(&store), Some(BOOT), 160);
        assert_eq!(manual.reason, Reason::Restart);

        // 手动重启后 10 秒就崩了：没有更早的异常上报可合并，必须立即上报
        let crash = crash(&store, 170);
        assert_eq!(crash.reason, Reason::UnexpectedExit);
        assert!(crash.alert.is_some(), "{:?}", crash.reason);
        assert!(!crash.alert.unwrap().body.contains("未单独上报"));
    }

    #[test]
    fn records_persist_across_restart() {
        assert_eq!(
            record_start(None, Some(BOOT), 1).history,
            History::Unavailable,
            "无状态库无从判断"
        );
        let store = mem();
        assert_eq!(
            record_start(Some(&store), Some(BOOT), 100).history,
            History::First,
            "首次启动没有历史"
        );

        // 正常退出 → 下次启动识别为服务重启
        record_stop(Some(&store), 200);
        let current = || env!("CARGO_PKG_VERSION").to_string();
        assert_eq!(
            record_start(Some(&store), Some(BOOT), 300).history,
            History::Previous(LastRun {
                started_at: 100,
                stopped_at: Some(200),
                version: current(),
                boot_id: Some(BOOT.to_string()),
            })
        );

        // 没走正常退出（崩溃/被杀）→ 下次启动看到的是“运行中”的旧记录
        let history = record_start(Some(&store), Some("boot-b"), 400).history;
        assert_eq!(
            history,
            History::Previous(LastRun {
                started_at: 300,
                stopped_at: None,
                version: current(),
                boot_id: Some(BOOT.to_string()),
            })
        );
        assert_eq!(classify(&history, Some("boot-b")), Reason::Reboot);

        // 记录损坏时不 panic，按无从判断处理
        store.runtime_set(KEY_LAST_RUN, "not json").unwrap();
        let broken = record_start(Some(&store), Some(BOOT), 500);
        assert_eq!(broken.reason, Reason::Unknown);
        assert!(
            broken.alert.is_some(),
            "判断不了原因也要上报本次启动：{:?}",
            broken.alert.map(|a| a.body)
        );
    }
}
