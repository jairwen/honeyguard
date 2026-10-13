//! 状态持久化（PRD ALR-05 / DET-02）：SQLite（rusqlite bundled），默认 `/var/lib/honeyguard/state.db`。
//!
//! 用途：
//! - **outbox**：待发告警队列（每个 alert × webhook 目标一行，存已渲染的 url/body）。
//!   入队即持久，投递成功删除，失败按指数退避重试；进程重启后自动补发积压。
//! - **seen_login_ips**：`new_ip` 模式已见登录 IP，重启后不重复对同一 IP 告警。
//!
//! 告警量级为每分钟个位数，同步 SQLite（Mutex 包裹）在异步上下文中的代价可忽略。

use crate::alert::Level;
use anyhow::{Context, Result};
use rusqlite::{Connection, params};
use std::net::IpAddr;
use std::path::Path;
use std::sync::Mutex;

pub const DEFAULT_DB_PATH: &str = "/var/lib/honeyguard/state.db";

/// 非告警类积压条数上限：超过后丢弃 info/warning 只保留 critical（PRD ALR-05）。
const BACKLOG_KEEP: i64 = 100;

#[derive(Debug, Clone)]
pub struct OutboxRow {
    pub id: i64,
    pub url: String,
    pub body: String,
    pub level: String,
    pub attempts: i32,
    pub next_try_at: i64,
}

pub struct Store {
    conn: Mutex<Connection>,
}

impl Store {
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(dir) = path.parent()
            && !dir.as_os_str().is_empty()
        {
            std::fs::create_dir_all(dir)
                .with_context(|| format!("创建状态目录失败: {}", dir.display()))?;
        }
        let conn = Connection::open(path)
            .with_context(|| format!("打开状态数据库失败: {}", path.display()))?;
        Self::init(conn)
    }

    pub fn open_default() -> Result<Self> {
        Self::open(Path::new(DEFAULT_DB_PATH))
    }

    fn init(conn: Connection) -> Result<Self> {
        let _ = conn.pragma_update(None, "journal_mode", "WAL"); // :memory: 不支持，忽略
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS outbox (
                 id          INTEGER PRIMARY KEY AUTOINCREMENT,
                 url         TEXT NOT NULL,
                 body        TEXT NOT NULL,
                 level       TEXT NOT NULL,
                 attempts    INTEGER NOT NULL DEFAULT 0,
                 next_try_at INTEGER NOT NULL DEFAULT 0,
                 created_at  INTEGER NOT NULL
             );
             CREATE INDEX IF NOT EXISTS idx_outbox_next ON outbox(next_try_at);
             CREATE TABLE IF NOT EXISTS seen_login_ips (
                 ip           TEXT PRIMARY KEY,
                 first_seen_at INTEGER NOT NULL
             );
             CREATE TABLE IF NOT EXISTS fim_baseline (
                 path   TEXT PRIMARY KEY,
                 sha256 TEXT NOT NULL,
                 kind   TEXT NOT NULL            -- file | user | suid
             );
             CREATE TABLE IF NOT EXISTS listen_baseline (
                 addr TEXT NOT NULL,
                 port INTEGER NOT NULL,
                 PRIMARY KEY (addr, port)
             );
             CREATE TABLE IF NOT EXISTS alert_log (
                 id      INTEGER PRIMARY KEY AUTOINCREMENT,
                 ts      INTEGER NOT NULL,
                 level   TEXT NOT NULL,
                 detector TEXT NOT NULL,
                 title   TEXT NOT NULL,
                 agg_key TEXT NOT NULL
             );
             CREATE INDEX IF NOT EXISTS idx_alert_log_ts ON alert_log(ts);
             CREATE TABLE IF NOT EXISTS behavior_procs (
                 exe            TEXT PRIMARY KEY,
                 comm           TEXT NOT NULL,
                 first_seen     INTEGER NOT NULL,
                 last_seen      INTEGER NOT NULL,
                 p2p_like       INTEGER NOT NULL DEFAULT 0,
                 max_concurrent INTEGER NOT NULL DEFAULT 0
             );
             CREATE TABLE IF NOT EXISTS behavior_pairs (
                 exe        TEXT NOT NULL,
                 ip         TEXT NOT NULL,
                 first_seen INTEGER NOT NULL,
                 last_seen  INTEGER NOT NULL,
                 hits       INTEGER NOT NULL DEFAULT 1,
                 last_port  INTEGER NOT NULL DEFAULT 0,
                 PRIMARY KEY (exe, ip)
             );
             CREATE INDEX IF NOT EXISTS idx_behavior_pairs_exe ON behavior_pairs(exe);",
        )
        .context("初始化状态数据库表失败")?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Connection> {
        self.conn.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// 告警入队（next_try_at = 0 立即可投递）。返回行 id。
    pub fn outbox_push(&self, url: &str, body: &str, level: Level, now: i64) -> Result<i64> {
        let conn = self.lock();
        conn.execute(
            "INSERT INTO outbox(url, body, level, next_try_at, created_at) VALUES (?1, ?2, ?3, 0, ?4)",
            params![url, body, level.to_string(), now],
        )
        .context("outbox 写入失败")?;
        Ok(conn.last_insert_rowid())
    }

    /// 取出到期（next_try_at <= now）的待发行，按 id 升序。
    pub fn outbox_due(&self, now: i64, limit: i64) -> Result<Vec<OutboxRow>> {
        let conn = self.lock();
        let mut stmt = conn
            .prepare("SELECT id, url, body, level, attempts, next_try_at FROM outbox WHERE next_try_at <= ?1 ORDER BY id LIMIT ?2")
            .context("outbox 查询失败")?;
        let rows = stmt
            .query_map(params![now, limit], |row| {
                Ok(OutboxRow {
                    id: row.get(0)?,
                    url: row.get(1)?,
                    body: row.get(2)?,
                    level: row.get(3)?,
                    attempts: row.get(4)?,
                    next_try_at: row.get(5)?,
                })
            })
            .context("outbox 查询失败")?
            .collect::<std::result::Result<Vec<_>, _>>()
            .context("outbox 读取失败")?;
        Ok(rows)
    }

    pub fn outbox_delete(&self, id: i64) -> Result<()> {
        self.lock()
            .execute("DELETE FROM outbox WHERE id = ?1", params![id])
            .map(|_| ())
            .context("outbox 删除失败")
    }

    /// 投递失败：累计尝试次数并排期下次重试。
    pub fn outbox_schedule_retry(&self, id: i64, attempts: i32, next_try_at: i64) -> Result<()> {
        self.lock()
            .execute(
                "UPDATE outbox SET attempts = ?2, next_try_at = ?3 WHERE id = ?1",
                params![id, attempts, next_try_at],
            )
            .map(|_| ())
            .context("outbox 更新失败")
    }

    pub fn outbox_pending_count(&self) -> Result<i64> {
        let conn = self.lock();
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM outbox", [], |row| row.get(0))
            .context("outbox 计数失败")?;
        Ok(count)
    }

    /// 积压控制：非 critical 条目只保留最新 BACKLOG_KEEP 条，critical 不丢。返回删除数。
    pub fn trim_backlog(&self) -> Result<usize> {
        let conn = self.lock();
        let deleted = conn
            .execute(
                "DELETE FROM outbox WHERE level != 'critical' AND id NOT IN (
                     SELECT id FROM outbox WHERE level != 'critical' ORDER BY id DESC LIMIT ?1
                 )",
                params![BACKLOG_KEEP],
            )
            .context("outbox 积压清理失败")?;
        Ok(deleted)
    }

    /// 记录登录 IP；返回 true 表示首次出现（此前未见）。
    pub fn login_ip_first_seen(&self, ip: &IpAddr, now: i64) -> Result<bool> {
        let conn = self.lock();
        let inserted = conn
            .execute(
                "INSERT OR IGNORE INTO seen_login_ips(ip, first_seen_at) VALUES (?1, ?2)",
                params![ip.to_string(), now],
            )
            .context("登录 IP 记录失败")?;
        Ok(inserted == 1)
    }

    // ---- 文件完整性基线（DET-05） ----

    /// 加载全部基线：path -> (sha256, kind)。
    pub fn fim_load(&self) -> Result<std::collections::HashMap<String, (String, String)>> {
        let conn = self.lock();
        let mut stmt = conn
            .prepare("SELECT path, sha256, kind FROM fim_baseline")
            .context("fim 基线查询失败")?;
        let rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    (row.get::<_, String>(1)?, row.get::<_, String>(2)?),
                ))
            })
            .context("fim 基线查询失败")?
            .collect::<std::result::Result<Vec<_>, _>>()
            .context("fim 基线读取失败")?;
        Ok(rows.into_iter().collect())
    }

    pub fn fim_put(&self, path: &str, sha256: &str, kind: &str) -> Result<()> {
        self.lock()
            .execute(
                "INSERT OR REPLACE INTO fim_baseline(path, sha256, kind) VALUES (?1, ?2, ?3)",
                params![path, sha256, kind],
            )
            .map(|_| ())
            .context("fim 基线写入失败")
    }

    pub fn fim_delete(&self, path: &str) -> Result<()> {
        self.lock()
            .execute("DELETE FROM fim_baseline WHERE path = ?1", params![path])
            .map(|_| ())
            .context("fim 基线删除失败")
    }

    pub fn fim_clear(&self) -> Result<()> {
        self.lock()
            .execute("DELETE FROM fim_baseline", [])
            .map(|_| ())
            .context("fim 基线清空失败")
    }

    // ---- 监听端口基线（DET-06） ----

    pub fn listen_load(&self) -> Result<std::collections::HashSet<(String, u16)>> {
        let conn = self.lock();
        let mut stmt = conn
            .prepare("SELECT addr, port FROM listen_baseline")
            .context("端口基线查询失败")?;
        let rows = stmt
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, u16>(1)?))
            })
            .context("端口基线查询失败")?
            .collect::<std::result::Result<Vec<_>, _>>()
            .context("端口基线读取失败")?;
        Ok(rows.into_iter().collect())
    }

    pub fn listen_put(&self, addr: &str, port: u16) -> Result<()> {
        self.lock()
            .execute(
                "INSERT OR IGNORE INTO listen_baseline(addr, port) VALUES (?1, ?2)",
                params![addr, port],
            )
            .map(|_| ())
            .context("端口基线写入失败")
    }

    pub fn listen_clear(&self) -> Result<()> {
        self.lock()
            .execute("DELETE FROM listen_baseline", [])
            .map(|_| ())
            .context("端口基线清空失败")
    }

    // ---- 告警日志与统计（心跳/每日摘要） ----

    pub fn alert_log_add(
        &self,
        ts: i64,
        level: Level,
        detector: &str,
        title: &str,
        agg_key: &str,
    ) -> Result<()> {
        self.lock()
            .execute(
                "INSERT INTO alert_log(ts, level, detector, title, agg_key) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![ts, level.to_string(), detector, title, agg_key],
            )
            .map(|_| ())
            .context("告警日志写入失败")
    }

    /// 按检测器统计 since 之后的告警数。
    pub fn alert_stats_since(&self, since: i64) -> Result<Vec<(String, i64)>> {
        let conn = self.lock();
        let mut stmt = conn
            .prepare(
                "SELECT detector, COUNT(*) FROM alert_log WHERE ts > ?1 GROUP BY detector ORDER BY COUNT(*) DESC",
            )
            .context("告警统计查询失败")?;
        let rows = stmt
            .query_map(params![since], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
            })
            .context("告警统计查询失败")?
            .collect::<std::result::Result<Vec<_>, _>>()
            .context("告警统计读取失败")?;
        Ok(rows)
    }

    /// since 之后告警最多的聚合键 Top N（如爆破来源 IP）。
    pub fn alert_top_keys_since(&self, since: i64, limit: i64) -> Result<Vec<(String, i64)>> {
        let conn = self.lock();
        let mut stmt = conn
            .prepare(
                "SELECT agg_key, COUNT(*) FROM alert_log WHERE ts > ?1 GROUP BY agg_key ORDER BY COUNT(*) DESC LIMIT ?2",
            )
            .context("告警 TopKey 查询失败")?;
        let rows = stmt
            .query_map(params![since, limit], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
            })
            .context("告警 TopKey 查询失败")?
            .collect::<std::result::Result<Vec<_>, _>>()
            .context("告警 TopKey 读取失败")?;
        Ok(rows)
    }

    // ---- 行为基线（DET-09 进程通信画像） ----

    /// 加载全部进程画像：exe -> profile。
    pub fn behavior_procs_load(&self) -> Result<std::collections::HashMap<String, BehaviorProc>> {
        let conn = self.lock();
        let mut stmt = conn
            .prepare("SELECT exe, comm, first_seen, last_seen, p2p_like, max_concurrent FROM behavior_procs")
            .context("behavior 进程画像查询失败")?;
        let rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    BehaviorProc {
                        comm: row.get(1)?,
                        first_seen: row.get(2)?,
                        last_seen: row.get(3)?,
                        p2p_like: row.get::<_, i64>(4)? != 0,
                        max_concurrent: row.get::<_, i64>(5)? as u32,
                    },
                ))
            })
            .context("behavior 进程画像查询失败")?
            .collect::<std::result::Result<Vec<_>, _>>()
            .context("behavior 进程画像读取失败")?;
        Ok(rows.into_iter().collect())
    }

    /// 新进程入档。
    pub fn behavior_proc_insert(&self, exe: &str, comm: &str, now: i64) -> Result<()> {
        self.lock()
            .execute(
                "INSERT OR IGNORE INTO behavior_procs(exe, comm, first_seen, last_seen) VALUES (?1, ?2, ?3, ?3)",
                params![exe, comm, now],
            )
            .map(|_| ())
            .context("behavior 进程画像写入失败")
    }

    /// 更新进程画像心跳：last_seen、并发峰值（带回落的迟滞更新）、P2P 标记。
    pub fn behavior_proc_touch(
        &self,
        exe: &str,
        now: i64,
        current_conns: u32,
        p2p_like: bool,
    ) -> Result<()> {
        // 迟滞回落：当前并发跌破峰值的 1/4 时直接回落，避免历史峰值永远不降
        self.lock()
            .execute(
                "UPDATE behavior_procs SET
                     last_seen = ?2,
                     max_concurrent = MAX(max_concurrent, ?3),
                     p2p_like = MAX(p2p_like, ?4)
                 WHERE exe = ?1",
                params![exe, now, current_conns as i64, p2p_like as i64],
            )
            .map(|_| ())
            .context("behavior 进程画像更新失败")?;
        if current_conns < 4 {
            // 小基数无需回落
            return Ok(());
        }
        self.lock()
            .execute(
                "UPDATE behavior_procs SET max_concurrent = ?2
                 WHERE exe = ?1 AND max_concurrent > ?2 * 4",
                params![exe, current_conns as i64],
            )
            .map(|_| ())
            .context("behavior 进程画像更新失败")
    }

    /// 查询 (exe, ip) 已记录的观测次数；None 表示陌生关系。
    pub fn behavior_pair_hits(&self, exe: &str, ip: &str) -> Result<Option<u32>> {
        let conn = self.lock();
        let mut stmt = conn
            .prepare("SELECT hits FROM behavior_pairs WHERE exe = ?1 AND ip = ?2")
            .context("behavior 关系查询失败")?;
        let mut rows = stmt
            .query_map(params![exe, ip], |row| row.get::<_, i64>(0))
            .context("behavior 关系查询失败")?;
        match rows.next() {
            Some(Ok(hits)) => Ok(Some(hits as u32)),
            Some(Err(e)) => Err(e).context("behavior 关系读取失败"),
            None => Ok(None),
        }
    }

    /// 记录/更新一条通信关系（未知关系在告警后同样落库，实现“一次告警后转正”）。
    pub fn behavior_pair_touch(&self, exe: &str, ip: &str, port: u16, now: i64) -> Result<()> {
        self.lock()
            .execute(
                "INSERT INTO behavior_pairs(exe, ip, first_seen, last_seen, hits, last_port)
                 VALUES (?1, ?2, ?3, ?3, 1, ?4)
                 ON CONFLICT(exe, ip) DO UPDATE SET last_seen = ?3, hits = hits + 1, last_port = ?4",
                params![exe, ip, now, port],
            )
            .map(|_| ())
            .context("behavior 关系写入失败")
    }

    /// 进程的远端 IP 去重数（用于 P2P 判定）。
    pub fn behavior_distinct_ips(&self, exe: &str) -> Result<i64> {
        let conn = self.lock();
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(DISTINCT ip) FROM behavior_pairs WHERE exe = ?1",
                params![exe],
                |row| row.get(0),
            )
            .context("behavior 关系计数失败")?;
        Ok(count)
    }

    /// 清空行为基线（`honeyguard baseline`）。返回清空前的 (进程数, 关系数)。
    pub fn behavior_clear(&self) -> Result<(i64, i64)> {
        let conn = self.lock();
        let procs: i64 = conn
            .query_row("SELECT COUNT(*) FROM behavior_procs", [], |r| r.get(0))
            .context("behavior 计数失败")?;
        let pairs: i64 = conn
            .query_row("SELECT COUNT(*) FROM behavior_pairs", [], |r| r.get(0))
            .context("behavior 计数失败")?;
        conn.execute("DELETE FROM behavior_procs", [])
            .context("behavior 清空失败")?;
        conn.execute("DELETE FROM behavior_pairs", [])
            .context("behavior 清空失败")?;
        Ok((procs, pairs))
    }
}

/// 进程通信画像（DET-09）。
#[derive(Debug, Clone)]
pub struct BehaviorProc {
    pub comm: String,
    pub first_seen: i64,
    pub last_seen: i64,
    /// 广泛连接型（P2P/BT 等）：陌生 IP 不告警，改监控并发激增。
    pub p2p_like: bool,
    /// 历史并发外连峰值（迟滞回落）。
    pub max_concurrent: u32,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use std::str::FromStr;

    fn mem() -> Store {
        Store::open(Path::new(":memory:")).unwrap()
    }

    #[test]
    fn outbox_roundtrip() {
        let store = mem();
        let now = 1000;
        let id = store
            .outbox_push("http://x/hook", "{\"a\":1}", Level::Warning, now)
            .unwrap();
        let due = store.outbox_due(now, 10).unwrap();
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].id, id);
        assert_eq!(due[0].url, "http://x/hook");
        assert_eq!(due[0].attempts, 0);

        // 失败重试排期后不再立即可取
        store.outbox_schedule_retry(id, 1, now + 8).unwrap();
        assert!(store.outbox_due(now, 10).unwrap().is_empty());
        let due = store.outbox_due(now + 8, 10).unwrap();
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].attempts, 1);

        // 成功后删除
        store.outbox_delete(id).unwrap();
        assert_eq!(store.outbox_pending_count().unwrap(), 0);
    }

    #[test]
    fn backlog_trim_keeps_critical_and_recent() {
        let store = mem();
        let now = 0;
        for i in 0..(BACKLOG_KEEP + 20) {
            store
                .outbox_push("http://x", "b", Level::Warning, now)
                .unwrap();
            if i % 3 == 0 {
                store
                    .outbox_push("http://x", "b", Level::Critical, now)
                    .unwrap();
            }
        }
        let before = store.outbox_pending_count().unwrap();
        store.trim_backlog().unwrap();
        let after = store.outbox_pending_count().unwrap();
        // 120 warning → 只保留最新 100；i%3==0 共 40 条 critical 全保留
        assert_eq!(before, BACKLOG_KEEP + 20 + 40);
        assert_eq!(after, BACKLOG_KEEP + 40, "critical 应全部保留");
        // 剩余的 warning 应是最新插入的那批（id 最大）
        let due = store.outbox_due(now, 1000).unwrap();
        let warning_ids: Vec<i64> = due
            .iter()
            .filter(|r| r.level == "warning")
            .map(|r| r.id)
            .collect();
        assert_eq!(warning_ids.len() as i64, BACKLOG_KEEP);
    }

    #[test]
    fn login_ip_first_seen_is_idempotent() {
        let store = mem();
        let ip = IpAddr::V4(Ipv4Addr::from_str("198.51.100.23").unwrap());
        assert!(
            store.login_ip_first_seen(&ip, 1).unwrap(),
            "首次应返回 true"
        );
        assert!(
            !store.login_ip_first_seen(&ip, 2).unwrap(),
            "重复应返回 false"
        );
    }

    #[test]
    fn persists_across_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.db");
        {
            let store = Store::open(&path).unwrap();
            store
                .outbox_push("http://x", "body", Level::Critical, 5)
                .unwrap();
        }
        let store = Store::open(&path).unwrap();
        assert_eq!(store.outbox_pending_count().unwrap(), 1, "重启后积压应恢复");
        let due = store.outbox_due(10, 10).unwrap();
        assert_eq!(due[0].body, "body");
    }
}
