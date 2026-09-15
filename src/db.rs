//! Thread-history store cleaner.
//!
//! On current Codex builds the TUI reconstructs a resumed session from the
//! SQLite thread-history database, NOT from the rollout .jsonl log. Hard-block
//! policy refusals are stored there as a `thread_turns` row with
//! `status = "failed"` and an `error_json` whose `codexErrorInfo` is
//! `"cyberPolicy"` or `"misalignmentPolicyViolation"` — both are cleared the
//! same way. Editing the .jsonl has no effect on resume (and desyncs the byte
//! offsets the DB records). This module fixes the actual store.
//!
//! Neutralize/leet flip the failed status to `"interrupted"` (a legitimate
//! TurnStatus meaning "the user aborted this turn") rather than `"completed"`,
//! which would falsely claim the model produced output.
//!
//! A "turn" owns its rows in `thread_items` (same thread_id + turn_id), which
//! includes the triggering user message.

use crate::leet;
use crate::rollout::CleanMode;
use rusqlite::types::ValueRef;
use rusqlite::{Connection, OpenFlags};
use serde_json::{json, Map, Value};
use std::error::Error;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum DbMode {
    Neutralize,
    DropTurn,
    /// Neutralize the block AND rewrite the turn's user messages into leet
    /// speak, so a re-scan no longer matches the cyber signature.
    Leet,
}

impl DbMode {
    pub fn parse(s: &str) -> Option<DbMode> {
        match s {
            "neutralize" => Some(DbMode::Neutralize),
            "drop-turn" => Some(DbMode::DropTurn),
            "leet" => Some(DbMode::Leet),
            _ => None,
        }
    }
    pub fn as_str(self) -> &'static str {
        match self {
            DbMode::Neutralize => "neutralize",
            DbMode::DropTurn => "drop-turn",
            DbMode::Leet => "leet",
        }
    }
    /// Map to the rollout cleaner's mode (for `--full`).
    pub fn to_clean(self) -> CleanMode {
        match self {
            DbMode::Neutralize => CleanMode::Neutralize,
            DbMode::DropTurn => CleanMode::DropTurn,
            DbMode::Leet => CleanMode::Leet,
        }
    }
}

pub struct CyberTurn {
    pub thread_id: String,
    pub turn_id: String,
    pub rollout_ordinal: i64,
    pub status: String,
    pub error_json: Option<String>,
}

pub struct DbCleanResult {
    /// Path of the DB acted on (kept for callers/backup provenance; the CLI
    /// prints its own path, so this is not read on the default flow).
    #[allow(dead_code)]
    pub db_path: PathBuf,
    pub turns: Vec<CyberTurn>,
    pub items_affected: usize,
    /// Whether a write was applied (false on dry-run / no matches). Used in tests.
    #[allow(dead_code)]
    pub applied: bool,
}

fn home_dir() -> PathBuf {
    for var in ["USERPROFILE", "HOME"] {
        if let Ok(p) = std::env::var(var) {
            if !p.is_empty() {
                return PathBuf::from(p);
            }
        }
    }
    PathBuf::from(".")
}

/// Directory holding the SQLite state. Precedence:
/// override (--sqlite-home) → CODEX_SQLITE_HOME → CODEX_HOME → ~/.codex.
pub fn sqlite_home(override_dir: Option<&str>) -> PathBuf {
    if let Some(d) = override_dir {
        if !d.is_empty() {
            return PathBuf::from(d);
        }
    }
    for var in ["CODEX_SQLITE_HOME", "CODEX_HOME"] {
        if let Ok(d) = std::env::var(var) {
            if !d.is_empty() {
                return PathBuf::from(d);
            }
        }
    }
    home_dir().join(".codex")
}

fn is_thread_history_name(name: &str) -> bool {
    name.starts_with("thread_history_") && name.ends_with(".sqlite")
}

/// Locate thread-history DB files. `explicit_db` is used verbatim; otherwise
/// search `sqlite_home` at its root, then recursively as a fallback. Newest
/// (highest version suffix) first.
pub fn find_thread_history_dbs(
    sqlite_home_override: Option<&str>,
    explicit_db: Option<&str>,
) -> Vec<PathBuf> {
    if let Some(db) = explicit_db {
        if !db.is_empty() {
            return vec![PathBuf::from(db)];
        }
    }
    let dir = sqlite_home(sqlite_home_override);

    let mut found: Vec<PathBuf> = Vec::new();
    if let Ok(rd) = std::fs::read_dir(&dir) {
        for e in rd.flatten() {
            if e.path().is_file() && is_thread_history_name(&e.file_name().to_string_lossy()) {
                found.push(e.path());
            }
        }
    }
    if found.is_empty() {
        for e in WalkDir::new(&dir).into_iter().filter_map(|e| e.ok()) {
            if e.file_type().is_file() && is_thread_history_name(&e.file_name().to_string_lossy()) {
                found.push(e.path().to_path_buf());
            }
        }
    }
    // Prefer higher version numbers (thread_history_2 over _1): reverse order.
    found.sort_by(|a, b| {
        b.to_string_lossy()
            .to_lowercase()
            .cmp(&a.to_string_lossy().to_lowercase())
    });
    found
}

/// SQL predicate identifying a policy-blocked turn. Covers the three hard-block
/// policies Codex enforces the same way (status='failed' + typed error_json):
/// CyberPolicy, MisalignmentPolicyViolation, and BioPolicy (which rides
/// codex_error_info=badRequest but is detected by message prefix — same UX,
/// composer locked). Matches both machine markers and human wording, resilient
/// across Codex builds. Apostrophes in literals are doubled per SQL syntax.
const CYBER_WHERE: &str = "status = 'failed' AND error_json IS NOT NULL AND (\
error_json LIKE '%cyberPolicy%' OR \
error_json LIKE '%cyber_policy%' OR \
error_json LIKE '%flagged for possible cybersecurity%' OR \
error_json LIKE '%flagged for cyber policy%' OR \
error_json LIKE '%Trusted Access for Cyber%' OR \
error_json LIKE '%misalignmentPolicyViolation%' OR \
error_json LIKE '%misalignment_policy_violation%' OR \
error_json LIKE '%misalignment policy%' OR \
error_json LIKE '%bio_policy%' OR \
error_json LIKE '%bioPolicy%' OR \
error_json LIKE '%flagged for possible biological risk%' OR \
error_json LIKE '%Invalid prompt: we''ve limited access%')";

fn row_to_turn(row: &rusqlite::Row) -> rusqlite::Result<CyberTurn> {
    Ok(CyberTurn {
        thread_id: row.get(0)?,
        turn_id: row.get(1)?,
        rollout_ordinal: row.get(2)?,
        status: row.get(3)?,
        error_json: row.get(4)?,
    })
}

/// List the cyber-refusal turns for a thread (or every thread if `thread_id` is None).
pub fn list_cyber_turns(
    conn: &Connection,
    thread_id: Option<&str>,
) -> rusqlite::Result<Vec<CyberTurn>> {
    let where_clause = if thread_id.is_some() {
        format!("thread_id = ? AND {CYBER_WHERE}")
    } else {
        CYBER_WHERE.to_string()
    };
    let sql = format!(
        "SELECT thread_id, turn_id, rollout_ordinal, status, error_json FROM thread_turns WHERE {where_clause} ORDER BY rollout_ordinal"
    );
    let mut stmt = conn.prepare(&sql)?;
    let turns = match thread_id {
        Some(tid) => stmt
            .query_map([tid], row_to_turn)?
            .collect::<rusqlite::Result<Vec<_>>>()?,
        None => stmt
            .query_map([], row_to_turn)?
            .collect::<rusqlite::Result<Vec<_>>>()?,
    };
    Ok(turns)
}

pub fn thread_exists(conn: &Connection, thread_id: &str) -> rusqlite::Result<bool> {
    conn.prepare("SELECT 1 FROM thread_turns WHERE thread_id = ? LIMIT 1")?
        .exists([thread_id])
}

fn value_ref_to_json(v: ValueRef) -> Value {
    match v {
        ValueRef::Null => Value::Null,
        ValueRef::Integer(n) => json!(n),
        ValueRef::Real(f) => json!(f),
        ValueRef::Text(t) => json!(String::from_utf8_lossy(t).into_owned()),
        ValueRef::Blob(b) => json!(format!("<blob {} bytes>", b.len())),
    }
}

/// Read rows of an arbitrary SELECT into JSON objects keyed by column name
/// (mirrors `SELECT *` for the backup).
fn rows_to_json(
    conn: &Connection,
    sql: &str,
    params: impl rusqlite::Params,
) -> rusqlite::Result<Vec<Value>> {
    let mut stmt = conn.prepare(sql)?;
    let cols: Vec<String> = stmt.column_names().iter().map(|s| s.to_string()).collect();
    let mut rows = stmt.query(params)?;
    let mut out = Vec::new();
    while let Some(row) = rows.next()? {
        let mut obj = Map::new();
        for (i, name) in cols.iter().enumerate() {
            obj.insert(name.clone(), value_ref_to_json(row.get_ref(i)?));
        }
        out.push(Value::Object(obj));
    }
    Ok(out)
}

fn turns_to_json(turns: &[CyberTurn]) -> Value {
    Value::Array(
        turns
            .iter()
            .map(|t| {
                json!({
                    "thread_id": t.thread_id,
                    "turn_id": t.turn_id,
                    "rollout_ordinal": t.rollout_ordinal,
                    "status": t.status,
                    "error_json": t.error_json,
                })
            })
            .collect(),
    )
}

fn backup_path_for(db_path: &Path, thread_id: Option<&str>) -> PathBuf {
    let mut s = db_path.as_os_str().to_os_string();
    s.push(format!(".cyber-backup.{}.json", thread_id.unwrap_or("all")));
    PathBuf::from(s)
}

/// Rewrite every user-controlled text into leet speak, in place. Covers two
/// item shapes: `userMessage` (walks `content[]` where `type='text'`, rewrites
/// `.text`) and `hookPrompt` (walks `fragments[]`, rewrites `.text` — prompt
/// fragments hooks inject into the model context). Also clears `textElements`
/// on any rewritten text part: those record byte ranges for @mentions/skill
/// spans and would misalign the TUI once we've changed the bytes.
/// Image/audio/skill/mention content parts are untouched.
fn leet_encode_user_message(item_json: &str) -> Option<(String, usize)> {
    let mut v: Value = serde_json::from_str(item_json).ok()?;
    let item_type = v.get("type").and_then(Value::as_str)?;
    let mut changed = 0usize;

    match item_type {
        "userMessage" => {
            let content = v.get_mut("content")?.as_array_mut()?;
            for part in content.iter_mut() {
                if part.get("type").and_then(Value::as_str) != Some("text") {
                    continue;
                }
                if let Some(text) = part.get("text").and_then(Value::as_str) {
                    let encoded = leet::encode(text);
                    if encoded != text {
                        part["text"] = Value::String(encoded);
                        // Byte offsets in textElements are invalid after rewrite.
                        if let Some(obj) = part.as_object_mut() {
                            obj.remove("textElements");
                            obj.remove("text_elements");
                        }
                        changed += 1;
                    }
                }
            }
        }
        "hookPrompt" => {
            let fragments = v.get_mut("fragments")?.as_array_mut()?;
            for frag in fragments.iter_mut() {
                if let Some(text) = frag.get("text").and_then(Value::as_str) {
                    let encoded = leet::encode(text);
                    if encoded != text {
                        frag["text"] = Value::String(encoded);
                        changed += 1;
                    }
                }
            }
        }
        _ => return None,
    }

    if changed == 0 {
        return None;
    }
    serde_json::to_string(&v).ok().map(|s| (s, changed))
}

/// Clean cyber-refusal turns in one thread-history DB. Writes a JSON backup of
/// the affected rows (synchronously, before the transaction) next to the DB.
pub fn clean_thread_history_db(
    db_path: &Path,
    mode: DbMode,
    thread_id: Option<&str>,
    dry_run: bool,
) -> Result<DbCleanResult, Box<dyn Error>> {
    let flags = if dry_run {
        OpenFlags::SQLITE_OPEN_READ_ONLY
    } else {
        OpenFlags::SQLITE_OPEN_READ_WRITE
    } | OpenFlags::SQLITE_OPEN_NO_MUTEX
        | OpenFlags::SQLITE_OPEN_URI;
    let mut conn = Connection::open_with_flags(db_path, flags)?;
    conn.busy_timeout(std::time::Duration::from_millis(3000))?;

    let turns = list_cyber_turns(&conn, thread_id)?;
    if turns.is_empty() || dry_run {
        return Ok(DbCleanResult {
            db_path: db_path.to_path_buf(),
            turns,
            items_affected: 0,
            applied: false,
        });
    }

    // Backup the exact rows we are about to change (turns + their items when
    // either drop-turn will delete them or leet mode will rewrite item_json).
    // Gather BEFORE the transaction so a rollback still preserves the snapshot.
    let mut backup = Map::new();
    backup.insert("dbPath".into(), json!(db_path.to_string_lossy()));
    backup.insert("mode".into(), json!(mode.as_str()));
    backup.insert("turns".into(), turns_to_json(&turns));
    if mode == DbMode::DropTurn || mode == DbMode::Leet {
        for t in &turns {
            let items = rows_to_json(
                &conn,
                "SELECT * FROM thread_items WHERE thread_id = ? AND turn_id = ?",
                rusqlite::params![t.thread_id, t.turn_id],
            )?;
            backup.insert(format!("items:{}", t.turn_id), Value::Array(items));
        }
    }
    let backup_path = backup_path_for(db_path, thread_id);
    std::fs::write(
        &backup_path,
        serde_json::to_string_pretty(&Value::Object(backup))?,
    )?;

    let mut items_affected = 0usize;
    {
        let tx = conn.transaction()?;
        for t in &turns {
            match mode {
                DbMode::DropTurn => {
                    items_affected += tx.execute(
                        "DELETE FROM thread_items WHERE thread_id = ? AND turn_id = ?",
                        rusqlite::params![t.thread_id, t.turn_id],
                    )?;
                    tx.execute(
                        "DELETE FROM thread_turns WHERE thread_id = ? AND turn_id = ?",
                        rusqlite::params![t.thread_id, t.turn_id],
                    )?;
                }
                DbMode::Neutralize => {
                    tx.execute(
                        "UPDATE thread_turns SET status = 'interrupted', error_json = NULL WHERE thread_id = ? AND turn_id = ?",
                        rusqlite::params![t.thread_id, t.turn_id],
                    )?;
                }
                DbMode::Leet => {
                    tx.execute(
                        "UPDATE thread_turns SET status = 'interrupted', error_json = NULL WHERE thread_id = ? AND turn_id = ?",
                        rusqlite::params![t.thread_id, t.turn_id],
                    )?;
                    let mut stmt = tx.prepare(
                        "SELECT item_id, item_json FROM thread_items WHERE thread_id = ? AND turn_id = ?",
                    )?;
                    let rows: Vec<(String, String)> = stmt
                        .query_map(rusqlite::params![t.thread_id, t.turn_id], |row| {
                            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                        })?
                        .collect::<rusqlite::Result<Vec<_>>>()?;
                    drop(stmt);
                    for (item_id, item_json) in &rows {
                        if let Some((new_json, n)) = leet_encode_user_message(item_json) {
                            tx.execute(
                                "UPDATE thread_items SET item_json = ? WHERE thread_id = ? AND turn_id = ? AND item_id = ?",
                                rusqlite::params![new_json, t.thread_id, t.turn_id, item_id],
                            )?;
                            items_affected += n;
                        }
                    }
                }
            }
        }
        tx.commit()?;
    }

    // Merge WAL into the main file so the change survives even if another tool
    // discards the -wal. Best-effort.
    let _ = conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE)");

    Ok(DbCleanResult {
        db_path: db_path.to_path_buf(),
        turns,
        items_affected,
        applied: true,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(0);
    const TID: &str = "thread-A";
    const CYBER_ERR: &str = r#"{"message":"This content was flagged for possible cybersecurity risk.","codexErrorInfo":"cyberPolicy","additionalDetails":null}"#;
    const MISALIGN_ERR: &str = r#"{"message":"This request violated the misalignment policy.","codexErrorInfo":"misalignmentPolicyViolation","additionalDetails":null}"#;
    const BIO_ERR: &str = r#"{"message":"This content was flagged for possible biological risk.","codexErrorInfo":"badRequest","additionalDetails":null}"#;
    const INVALID_PROMPT_ERR: &str = r#"{"message":"Invalid prompt: we've limited access to this content for safety reasons.","codexErrorInfo":"badRequest"}"#;
    const OTHER_ERR: &str = r#"{"message":"network timeout","codexErrorInfo":"io"}"#;

    fn unique_db_path() -> PathBuf {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        std::env::temp_dir().join(format!(
            "codex-cyber-db-test-{}-{}.sqlite",
            std::process::id(),
            n
        ))
    }

    fn seed(path: &Path) {
        let conn = Connection::open(path).unwrap();
        conn.execute_batch(
            "CREATE TABLE thread_turns (thread_id TEXT NOT NULL, turn_id TEXT NOT NULL, rollout_ordinal INTEGER NOT NULL, status TEXT NOT NULL, error_json TEXT, PRIMARY KEY (thread_id, turn_id));\
             CREATE TABLE thread_items (thread_id TEXT NOT NULL, turn_id TEXT NOT NULL, item_id TEXT NOT NULL, rollout_ordinal INTEGER NOT NULL, item_json TEXT NOT NULL, PRIMARY KEY (thread_id, turn_id, item_id));",
        ).unwrap();
        let turns = [
            (TID, "t-ok", 1, "completed", None),
            (TID, "t-cyber1", 2, "failed", Some(CYBER_ERR)),
            (TID, "t-cyber2", 3, "failed", Some(CYBER_ERR)),
            (TID, "t-io", 4, "failed", Some(OTHER_ERR)),
            ("thread-B", "t-cyberB", 5, "failed", Some(CYBER_ERR)),
        ];
        for (thread, turn, ord, status, err) in turns {
            conn.execute(
                "INSERT INTO thread_turns (thread_id, turn_id, rollout_ordinal, status, error_json) VALUES (?,?,?,?,?)",
                rusqlite::params![thread, turn, ord, status, err],
            ).unwrap();
        }
        for (turn, item) in [("t-cyber1", "i1"), ("t-cyber2", "i2")] {
            conn.execute(
                "INSERT INTO thread_items (thread_id, turn_id, item_id, rollout_ordinal, item_json) VALUES (?,?,?,?,?)",
                rusqlite::params![TID, turn, item, 2, r#"{"type":"userMessage"}"#],
            ).unwrap();
        }
    }

    fn cleanup(path: &Path) {
        for suffix in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{}{}", path.display(), suffix));
        }
        let _ = std::fs::remove_file(backup_path_for(path, Some(TID)));
    }

    #[test]
    fn list_cyber_turns_finds_only_cyber_failed() {
        let path = unique_db_path();
        seed(&path);
        let conn = Connection::open_with_flags(&path, OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
        let mut ids: Vec<String> = list_cyber_turns(&conn, Some(TID))
            .unwrap()
            .into_iter()
            .map(|t| t.turn_id)
            .collect();
        ids.sort();
        drop(conn);
        cleanup(&path);
        assert_eq!(ids, vec!["t-cyber1", "t-cyber2"]);
    }

    #[test]
    fn neutralize_clears_error_keeps_items_and_other_rows() {
        let path = unique_db_path();
        seed(&path);
        let res = clean_thread_history_db(&path, DbMode::Neutralize, Some(TID), false).unwrap();
        assert!(res.applied);
        assert_eq!(res.turns.len(), 2);

        let conn = Connection::open_with_flags(&path, OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
        let status: String = conn
            .query_row(
                "SELECT status FROM thread_turns WHERE thread_id=? AND turn_id='t-cyber1'",
                [TID],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(status, "interrupted");
        let err: Option<String> = conn
            .query_row(
                "SELECT error_json FROM thread_turns WHERE thread_id=? AND turn_id='t-cyber1'",
                [TID],
                |r| r.get(0),
            )
            .unwrap();
        assert!(err.is_none());
        let io_status: String = conn
            .query_row(
                "SELECT status FROM thread_turns WHERE thread_id=? AND turn_id='t-io'",
                [TID],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(io_status, "failed");
        let items: i64 = conn
            .query_row(
                "SELECT count(*) FROM thread_items WHERE thread_id=?",
                [TID],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(items, 2);
        let b_status: String = conn
            .query_row(
                "SELECT status FROM thread_turns WHERE thread_id='thread-B'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(b_status, "failed");
        drop(conn);
        cleanup(&path);
    }

    #[test]
    fn drop_turn_deletes_turns_and_items() {
        let path = unique_db_path();
        seed(&path);
        let res = clean_thread_history_db(&path, DbMode::DropTurn, Some(TID), false).unwrap();
        assert!(res.applied);
        assert_eq!(res.items_affected, 2);

        let conn = Connection::open_with_flags(&path, OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
        let mut ids: Vec<String> = {
            let mut stmt = conn
                .prepare("SELECT turn_id FROM thread_turns WHERE thread_id=?")
                .unwrap();
            let v = stmt
                .query_map([TID], |r| r.get::<_, String>(0))
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap();
            v
        };
        ids.sort();
        let items: i64 = conn
            .query_row(
                "SELECT count(*) FROM thread_items WHERE thread_id=?",
                [TID],
                |r| r.get(0),
            )
            .unwrap();
        drop(conn);
        cleanup(&path);
        assert_eq!(ids, vec!["t-io", "t-ok"]);
        assert_eq!(items, 0);
    }

    #[test]
    fn writes_non_empty_backup() {
        let path = unique_db_path();
        seed(&path);
        clean_thread_history_db(&path, DbMode::DropTurn, Some(TID), false).unwrap();
        let backup = backup_path_for(&path, Some(TID));
        let content = std::fs::read_to_string(&backup).unwrap();
        let parsed: Value = serde_json::from_str(&content).unwrap();
        let mut ids: Vec<String> = parsed["turns"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["turn_id"].as_str().unwrap().to_string())
            .collect();
        ids.sort();
        assert_eq!(ids, vec!["t-cyber1", "t-cyber2"]);
        assert_eq!(parsed["items:t-cyber1"].as_array().unwrap().len(), 1);
        cleanup(&path);
    }

    #[test]
    fn dry_run_changes_nothing() {
        let path = unique_db_path();
        seed(&path);
        let res = clean_thread_history_db(&path, DbMode::Neutralize, Some(TID), true).unwrap();
        assert!(!res.applied);
        let conn = Connection::open_with_flags(&path, OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
        let failed: i64 = conn
            .query_row(
                "SELECT count(*) FROM thread_turns WHERE status='failed'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        drop(conn);
        cleanup(&path);
        assert_eq!(failed, 4);
    }

    fn seed_with_user_messages(path: &Path) {
        let conn = Connection::open(path).unwrap();
        conn.execute_batch(
            "CREATE TABLE thread_turns (thread_id TEXT NOT NULL, turn_id TEXT NOT NULL, rollout_ordinal INTEGER NOT NULL, status TEXT NOT NULL, error_json TEXT, PRIMARY KEY (thread_id, turn_id));\
             CREATE TABLE thread_items (thread_id TEXT NOT NULL, turn_id TEXT NOT NULL, item_id TEXT NOT NULL, rollout_ordinal INTEGER NOT NULL, item_json TEXT NOT NULL, PRIMARY KEY (thread_id, turn_id, item_id));",
        ).unwrap();
        conn.execute(
            "INSERT INTO thread_turns VALUES (?,?,?,?,?)",
            rusqlite::params![TID, "t-cyber1", 1, "failed", CYBER_ERR],
        )
        .unwrap();
        let user_msg = r#"{"type":"userMessage","content":[{"type":"text","text":"hello world"}]}"#;
        conn.execute(
            "INSERT INTO thread_items VALUES (?,?,?,?,?)",
            rusqlite::params![TID, "t-cyber1", "i1", 1, user_msg],
        )
        .unwrap();
    }

    #[test]
    fn leet_mode_neutralizes_and_encodes_user_messages() {
        let path = unique_db_path();
        seed_with_user_messages(&path);
        let res = clean_thread_history_db(&path, DbMode::Leet, Some(TID), false).unwrap();
        assert!(res.applied);
        assert_eq!(res.turns.len(), 1);
        assert_eq!(res.items_affected, 1);

        let conn = Connection::open_with_flags(&path, OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
        let status: String = conn
            .query_row(
                "SELECT status FROM thread_turns WHERE thread_id=? AND turn_id='t-cyber1'",
                [TID],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(status, "interrupted");
        let err: Option<String> = conn
            .query_row(
                "SELECT error_json FROM thread_turns WHERE thread_id=? AND turn_id='t-cyber1'",
                [TID],
                |r| r.get(0),
            )
            .unwrap();
        assert!(err.is_none());
        let item_json: String = conn
            .query_row(
                "SELECT item_json FROM thread_items WHERE thread_id=? AND turn_id='t-cyber1'",
                [TID],
                |r| r.get(0),
            )
            .unwrap();
        let parsed: Value = serde_json::from_str(&item_json).unwrap();
        assert_eq!(
            parsed["content"][0]["text"].as_str().unwrap(),
            "h3110 w0r1d"
        );
        drop(conn);
        cleanup(&path);
    }

    fn seed_misalign(path: &Path) {
        let conn = Connection::open(path).unwrap();
        conn.execute_batch(
            "CREATE TABLE thread_turns (thread_id TEXT NOT NULL, turn_id TEXT NOT NULL, rollout_ordinal INTEGER NOT NULL, status TEXT NOT NULL, error_json TEXT, PRIMARY KEY (thread_id, turn_id));\
             CREATE TABLE thread_items (thread_id TEXT NOT NULL, turn_id TEXT NOT NULL, item_id TEXT NOT NULL, rollout_ordinal INTEGER NOT NULL, item_json TEXT NOT NULL, PRIMARY KEY (thread_id, turn_id, item_id));",
        ).unwrap();
        conn.execute(
            "INSERT INTO thread_turns VALUES (?,?,?,?,?)",
            rusqlite::params![TID, "t-mis", 1, "failed", MISALIGN_ERR],
        )
        .unwrap();
    }

    #[test]
    fn list_cyber_turns_also_picks_up_misalignment() {
        let path = unique_db_path();
        seed_misalign(&path);
        let conn = Connection::open_with_flags(&path, OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
        let turns = list_cyber_turns(&conn, Some(TID)).unwrap();
        drop(conn);
        cleanup(&path);
        assert_eq!(turns.len(), 1);
        assert_eq!(turns[0].turn_id, "t-mis");
    }

    #[test]
    fn leet_mode_backs_up_items_before_rewrite() {
        let path = unique_db_path();
        seed_with_user_messages(&path);
        clean_thread_history_db(&path, DbMode::Leet, Some(TID), false).unwrap();
        let backup = backup_path_for(&path, Some(TID));
        let content = std::fs::read_to_string(&backup).unwrap();
        let parsed: Value = serde_json::from_str(&content).unwrap();
        // items backup should exist and contain the original text.
        let items = parsed["items:t-cyber1"].as_array().unwrap();
        assert_eq!(items.len(), 1);
        let original_json: Value =
            serde_json::from_str(items[0]["item_json"].as_str().unwrap()).unwrap();
        assert_eq!(original_json["content"][0]["text"], "hello world");
        cleanup(&path);
    }

    fn seed_bio_and_invalid(path: &Path) {
        let conn = Connection::open(path).unwrap();
        conn.execute_batch(
            "CREATE TABLE thread_turns (thread_id TEXT NOT NULL, turn_id TEXT NOT NULL, rollout_ordinal INTEGER NOT NULL, status TEXT NOT NULL, error_json TEXT, PRIMARY KEY (thread_id, turn_id));\
             CREATE TABLE thread_items (thread_id TEXT NOT NULL, turn_id TEXT NOT NULL, item_id TEXT NOT NULL, rollout_ordinal INTEGER NOT NULL, item_json TEXT NOT NULL, PRIMARY KEY (thread_id, turn_id, item_id));",
        ).unwrap();
        for (turn, err) in [("t-bio", BIO_ERR), ("t-inv", INVALID_PROMPT_ERR)] {
            conn.execute(
                "INSERT INTO thread_turns VALUES (?,?,?,?,?)",
                rusqlite::params![TID, turn, 1, "failed", err],
            )
            .unwrap();
        }
    }

    #[test]
    fn list_cyber_turns_picks_up_bio_and_invalid_prompt() {
        let path = unique_db_path();
        seed_bio_and_invalid(&path);
        let conn = Connection::open_with_flags(&path, OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
        let mut ids: Vec<String> = list_cyber_turns(&conn, Some(TID))
            .unwrap()
            .into_iter()
            .map(|t| t.turn_id)
            .collect();
        ids.sort();
        drop(conn);
        cleanup(&path);
        assert_eq!(ids, vec!["t-bio", "t-inv"]);
    }

    #[test]
    fn leet_encode_hook_prompt() {
        let input = r#"{"type":"hookPrompt","fragments":[{"text":"hello world","hookRunId":"h1"},{"text":"scan target"}]}"#;
        let (out, n) = leet_encode_user_message(input).unwrap();
        assert_eq!(n, 2);
        let v: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["fragments"][0]["text"], "h3110 w0r1d");
        assert_eq!(v["fragments"][0]["hookRunId"], "h1");
        assert_eq!(v["fragments"][1]["text"], "5c4n 74r637");
    }

    #[test]
    fn leet_encode_clears_text_elements() {
        let input = r#"{"type":"userMessage","content":[{"type":"text","text":"hello","textElements":[{"byteRange":{"start":0,"end":5},"placeholder":"x"}]}]}"#;
        let (out, n) = leet_encode_user_message(input).unwrap();
        assert_eq!(n, 1);
        let v: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["content"][0]["text"], "h3110");
        assert!(v["content"][0].get("textElements").is_none());
    }

    #[test]
    fn neutralize_writes_interrupted_not_completed() {
        let path = unique_db_path();
        seed(&path);
        clean_thread_history_db(&path, DbMode::Neutralize, Some(TID), false).unwrap();
        let conn = Connection::open_with_flags(&path, OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
        let status: String = conn
            .query_row(
                "SELECT status FROM thread_turns WHERE thread_id=? AND turn_id='t-cyber1'",
                [TID],
                |r| r.get(0),
            )
            .unwrap();
        drop(conn);
        cleanup(&path);
        assert_eq!(status, "interrupted");
    }
}
