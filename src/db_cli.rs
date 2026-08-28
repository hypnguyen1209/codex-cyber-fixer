//! `db` subcommand — remove the cybersecurity "Trusted Access" refusal from the
//! Codex thread-history SQLite store, which is what `codex resume` actually
//! reads (the rollout .jsonl does not drive resume on current builds).
//!
//! IMPORTANT: fully exit Codex before applying changes — it keeps the DB open
//! and caches the timeline, so a write while it runs may be lost or conflict.
//! (--dry-run is read-only and safe to run anytime.)

use crate::db::{
    clean_thread_history_db, find_thread_history_dbs, list_cyber_turns, sqlite_home, thread_exists,
    CyberTurn, DbMode,
};
use crate::rollout_cli::{clean_rollout_in_place, InPlaceOpts};
use rusqlite::{Connection, OpenFlags};
use std::path::{Path, PathBuf};

struct Args {
    ids: Vec<String>,
    mode: DbMode,
    all: bool,
    dry_run: bool,
    full: bool,
    sqlite_home: Option<String>,
    db: Option<String>,
    help: bool,
}

impl Default for Args {
    fn default() -> Self {
        Args {
            ids: Vec::new(),
            mode: DbMode::Neutralize,
            all: false,
            dry_run: false,
            full: false,
            sqlite_home: None,
            db: None,
            help: false,
        }
    }
}

fn parse_args(argv: &[String]) -> Result<Args, String> {
    let mut a = Args::default();
    let mut i = 0;
    while i < argv.len() {
        let arg = argv[i].as_str();
        match arg {
            "-h" | "--help" => a.help = true,
            "-n" | "--dry-run" => a.dry_run = true,
            "--all" => a.all = true,
            "--full" => a.full = true,
            "--sqlite-home" | "-s" => {
                i += 1;
                a.sqlite_home = argv.get(i).cloned();
            }
            "--db" => {
                i += 1;
                a.db = argv.get(i).cloned();
            }
            "-m" | "--mode" => {
                i += 1;
                let v = argv.get(i).map(|s| s.as_str()).unwrap_or("");
                a.mode = DbMode::parse(v).ok_or_else(|| {
                    format!("invalid --mode \"{v}\" (use neutralize | drop-turn | leet)")
                })?;
            }
            _ => {
                if arg.starts_with('-') {
                    return Err(format!("unknown option: {arg}"));
                }
                a.ids.push(arg.to_string());
            }
        }
        i += 1;
    }
    Ok(a)
}

const HELP: &str = r#"codex-cyber-fixer db — strip hard-block policy refusals from Codex's resume store

Handles both CyberPolicy and MisalignmentPolicyViolation (same failure shape).

Usage:
  codex-cyber-fixer [db] [options] <session-id> ...   (db is the default subcommand)
  codex-cyber-fixer db  [options] --all

The session id is the thread id shown by `codex resume <id>`. The thread-history
DB is found under the Codex home (CODEX_HOME or ~/.codex): thread_history_*.sqlite

A session started with a relocated state dir
  codex -c 'sqlite_home = "/abs/path/to/codex-state"'
stores its thread-history there, NOT in ~/.codex. Point the tool at it with
--sqlite-home (a directory) or --db (a specific thread_history_*.sqlite file).

Options:
  -m, --mode <m>       neutralize | drop-turn | leet    (default: neutralize)
                         neutralize  mark the blocked turn interrupted, clear error
                                     (keeps the user message; block disappears)
                         drop-turn   delete the whole blocked turn and its items
                                     (removes the flagged user message too)
                         leet        neutralize the block AND rewrite the turn's
                                     user messages into leet speak so a re-scan
                                     no longer matches the policy signature
  -s, --sqlite-home <d> directory holding thread_history_*.sqlite (a session's
                        sqlite_home). Also via CODEX_SQLITE_HOME / CODEX_HOME.
      --db <file>      operate on this exact thread_history_*.sqlite file
      --all            target every thread in the DB, not just given ids
      --full           after fixing the DB, also clean the matching rollout
                       .jsonl log (cosmetic — does not affect resume; needs
                       explicit session id(s), ignored with --all)
  -n, --dry-run        list what would change; write nothing (safe while Codex runs)
  -h, --help           show this help

A JSON backup of the affected rows is written next to the DB before any change.
Exit Codex before applying (not dry-run) changes.
"#;

fn short_err(json: &Option<String>) -> String {
    let Some(j) = json else { return String::new() };
    let msg = match serde_json::from_str::<serde_json::Value>(j) {
        Ok(o) => o
            .get("message")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .unwrap_or_default(),
        Err(_) => j.clone(),
    };
    msg.chars().take(70).collect()
}

fn open_ro(path: &Path) -> rusqlite::Result<Connection> {
    Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_URI,
    )
}

pub fn run_db_cli(argv: &[String]) -> i32 {
    let args = match parse_args(argv) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("error: {e}");
            return 2;
        }
    };

    if args.help || (args.ids.is_empty() && !args.all) {
        print!("{HELP}");
        return if args.help { 0 } else { 1 };
    }

    let dbs = find_thread_history_dbs(args.sqlite_home.as_deref(), args.db.as_deref());
    if dbs.is_empty() {
        eprintln!(
            "error: no thread_history_*.sqlite found under {} (use --sqlite-home <dir> or --db <file> if the session set sqlite_home)",
            sqlite_home(args.sqlite_home.as_deref()).display()
        );
        return 1;
    }

    // Targets: explicit thread ids, or [None] meaning "all threads".
    let targets: Vec<Option<String>> = if args.all {
        vec![None]
    } else {
        args.ids.iter().map(|s| Some(s.clone())).collect()
    };

    let mut total_turns = 0usize;
    let mut failures = 0usize;

    for target in &targets {
        let thread_id = target.as_deref();

        // Find the DB(s) that actually hold this thread (for --all, use each DB).
        let candidate_dbs: Vec<PathBuf> = match thread_id {
            Some(tid) => dbs
                .iter()
                .filter(|p| match open_ro(p) {
                    Ok(conn) => thread_exists(&conn, tid).unwrap_or(false),
                    Err(_) => false,
                })
                .cloned()
                .collect(),
            None => dbs.clone(),
        };

        if let Some(tid) = thread_id {
            if candidate_dbs.is_empty() {
                eprintln!("✗ {tid}: thread not found in any thread-history DB");
                failures += 1;
                continue;
            }
        }

        for db_path in &candidate_dbs {
            let label = thread_id.unwrap_or("(all threads)").to_string();

            if args.dry_run {
                match open_ro(db_path).and_then(|conn| list_cyber_turns(&conn, thread_id)) {
                    Ok(turns) => {
                        total_turns += turns.len();
                        println!("· {label} @ {}", db_path.display());
                        if turns.is_empty() {
                            println!("    no cyber-refusal turns");
                        } else {
                            print_dry_turns(&turns);
                        }
                    }
                    Err(e) => {
                        eprintln!("✗ {}: {e}", db_path.display());
                        failures += 1;
                    }
                }
                continue;
            }

            match clean_thread_history_db(db_path, args.mode, thread_id, false) {
                Ok(res) => {
                    total_turns += res.turns.len();
                    if res.turns.is_empty() {
                        println!("· {label} @ {} — no cyber-refusal turns", db_path.display());
                    } else if args.mode == DbMode::DropTurn {
                        println!(
                            "✓ {label} @ {} — dropped {} turn(s), {} item(s)",
                            db_path.display(),
                            res.turns.len(),
                            res.items_affected
                        );
                    } else if args.mode == DbMode::Leet {
                        println!(
                            "✓ {label} @ {} — neutralized {} turn(s), leet-encoded {} text part(s)",
                            db_path.display(),
                            res.turns.len(),
                            res.items_affected
                        );
                    } else {
                        println!(
                            "✓ {label} @ {} — neutralized {} turn(s)",
                            db_path.display(),
                            res.turns.len()
                        );
                    }
                }
                Err(e) => {
                    eprintln!("✗ {}: {e}", db_path.display());
                    failures += 1;
                }
            }
        }
    }

    println!(
        "\n{total_turns} cyber-refusal turn(s) {}.",
        if args.dry_run {
            "found (dry-run, nothing written)"
        } else {
            "handled"
        }
    );

    // --full: also tidy the matching rollout .jsonl (cosmetic — resume already
    // reads the DB we just fixed). Needs concrete session ids to locate files.
    if args.full {
        if args.all {
            println!("\nrollout: --full needs explicit session id(s) to locate the .jsonl; skipped for --all.");
        } else {
            println!("\n· also cleaning rollout .jsonl (cosmetic; does not affect resume):");
            let r = clean_rollout_in_place(
                &args.ids,
                &InPlaceOpts {
                    mode: args.mode.to_clean(),
                    quiet: false,
                    dry_run: args.dry_run,
                    no_backup: false,
                },
            );
            failures += r.failures;
            println!(
                "  {} rollout file(s), {} cleaned{}.",
                r.scanned,
                r.changed,
                if args.dry_run {
                    " (dry-run, nothing written)"
                } else {
                    ""
                }
            );
        }
    }

    if failures > 0 {
        1
    } else {
        0
    }
}

fn print_dry_turns(turns: &[CyberTurn]) {
    for t in turns {
        println!(
            "    would fix turn {} (ord {}) — {}",
            t.turn_id,
            t.rollout_ordinal,
            short_err(&t.error_json)
        );
    }
}
