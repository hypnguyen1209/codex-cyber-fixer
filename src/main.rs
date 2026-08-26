//! codex-cyber-fixer — clear the Codex cybersecurity "Trusted Access" refusal
//! from a session so `codex resume` keeps working.
//!
//! Two subcommands:
//!   db       (default) fix the SQLite thread-history store — the source of
//!            truth for resume. Add --full to also tidy the rollout .jsonl.
//!   rollout  clean only the rollout .jsonl transcript (cosmetic).

mod db;
mod db_cli;
mod rollout;
mod rollout_cli;

const TOP_HELP: &str = r#"codex-cyber-fixer — clear the Codex cybersecurity Trusted-Access refusal

Usage:
  codex-cyber-fixer [db] [options] <session-id> ...   fix the resume store (default)
  codex-cyber-fixer rollout [options] <input> ...      clean the rollout .jsonl

`db` is the source of truth for `codex resume`; `rollout` is cosmetic. Run a
subcommand with --help for its options. Exit Codex before applying changes.
"#;

fn main() {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let first = argv.first().map(|s| s.as_str());

    let code = match first {
        Some("rollout") => rollout_cli::run_rollout_cli(&argv[1..]),
        Some("-h") | Some("--help") if argv.len() == 1 => {
            print!("{TOP_HELP}");
            0
        }
        // `db` is the default subcommand; strip a leading explicit "db".
        Some("db") => db_cli::run_db_cli(&argv[1..]),
        _ => db_cli::run_db_cli(&argv),
    };
    std::process::exit(code);
}
