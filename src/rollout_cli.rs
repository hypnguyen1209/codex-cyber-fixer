//! Rollout (.jsonl) cleaner CLI.
//!
//! Strips the cybersecurity Trusted-Access refusal from a Codex session rollout
//! log. NOTE: on current Codex builds the .jsonl does NOT drive `codex resume`
//! (the SQLite thread-history store does — see db.rs). Cleaning the rollout is
//! cosmetic: it tidies the transcript and keeps it consistent with a fixed DB.
//! It is exposed as the `rollout` subcommand and reused by `db --full`.

use crate::rollout::{clean_rollout, CleanMode, CleanStats};
use std::path::PathBuf;
use walkdir::WalkDir;

struct Args {
    inputs: Vec<String>,
    mode: CleanMode,
    out: Option<String>,
    copy: bool,
    dry_run: bool,
    no_backup: bool,
    quiet: bool,
    help: bool,
}

impl Default for Args {
    fn default() -> Self {
        Args {
            inputs: Vec::new(),
            mode: CleanMode::Neutralize,
            out: None,
            copy: false,
            dry_run: false,
            no_backup: false,
            quiet: false,
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
            "--dry-run" | "-n" => a.dry_run = true,
            "--copy" | "-c" => a.copy = true,
            "--no-backup" => a.no_backup = true,
            "-q" | "--quiet" => a.quiet = true,
            "--out" | "-o" => {
                i += 1;
                a.out = argv.get(i).cloned();
            }
            "--mode" | "-m" => {
                i += 1;
                let v = argv.get(i).map(|s| s.as_str()).unwrap_or("");
                a.mode = CleanMode::parse(v).ok_or_else(|| {
                    format!(
                        "invalid --mode \"{v}\" (use neutralize | drop-event | drop-turn | leet)"
                    )
                })?;
            }
            _ => {
                if arg.starts_with('-') {
                    return Err(format!("unknown option: {arg}"));
                }
                a.inputs.push(arg.to_string());
            }
        }
        i += 1;
    }
    Ok(a)
}

const HELP: &str = r#"codex-cyber-fixer rollout — strip the cybersecurity Trusted-Access refusal from a Codex rollout

Usage:
  codex-cyber-fixer rollout [options] <session-id | file | glob> ...

A bare token that isn't an existing path or a glob is treated as a Codex
SESSION ID and resolved under the Codex sessions directory:
  Windows      %USERPROFILE%\.codex\sessions
  Linux/macOS  $HOME/.codex/sessions
  (override .codex home with the CODEX_HOME env var)

By default the input is OVERWRITTEN in place (a .bak backup is written first).

Options:
  -m, --mode <m>   neutralize | drop-event | drop-turn | leet  (default: neutralize)
                     neutralize  keep the turn, strip only the cyber error
                     drop-event  remove only the refusal task_complete line
                     drop-turn   remove the whole blocked turn (incl. user msg)
                     leet        neutralize + rewrite user msg text into leet speak
      --no-backup  overwrite without writing a .bak backup
  -c, --copy       don't overwrite; write "<input>.cleaned.jsonl" instead
  -o, --out <path> write result to <path> (single input; no overwrite)
  -n, --dry-run    report changes; write nothing
  -q, --quiet      only print files that changed
  -h, --help       show this help
"#;

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

fn codex_sessions_dir() -> PathBuf {
    let codex_home = std::env::var("CODEX_HOME")
        .ok()
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| home_dir().join(".codex"));
    codex_home.join("sessions")
}

fn has_glob_chars(s: &str) -> bool {
    s.chars()
        .any(|c| matches!(c, '*' | '?' | '[' | ']' | '{' | '}'))
}

fn is_artefact(name: &str) -> bool {
    name.ends_with(".bak") || name.ends_with(".cleaned.jsonl")
}

/// Resolve one CLI token to concrete file path(s): explicit glob → existing
/// path → Codex session id searched under the sessions dir.
fn resolve_token(token: &str) -> Result<Vec<String>, String> {
    // 1) explicit glob -> expand relative to cwd
    if has_glob_chars(token) {
        let mut out = Vec::new();
        let entries = glob::glob(token).map_err(|e| format!("bad glob {token}: {e}"))?;
        for entry in entries.flatten() {
            if entry.is_file() {
                out.push(entry.to_string_lossy().into_owned());
            }
        }
        if out.is_empty() {
            return Err(format!("glob matched nothing: {token}"));
        }
        return Ok(out);
    }

    // 2) an existing file path
    if PathBuf::from(token).is_file() {
        return Ok(vec![token.to_string()]);
    }

    // 3) otherwise treat as a session id -> search the sessions dir
    let dir = codex_sessions_dir();
    if !dir.is_dir() {
        return Err(format!(
            "no file or session matched \"{token}\" (looked in {})",
            dir.display()
        ));
    }
    let mut real: Vec<String> = Vec::new();
    for e in WalkDir::new(&dir).into_iter().filter_map(|e| e.ok()) {
        if !e.file_type().is_file() {
            continue;
        }
        let name = e.file_name().to_string_lossy();
        if name.ends_with(".jsonl") && name.contains(token) && !is_artefact(&name) {
            real.push(e.path().to_string_lossy().into_owned());
        }
    }
    match real.len() {
        1 => Ok(real),
        0 => Err(format!(
            "no file or session matched \"{token}\" (looked in {})",
            dir.display()
        )),
        n => Err(format!(
            "session id \"{token}\" is ambiguous ({n} matches):\n  {}",
            real.join("\n  ")
        )),
    }
}

pub fn resolve_inputs(tokens: &[String]) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for t in tokens {
        for p in resolve_token(t)? {
            if seen.insert(p.clone()) {
                out.push(p);
            }
        }
    }
    Ok(out)
}

fn summarize(s: &CleanStats) -> String {
    let mut parts: Vec<String> = Vec::new();
    if s.events_neutralized > 0 {
        parts.push(format!("{} event(s) neutralized", s.events_neutralized));
    }
    if s.events_dropped > 0 {
        parts.push(format!("{} event(s) dropped", s.events_dropped));
    }
    if s.turns_dropped > 0 {
        parts.push(format!(
            "{} turn(s) dropped ({} lines)",
            s.turns_dropped, s.turn_lines_dropped
        ));
    }
    if s.content_parts_stripped > 0 {
        parts.push(format!(
            "{} content part(s) stripped",
            s.content_parts_stripped
        ));
    }
    if s.messages_dropped > 0 {
        parts.push(format!("{} message(s) dropped", s.messages_dropped));
    }
    if s.texts_leet_encoded > 0 {
        parts.push(format!("{} text(s) leet-encoded", s.texts_leet_encoded));
    }
    if s.parse_errors > 0 {
        parts.push(format!("{} unparseable line(s) left as-is", s.parse_errors));
    }
    if parts.is_empty() {
        "no refusal found".to_string()
    } else {
        parts.join(", ")
    }
}

pub struct InPlaceOpts {
    pub mode: CleanMode,
    pub quiet: bool,
    pub dry_run: bool,
    pub no_backup: bool,
}

pub struct InPlaceResult {
    pub scanned: usize,
    pub changed: usize,
    pub failures: usize,
}

/// Resolve tokens to rollout files and clean each IN PLACE (writing a .bak
/// first, unless no_backup). Reused by `db --full`. Returns counts; never exits.
pub fn clean_rollout_in_place(tokens: &[String], opts: &InPlaceOpts) -> InPlaceResult {
    let files = match resolve_inputs(tokens) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("  rollout: {e}");
            return InPlaceResult {
                scanned: 0,
                changed: 0,
                failures: 1,
            };
        }
    };

    let mut changed = 0;
    let mut failures = 0;
    for file in &files {
        let input = match std::fs::read_to_string(file) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("  ✗ {file}: cannot read ({e})");
                failures += 1;
                continue;
            }
        };
        let result = clean_rollout(&input, opts.mode);
        if result.stats.changed {
            changed += 1;
        }
        let tag = if result.stats.changed { "✓" } else { "·" };
        if result.stats.changed || !opts.quiet {
            println!("  {tag} {file} — {}", summarize(&result.stats));
        }
        if opts.dry_run || !result.stats.changed {
            continue;
        }
        if let Err(e) = write_in_place(file, &input, &result.output, opts.no_backup) {
            eprintln!("  ✗ {file}: cannot write ({e})");
            failures += 1;
        }
    }
    InPlaceResult {
        scanned: files.len(),
        changed,
        failures,
    }
}

fn write_in_place(file: &str, input: &str, output: &str, no_backup: bool) -> std::io::Result<()> {
    if !no_backup {
        std::fs::write(format!("{file}.bak"), input)?;
    }
    std::fs::write(file, output)
}

pub fn run_rollout_cli(argv: &[String]) -> i32 {
    let args = match parse_args(argv) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("error: {e}");
            return 2;
        }
    };

    if args.help || args.inputs.is_empty() {
        print!("{HELP}");
        return if args.help { 0 } else { 1 };
    }
    if args.out.is_some() && (args.copy || args.dry_run) {
        eprintln!("error: --out cannot be combined with --copy or --dry-run");
        return 2;
    }

    let files = match resolve_inputs(&args.inputs) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("error: {e}");
            return 1;
        }
    };
    if files.is_empty() {
        eprintln!("error: no input files matched");
        return 1;
    }
    if args.out.is_some() && files.len() > 1 {
        eprintln!("error: --out requires exactly one input file");
        return 2;
    }

    let mut changed_count = 0;
    let mut failures = 0;

    for file in &files {
        let input = match std::fs::read_to_string(file) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("✗ {file}: cannot read ({e})");
                failures += 1;
                continue;
            }
        };
        let result = clean_rollout(&input, args.mode);
        if result.stats.changed {
            changed_count += 1;
        }
        let tag = if result.stats.changed { "✓" } else { "·" };
        if result.stats.changed || !args.quiet {
            println!("{tag} {file} — {}", summarize(&result.stats));
        }
        if args.dry_run || !result.stats.changed {
            continue;
        }

        let write_res: std::io::Result<()> = if let Some(out) = &args.out {
            std::fs::write(out, &result.output).map(|_| {
                if !args.quiet {
                    println!("  → wrote {out}");
                }
            })
        } else if args.copy {
            let dest = format!("{file}.cleaned.jsonl");
            std::fs::write(&dest, &result.output).map(|_| {
                if !args.quiet {
                    println!("  → wrote {dest}");
                }
            })
        } else {
            write_in_place(file, &input, &result.output, args.no_backup).map(|_| {
                if !args.quiet {
                    if args.no_backup {
                        println!("  → overwritten in place");
                    } else {
                        println!("  → overwritten in place (backup: {file}.bak)");
                    }
                }
            })
        };
        if let Err(e) = write_res {
            eprintln!("✗ {file}: cannot write ({e})");
            failures += 1;
        }
    }

    if !args.quiet {
        println!(
            "\n{} file(s) scanned, {} with refusals{}.",
            files.len(),
            changed_count,
            if args.dry_run {
                " (dry-run, nothing written)"
            } else {
                ""
            }
        );
    }
    if failures > 0 {
        1
    } else {
        0
    }
}
