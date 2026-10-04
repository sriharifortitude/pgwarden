//! Finding SQL files, building one schema from all of them, and applying
//! suppression comments.

use crate::lexer::lex;
use crate::rules::{self, Finding, Options, Severity, META_FIX, META_ID};
use crate::schema::{split, Loc, Schema, Statement};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

/// Largest SQL file read. A dump of a big schema is megabytes; this keeps a
/// hostile file from using the machine's memory.
pub const MAX_FILE_BYTES: u64 = 64 * 1024 * 1024;
const SKIP_DIRS: &[&str] = &[".git", "node_modules", "target", "vendor", ".venv"];

#[derive(Debug, Default)]
pub struct Report {
    pub files: Vec<String>,
    pub findings: Vec<(String, Finding)>,
    pub suppressed: usize,
    /// Files that could not be read or lexed. A file that was not read says
    /// nothing about its safety, so these are not findings.
    pub errors: Vec<String>,
}

pub fn find_files(paths: &[PathBuf]) -> Result<Vec<PathBuf>, String> {
    let mut out = Vec::new();
    for p in paths {
        if p.is_file() {
            out.push(p.clone());
        } else if p.is_dir() {
            walk(p, &mut out)?;
        } else {
            return Err(format!("{}: no such file or directory", p.display()));
        }
    }
    Ok(out)
}

fn walk(dir: &Path, out: &mut Vec<PathBuf>) -> Result<(), String> {
    let mut entries: Vec<PathBuf> = fs::read_dir(dir)
        .map_err(|e| format!("{}: {e}", dir.display()))?
        .filter_map(Result::ok)
        .map(|e| e.path())
        .collect();
    entries.sort();
    for path in entries {
        if path.is_dir() {
            let skip = path
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| SKIP_DIRS.contains(&n));
            if !skip {
                walk(&path, out)?;
            }
        } else if path
            .extension()
            .and_then(|e| e.to_str())
            .is_some_and(|e| e.eq_ignore_ascii_case("sql"))
        {
            out.push(path);
        }
    }
    Ok(())
}

fn read(path: &Path) -> Result<String, String> {
    let file = fs::File::open(path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            "no such file".to_string()
        } else {
            format!("cannot read ({})", e.kind())
        }
    })?;
    let mut bytes = Vec::new();
    file.take(MAX_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| format!("cannot read ({})", e.kind()))?;
    if bytes.len() as u64 > MAX_FILE_BYTES {
        return Err(format!(
            "larger than {} MiB; refusing it",
            MAX_FILE_BYTES >> 20
        ));
    }
    String::from_utf8(bytes)
        .map(|s| s.trim_start_matches('\u{feff}').to_string())
        .map_err(|e| format!("not valid UTF-8 (byte {})", e.utf8_error().valid_up_to()))
}

pub fn scan_paths(paths: &[PathBuf], options: &Options) -> Result<Report, String> {
    let files = find_files(paths)?;
    let mut sources: Vec<(String, String)> = Vec::new();
    let mut report = Report::default();
    for path in &files {
        let display = path.to_string_lossy().replace('\\', "/");
        match read(path) {
            Ok(text) => sources.push((display, text)),
            Err(e) => report.errors.push(format!("{display}: {e}")),
        }
    }
    let (findings, suppressed, files, errors) = scan_sources(&sources, options);
    report.files = files;
    report.errors.extend(errors);
    report.findings = findings;
    report.suppressed = suppressed;
    Ok(report)
}

type Scanned = (Vec<(String, Finding)>, usize, Vec<String>, Vec<String>);

/// Scan SQL given as (name, text) pairs, in order. All files are applied to one
/// schema, in the order given, so a table made in one file and secured in a
/// later one is judged by where it ends up.
pub fn scan_sources(sources: &[(String, String)], options: &Options) -> Scanned {
    let mut statements: Vec<Statement> = Vec::new();
    let mut names = Vec::new();
    let mut errors = Vec::new();
    let mut lines: Vec<Vec<&str>> = Vec::new();
    for (name, text) in sources {
        match lex(text) {
            Ok(tokens) => {
                let idx = names.len();
                statements.extend(split(&tokens, idx));
                names.push(name.clone());
                lines.push(text.lines().collect());
            }
            Err(e) => errors.push(format!("{name}: {e}")),
        }
    }
    let schema = Schema::build(&statements);
    let mut kept: Vec<(String, Finding)> = Vec::new();
    let mut suppressed = 0;
    let mut reasonless: Vec<Loc> = Vec::new();
    for f in rules::run(&schema, options) {
        let file_lines = &lines[f.loc.file];
        match suppression(file_lines, &f) {
            Suppression::None => kept.push((names[f.loc.file].clone(), f)),
            Suppression::WithReason => suppressed += 1,
            Suppression::NoReason(at) => {
                let loc = Loc {
                    file: f.loc.file,
                    line: at,
                };
                let file = names[f.loc.file].clone();
                let rule = f.rule;
                kept.push((file.clone(), f));
                if !reasonless.contains(&loc) {
                    reasonless.push(loc);
                    kept.push((
                        file,
                        Finding {
                            rule: META_ID,
                            severity: Severity::Low,
                            loc,
                            message: format!("this comment suppresses {rule} but gives no reason, so it suppresses nothing. {META_FIX}"),
                        },
                    ));
                }
            }
        }
    }
    kept.sort_by(|a, b| {
        (&a.0, a.1.loc.line, a.1.rule, &a.1.message).cmp(&(
            &b.0,
            b.1.loc.line,
            b.1.rule,
            &b.1.message,
        ))
    });
    (kept, suppressed, names, errors)
}

enum Suppression {
    None,
    WithReason,
    NoReason(usize),
}

/// `-- pgwarden:ignore PW001 -- reason` on the comment line directly above the
/// statement's first line.
fn suppression(lines: &[&str], f: &Finding) -> Suppression {
    if f.loc.line < 2 || f.loc.line - 2 >= lines.len() {
        return Suppression::None;
    }
    let text = lines[f.loc.line - 2].trim();
    let Some(body) = text.strip_prefix("--") else {
        return Suppression::None;
    };
    let Some(rest) = body.trim().strip_prefix("pgwarden:ignore") else {
        return Suppression::None;
    };
    let rest = rest.trim_start();
    let Some(after) = rest.strip_prefix(f.rule) else {
        return Suppression::None;
    };
    if after
        .chars()
        .next()
        .is_some_and(|c| c.is_ascii_alphanumeric())
    {
        return Suppression::None;
    }
    let reason = after
        .trim()
        .trim_start_matches("--")
        .trim_start_matches(':')
        .trim();
    if reason.is_empty() {
        Suppression::NoReason(f.loc.line - 1)
    } else {
        Suppression::WithReason
    }
}
