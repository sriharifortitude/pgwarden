use pgwarden::report;
use pgwarden::rules::{self, Options, Severity};
use pgwarden::scan::scan_paths;
use std::path::PathBuf;
use std::process::ExitCode;

const USAGE: &str = "\
usage: pgwarden scan [--format terminal|json|sarif] [--brief] [--fail-on LEVEL]
                     [--tenant-column NAME]... [PATH...]
       pgwarden rules

  scan     check SQL: pg_dump output, schema files or migrations. PATH is a .sql
           file or a directory searched for them. All files are applied in path
           order to one schema, so a table made in one file and secured in a later
           one is judged by where it ends up. With no PATH, the current directory.
  rules    list every rule with why it matters and how to fix it

  --format           terminal (default), json, or sarif for GitHub code scanning
  --brief            terminal format: one line per finding, without the fix
  --fail-on          lowest severity that makes the exit code 1: low, medium, high
                     (default), critical, or none
  --tenant-column    a column name that marks per-tenant data (repeatable;
                     default: tenant_id, org_id, organization_id, workspace_id, ...)

exit codes: 0 nothing at or above --fail-on, 1 at least one finding is, 2 usage
error or a file that could not be read

suppress a finding with a reason, on the comment line directly above the statement:
  -- pgwarden:ignore PW001 -- search_path is set by the caller's role";

fn main() -> ExitCode {
    match run(std::env::args().skip(1).collect()) {
        Ok(code) => code,
        Err(message) => {
            eprintln!("pgwarden: {message}\n\n{USAGE}");
            ExitCode::from(2)
        }
    }
}

fn list_rules() {
    for (i, r) in rules::RULES.iter().enumerate() {
        if i > 0 {
            println!();
        }
        println!(
            "{}  {:<8} {} ({})\n    why: {}\n    fix: {}",
            r.id,
            r.severity.as_str().to_uppercase(),
            r.title,
            r.name,
            r.why,
            r.fix
        );
    }
}

fn run(args: Vec<String>) -> Result<ExitCode, String> {
    let mut args = args.into_iter();
    match args.next().as_deref() {
        Some("rules") => {
            if args.next().is_some() {
                return Err("rules takes no arguments".into());
            }
            list_rules();
            Ok(ExitCode::SUCCESS)
        }
        Some("scan") => scan(args.collect()),
        Some("-h" | "--help" | "help") => {
            println!("{USAGE}");
            Ok(ExitCode::SUCCESS)
        }
        Some(other) => Err(format!("unknown command {other:?}")),
        None => Err("no command given".into()),
    }
}

fn scan(args: Vec<String>) -> Result<ExitCode, String> {
    let mut format = "terminal".to_string();
    let mut brief = false;
    let mut fail_on = Some(Severity::High);
    let mut options = Options::default();
    let mut paths: Vec<PathBuf> = Vec::new();
    let mut it = args.into_iter();
    while let Some(arg) = it.next() {
        let (flag, inline) = match arg.split_once('=') {
            Some((f, v)) if f.starts_with("--") => (f.to_string(), Some(v.to_string())),
            _ => (arg.clone(), None),
        };
        let mut value = |name: &str| {
            inline
                .clone()
                .or_else(|| it.next())
                .ok_or_else(|| format!("{name} needs a value"))
        };
        match flag.as_str() {
            "--format" => {
                format = value("--format")?;
                if !["terminal", "json", "sarif"].contains(&format.as_str()) {
                    return Err(format!("unknown format {format:?}"));
                }
            }
            "--brief" => brief = true,
            "--fail-on" => {
                let v = value("--fail-on")?;
                fail_on = if v == "none" {
                    None
                } else {
                    Some(Severity::parse(&v).ok_or_else(|| format!("unknown severity {v:?}"))?)
                };
            }
            "--tenant-column" => options.tenant_columns.push(value("--tenant-column")?),
            f if f.starts_with("--") => return Err(format!("unknown option {f}")),
            _ => paths.push(PathBuf::from(arg)),
        }
    }
    if paths.is_empty() {
        paths.push(PathBuf::from("."));
    }

    let report = scan_paths(&paths, &options)?;
    for e in &report.errors {
        eprintln!("pgwarden: {e}");
    }
    if report.files.is_empty() && report.errors.is_empty() {
        return Err(format!(
            "no .sql files found in {}",
            paths
                .iter()
                .map(|p| p.display().to_string())
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    match format.as_str() {
        "json" => print!("{}", report::json(&report)),
        "sarif" => print!("{}", report::sarif(&report)),
        _ => print!("{}", report::terminal(&report, brief)),
    }
    if !report.errors.is_empty() {
        eprintln!(
            "pgwarden: {} file(s) could not be read and are not covered by the result above",
            report.errors.len()
        );
        return Ok(ExitCode::from(2));
    }
    if let Some(threshold) = fail_on {
        if report.findings.iter().any(|(_, f)| f.severity >= threshold) {
            return Ok(ExitCode::from(1));
        }
    }
    Ok(ExitCode::SUCCESS)
}
