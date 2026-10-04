use std::path::PathBuf;
use std::process::{Command, Output};

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_pgwarden"))
        .args(args)
        .output()
        .expect("binary runs")
}

fn testdata(rel: &str) -> String {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("testdata")
        .join(rel)
        .to_string_lossy()
        .into_owned()
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).replace("\r\n", "\n")
}

fn temp(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("pgwarden-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn the_vulnerable_fixture_is_reported_with_lines() {
    let out = run(&["scan", "--brief", &testdata("vulnerable")]);
    let stdout = text(&out.stdout);
    assert_eq!(out.status.code(), Some(1));
    for expected in [
        "001_schema.sql:16  HIGH     PW003",
        "002_functions.sql:1  HIGH     PW001",
        "002_functions.sql:1  HIGH     PW002",
        "002_functions.sql:13  HIGH     PW005",
        "003_roles.sql:1  HIGH     PW007",
        "003_roles.sql:3  HIGH     PW006",
        "15 finding(s): 9 high, 4 medium, 2 low, in 3 SQL file(s)",
    ] {
        assert!(stdout.contains(expected), "missing {expected:?}\n{stdout}");
    }
}

#[test]
fn the_clean_fixture_passes_at_the_strictest_level() {
    let out = run(&["scan", "--fail-on", "low", &testdata("clean")]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stdout));
    assert!(text(&out.stdout).contains("0 finding(s): none, in 1 SQL file(s)"));
}

#[test]
fn fail_on_sets_the_exit_code() {
    let dir = testdata("vulnerable");
    let codes: Vec<Option<i32>> = ["low", "medium", "high", "critical", "none"]
        .iter()
        .map(|l| run(&["scan", "--fail-on", l, &dir]).status.code())
        .collect();
    assert_eq!(codes, vec![Some(1), Some(1), Some(1), Some(0), Some(0)]);
}

#[test]
fn the_full_report_carries_the_fix_and_brief_does_not() {
    let dir = testdata("vulnerable");
    let full = text(&run(&["scan", &dir]).stdout);
    let brief = text(&run(&["scan", "--brief", &dir]).stdout);
    assert!(full.contains("    fix: ") && !brief.contains("fix:"));
    assert_eq!(brief.matches('\n').count(), 17); // 15 findings, a blank line, the summary
}

#[test]
fn json_is_complete_and_empty_lists_are_lists() {
    let doc: serde_json::Value = serde_json::from_str(&text(
        &run(&["scan", "--format", "json", &testdata("vulnerable")]).stdout,
    ))
    .unwrap();
    assert_eq!(doc["files"], 3);
    assert_eq!(doc["findings"].as_array().unwrap().len(), 15);
    assert_eq!(doc["errors"], serde_json::json!([]));
    let first = &doc["findings"][0];
    for key in ["rule", "name", "severity", "file", "line", "message", "fix"] {
        assert!(first.get(key).is_some(), "{key}");
    }
    let clean: serde_json::Value = serde_json::from_str(&text(
        &run(&["scan", "--format=json", &testdata("clean")]).stdout,
    ))
    .unwrap();
    assert_eq!(clean["findings"], serde_json::json!([]));
}

#[test]
fn sarif_has_rules_results_and_levels() {
    let doc: serde_json::Value = serde_json::from_str(&text(
        &run(&["scan", "--format", "sarif", &testdata("vulnerable")]).stdout,
    ))
    .unwrap();
    assert_eq!(doc["version"], "2.1.0");
    let run0 = &doc["runs"][0];
    assert_eq!(run0["tool"]["driver"]["name"], "pgwarden");
    assert_eq!(
        run0["tool"]["driver"]["rules"].as_array().unwrap().len(),
        12
    );
    let levels: Vec<&str> = run0["results"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["level"].as_str().unwrap())
        .collect();
    let n = |l: &str| levels.iter().filter(|x| **x == l).count();
    assert_eq!((n("error"), n("warning"), n("note")), (9, 4, 2));
    for r in run0["results"].as_array().unwrap() {
        let uri = r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
            .as_str()
            .unwrap();
        assert!(!uri.contains('\\'), "{uri}");
        assert!(
            r["locations"][0]["physicalLocation"]["region"]["startLine"]
                .as_u64()
                .unwrap()
                >= 1
        );
    }
}

#[test]
fn output_is_deterministic() {
    let dir = testdata("vulnerable");
    assert_eq!(run(&["scan", &dir]).stdout, run(&["scan", &dir]).stdout);
}

#[test]
fn the_rules_command_explains_every_rule() {
    let out = text(&run(&["rules"]).stdout);
    assert_eq!(out.matches("    why: ").count(), 11);
    assert_eq!(out.matches("    fix: ").count(), 11);
    assert!(out.contains("PW005") && out.contains("security_invoker"));
}

#[test]
fn a_tenant_column_can_be_configured() {
    let dir = temp("tenant");
    std::fs::write(
        dir.join("a.sql"),
        "CREATE TABLE a (shop_id int);\nCREATE TABLE b (tenant_id int);\n",
    )
    .unwrap();
    let default = text(&run(&["scan", "--brief", dir.to_str().unwrap()]).stdout);
    assert!(
        default.contains("PW010") && !default.contains("shop_id"),
        "{default}"
    );
    let custom = text(
        &run(&[
            "scan",
            "--brief",
            "--tenant-column",
            "shop_id",
            dir.to_str().unwrap(),
        ])
        .stdout,
    );
    assert!(
        custom.contains("column named shop_id") && !custom.contains("tenant_id"),
        "{custom}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn an_unreadable_file_is_named_and_fails_the_run_but_the_rest_is_scanned() {
    let dir = temp("bad");
    std::fs::write(dir.join("a_good.sql"), "CREATE TABLE t (id int);\n").unwrap();
    std::fs::write(dir.join("b_bad.sql"), "SELECT 'never closed;\n").unwrap();
    std::fs::write(dir.join("c_binary.sql"), b"SELECT 1;\n\xff\xfe\n").unwrap();
    let out = run(&["scan", dir.to_str().unwrap()]);
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(out.status.code(), Some(2));
    let stderr = text(&out.stderr);
    assert!(
        stderr.contains("b_bad.sql: line 1: unterminated string literal"),
        "{stderr}"
    );
    assert!(stderr.contains("c_binary.sql: not valid UTF-8"), "{stderr}");
    assert!(stderr.contains("2 file(s) could not be read"), "{stderr}");
    assert!(text(&out.stdout).contains("0 finding(s): none, in 1 SQL file(s)"));
}

#[test]
fn a_missing_path_and_an_empty_directory_are_errors() {
    let out = run(&["scan", "definitely-not-here.sql"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(text(&out.stderr).contains("definitely-not-here.sql: no such file or directory"));
    let dir = temp("empty");
    let out = run(&["scan", dir.to_str().unwrap()]);
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(out.status.code(), Some(2));
    assert!(text(&out.stderr).contains("no .sql files found"));
}

#[test]
fn directories_are_searched_recursively_in_order_and_noise_is_skipped() {
    let dir = temp("walk");
    for (name, sql) in [
        ("b/002.sql", "CREATE TABLE x (tenant_id int);"),
        ("a/001.sql", "CREATE TABLE y (id int);"),
        ("node_modules/n.sql", "CREATE ROLE r SUPERUSER;"),
        (".git/g.sql", "CREATE ROLE r SUPERUSER;"),
        ("notes.txt", "CREATE ROLE r SUPERUSER;"),
    ] {
        let p = dir.join(name);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, sql).unwrap();
    }
    let out = text(&run(&["scan", "--format", "json", dir.to_str().unwrap()]).stdout);
    let _ = std::fs::remove_dir_all(&dir);
    let doc: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(doc["files"], 2);
    assert_eq!(doc["findings"].as_array().unwrap().len(), 1);
}

#[test]
fn usage_errors_exit_2() {
    for args in [
        vec![],
        vec!["nope"],
        vec!["scan", "--format", "xml"],
        vec!["scan", "--fail-on", "urgent"],
        vec!["scan", "--fail-on"],
        vec!["scan", "--bogus"],
        vec!["rules", "extra"],
    ] {
        let out = run(&args);
        assert_eq!(out.status.code(), Some(2), "{args:?}");
        assert!(text(&out.stderr).contains("usage: pgwarden"), "{args:?}");
    }
}

#[test]
fn an_oversized_file_is_refused_without_being_read_whole() {
    let dir = temp("big");
    let path = dir.join("big.sql");
    let file = std::fs::File::create(&path).unwrap();
    file.set_len(64 * 1024 * 1024 + 1).unwrap();
    let out = run(&["scan", path.to_str().unwrap()]);
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(out.status.code(), Some(2));
    assert!(
        text(&out.stderr).contains("larger than 64 MiB; refusing it"),
        "{}",
        text(&out.stderr)
    );
}
