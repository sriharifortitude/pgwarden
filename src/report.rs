//! Terminal, JSON and SARIF output. All three are deterministic.

use crate::rules::{self, Severity, META_FIX, META_ID};
use crate::scan::Report;
use serde_json::{json, Value};

const ORDER: [Severity; 4] = [
    Severity::Critical,
    Severity::High,
    Severity::Medium,
    Severity::Low,
];

pub fn summary(r: &Report) -> String {
    let parts: Vec<String> = ORDER
        .iter()
        .filter_map(|s| {
            let n = r.findings.iter().filter(|(_, f)| f.severity == *s).count();
            (n > 0).then(|| format!("{n} {}", s.as_str()))
        })
        .collect();
    let mut text = format!(
        "{} finding(s): {}, in {} SQL file(s)",
        r.findings.len(),
        if parts.is_empty() {
            "none".to_string()
        } else {
            parts.join(", ")
        },
        r.files.len()
    );
    if r.suppressed > 0 {
        text.push_str(&format!("; {} suppressed with a reason", r.suppressed));
    }
    text
}

fn title(rule: &str) -> &'static str {
    if rule == META_ID {
        return "suppression comment without a reason";
    }
    rules::by_id(rule).map_or("", |r| r.title)
}

fn fix(rule: &str) -> &'static str {
    if rule == META_ID {
        return META_FIX;
    }
    rules::by_id(rule).map_or("", |r| r.fix)
}

pub fn terminal(r: &Report, brief: bool) -> String {
    let mut out = String::new();
    for (file, f) in &r.findings {
        if brief {
            out.push_str(&format!(
                "{file}:{}  {:<8} {}  {}\n",
                f.loc.line,
                f.severity.as_str().to_uppercase(),
                f.rule,
                f.message
            ));
            continue;
        }
        out.push_str(&format!(
            "{file}:{}  {:<8} {}  {}\n    {}\n    fix: {}\n",
            f.loc.line,
            f.severity.as_str().to_uppercase(),
            f.rule,
            title(f.rule),
            f.message,
            fix(f.rule)
        ));
    }
    if !r.findings.is_empty() {
        out.push('\n');
    }
    out.push_str(&summary(r));
    out.push('\n');
    out
}

pub fn json(r: &Report) -> String {
    let findings: Vec<Value> = r
        .findings
        .iter()
        .map(|(file, f)| {
            json!({
                "rule": f.rule,
                "name": rules::by_id(f.rule).map_or("ignore-without-reason", |x| x.name),
                "severity": f.severity.as_str(),
                "file": file,
                "line": f.loc.line,
                "message": f.message,
                "fix": fix(f.rule),
            })
        })
        .collect();
    let doc = json!({ "files": r.files.len(), "suppressed": r.suppressed, "findings": findings, "errors": r.errors });
    serde_json::to_string_pretty(&doc).expect("a json value serialises") + "\n"
}

fn level(s: Severity) -> &'static str {
    match s {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low => "note",
    }
}

pub fn sarif(r: &Report) -> String {
    let mut descriptors: Vec<Value> = vec![json!({
        "id": META_ID, "name": "ignore-without-reason",
        "shortDescription": { "text": title(META_ID) }, "fullDescription": { "text": "A suppression nobody can explain is a finding nobody will revisit." },
        "help": { "text": META_FIX }, "defaultConfiguration": { "level": "note" }
    })];
    descriptors.extend(rules::RULES.iter().map(|x| {
        json!({
            "id": x.id, "name": x.name, "shortDescription": { "text": x.title }, "fullDescription": { "text": x.why },
            "help": { "text": x.fix }, "defaultConfiguration": { "level": level(x.severity) }
        })
    }));
    let results: Vec<Value> = r
        .findings
        .iter()
        .map(|(file, f)| {
            json!({
                "ruleId": f.rule, "level": level(f.severity), "message": { "text": f.message },
                "locations": [{ "physicalLocation": { "artifactLocation": { "uri": file }, "region": { "startLine": f.loc.line } } }]
            })
        })
        .collect();
    let doc = json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{ "tool": { "driver": { "name": "pgwarden", "informationUri": "https://github.com/sriharifortitude/pgwarden", "rules": descriptors } }, "results": results }]
    });
    serde_json::to_string_pretty(&doc).expect("a json value serialises") + "\n"
}
