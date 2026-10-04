//! The checks. Each looks at the schema as the SQL leaves it and returns
//! findings; each carries the text a person needs to understand and fix it.

use crate::schema::{Kind, Loc, Schema};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }

    pub fn parse(s: &str) -> Option<Severity> {
        match s {
            "low" => Some(Severity::Low),
            "medium" => Some(Severity::Medium),
            "high" => Some(Severity::High),
            "critical" => Some(Severity::Critical),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub rule: &'static str,
    pub severity: Severity,
    pub loc: Loc,
    pub message: String,
}

#[derive(Debug, Clone, Default)]
pub struct Options {
    /// Column names that mark a table as holding per-tenant rows.
    pub tenant_columns: Vec<String>,
}

pub const DEFAULT_TENANT_COLUMNS: &[&str] = &[
    "tenant_id",
    "org_id",
    "organization_id",
    "organisation_id",
    "workspace_id",
    "company_id",
];

pub struct Rule {
    pub id: &'static str,
    pub name: &'static str,
    pub title: &'static str,
    pub severity: Severity,
    pub why: &'static str,
    pub fix: &'static str,
    pub check: fn(&Schema, &Options) -> Vec<Finding>,
}

fn finding(rule: &'static str, severity: Severity, loc: Loc, message: String) -> Finding {
    Finding {
        rule,
        severity,
        loc,
        message,
    }
}

pub static RULES: &[Rule] = &[
    Rule {
        id: "PW001",
        name: "definer-search-path",
        title: "SECURITY DEFINER function without a pinned search_path",
        severity: Severity::High,
        why: "A SECURITY DEFINER function runs with its owner's privileges. Names in its body that are not schema-qualified are looked up through the caller's search_path, so a caller who can create a table or function in an earlier schema can substitute their own object and have it used with the owner's rights. The PostgreSQL manual's guidance for writing SECURITY DEFINER functions safely is to set search_path on the function itself.",
        fix: "Add SET search_path = pg_catalog, pg_temp (or an explicit list) to the function, and schema-qualify the objects it uses.",
        check: check_definer_search_path,
    },
    Rule {
        id: "PW002",
        name: "definer-public-execute",
        title: "SECURITY DEFINER function executable by PUBLIC",
        severity: Severity::High,
        why: "PostgreSQL grants EXECUTE on every new function to PUBLIC unless that is revoked. A SECURITY DEFINER function nobody revoked is therefore callable, with its owner's privileges, by every role that can connect.",
        fix: "REVOKE ALL ON FUNCTION name(args) FROM PUBLIC; then GRANT EXECUTE to the specific roles that need it.",
        check: check_definer_public_execute,
    },
    Rule {
        id: "PW003",
        name: "policy-without-rls",
        title: "policy on a table where row-level security is not enabled",
        severity: Severity::High,
        why: "CREATE POLICY has no effect until ALTER TABLE ... ENABLE ROW LEVEL SECURITY. A table with policies and RLS left off returns every row to every role with table privileges, while the schema reads as though access is restricted.",
        fix: "ALTER TABLE name ENABLE ROW LEVEL SECURITY; (and FORCE ROW LEVEL SECURITY if the owner role is used by the application).",
        check: check_policy_without_rls,
    },
    Rule {
        id: "PW004",
        name: "rls-without-policy",
        title: "row-level security enabled with no policies",
        severity: Severity::Low,
        why: "With RLS enabled and no policy, non-owner roles see no rows at all. That is right for a table nobody should read directly, and a bug for one whose policies were never written.",
        fix: "Add the policies, or leave a comment saying the table is deliberately closed.",
        check: check_rls_without_policy,
    },
    Rule {
        id: "PW005",
        name: "view-bypasses-rls",
        title: "view over a row-level-security table runs as its owner",
        severity: Severity::High,
        why: "A view runs with its owner's privileges by default. The owner of a table bypasses its row-level security unless FORCE ROW LEVEL SECURITY is set, so everyone who can read the view sees every row, whatever the policies say.",
        fix: "CREATE VIEW ... WITH (security_invoker = true) (PostgreSQL 15 and later), or FORCE ROW LEVEL SECURITY on the table.",
        check: check_view_bypasses_rls,
    },
    Rule {
        id: "PW006",
        name: "public-grant",
        title: "privileges granted to PUBLIC",
        severity: Severity::Medium,
        why: "PUBLIC is every role, including ones created later. A grant to it cannot be narrowed by adding roles; it has to be revoked. Write privileges on a table, or CREATE on a schema, given to PUBLIC let any login modify data or plant objects.",
        fix: "Grant to the specific roles that need access, and REVOKE the PUBLIC grant.",
        check: check_public_grant,
    },
    Rule {
        id: "PW007",
        name: "risky-role",
        title: "role with SUPERUSER, BYPASSRLS or CREATEROLE",
        severity: Severity::High,
        why: "SUPERUSER and BYPASSRLS skip every privilege and row-level-security check, and CREATEROLE can mint roles with chosen attributes. A role an application connects as should have none of them.",
        fix: "Remove the attribute, and give the role only the grants it needs.",
        check: check_risky_role,
    },
    Rule {
        id: "PW008",
        name: "password-in-sql",
        title: "role password stored in the SQL",
        severity: Severity::High,
        why: "A plaintext password in a migration or dump is in version control for good. An MD5 hash is weak: with md5 authentication the hash itself is enough to log in, and it can be cracked offline. Even a SCRAM verifier is material that should not sit in a repository.",
        fix: "Create roles without a password in SQL and set it from the deployment's secret store, or use certificate or IAM authentication.",
        check: check_password,
    },
    Rule {
        id: "PW009",
        name: "untrusted-code",
        title: "untrusted language or an extension that reaches outside the database",
        severity: Severity::Medium,
        why: "Functions in an untrusted language (plpython3u, plperlu, pltclu) can read files and run commands as the database server's OS user. dblink, file_fdw and adminpack reach the network and the server's filesystem. Each widens what a SQL injection or a compromised role can do.",
        fix: "Use a trusted language (plpgsql), and keep such extensions out of databases that serve application roles.",
        check: check_untrusted,
    },
    Rule {
        id: "PW010",
        name: "tenant-without-rls",
        title: "per-tenant table without row-level security",
        severity: Severity::Medium,
        why: "A table with a tenant or organisation column that has no row-level security relies on every query in the application remembering a WHERE clause. One missed filter returns another customer's rows.",
        fix: "ENABLE ROW LEVEL SECURITY and add a policy on the tenant column, or confirm the table is not tenant data (the column names checked are configurable with --tenant-column).",
        check: check_tenant,
    },
    Rule {
        id: "PW011",
        name: "secret-column",
        title: "column that looks like a plaintext secret",
        severity: Severity::Low,
        why: "A text column named password, token, secret or api_key that is not named as a hash or as encrypted is often a credential stored in the clear, readable by anyone with SELECT or a backup.",
        fix: "Store a hash (for passwords) or encrypt the value, and name the column to say so (password_hash, token_encrypted).",
        check: check_secret_column,
    },
];

pub const META_ID: &str = "PW000";
pub const META_FIX: &str = "Write `-- pgwarden:ignore PW001 -- why this is acceptable`.";

pub fn by_id(id: &str) -> Option<&'static Rule> {
    RULES.iter().find(|r| r.id == id)
}

pub fn run(schema: &Schema, options: &Options) -> Vec<Finding> {
    let mut out: Vec<Finding> = RULES
        .iter()
        .flat_map(|r| (r.check)(schema, options))
        .collect();
    out.sort_by(|a, b| (a.loc, a.rule, &a.message).cmp(&(b.loc, b.rule, &b.message)));
    out
}

// ---- PW001 / PW002 ----------------------------------------------------------

fn check_definer_search_path(s: &Schema, _: &Options) -> Vec<Finding> {
    s.functions
        .values()
        .filter(|f| f.definer && !f.search_path_set)
        .map(|f| {
            finding(
                "PW001",
                Severity::High,
                f.loc,
                format!("function {}() is SECURITY DEFINER and has no SET search_path, so names inside it resolve through the caller's search_path", f.name),
            )
        })
        .collect()
}

fn function_is_revoked_from_public(s: &Schema, name: &str) -> bool {
    s.grants.iter().any(|g| {
        g.revoke
            && g.kind == Kind::Function
            && g.grantees.iter().any(|x| x == "public")
            && (g.default_privileges || g.all_in_schema || g.objects.iter().any(|o| o == name))
    })
}

fn check_definer_public_execute(s: &Schema, _: &Options) -> Vec<Finding> {
    s.functions
        .values()
        .filter(|f| f.definer && !f.returns_trigger && !function_is_revoked_from_public(s, &f.name))
        .map(|f| {
            finding(
                "PW002",
                Severity::High,
                f.loc,
                format!("function {}() is SECURITY DEFINER and nothing revokes EXECUTE from PUBLIC, so any role that can connect can call it with the owner's privileges", f.name),
            )
        })
        .collect()
}

// ---- PW003 / PW004 / PW005 --------------------------------------------------

fn check_policy_without_rls(s: &Schema, _: &Options) -> Vec<Finding> {
    let mut out = Vec::new();
    for table in s.tables.values().filter(|t| t.rls.is_none()) {
        let policies: Vec<_> = s
            .policies
            .iter()
            .filter(|p| p.table == table.name)
            .collect();
        if let Some(first) = policies.first() {
            out.push(finding(
                "PW003",
                Severity::High,
                first.loc,
                format!("table {} has {} polic{} but row-level security is not enabled, so they are not enforced", table.name, policies.len(), if policies.len() == 1 { "y" } else { "ies" }),
            ));
        }
    }
    out
}

fn check_rls_without_policy(s: &Schema, _: &Options) -> Vec<Finding> {
    s.tables
        .values()
        .filter_map(|t| t.rls.map(|loc| (t, loc)))
        .filter(|(t, _)| !s.policies.iter().any(|p| p.table == t.name))
        .map(|(t, loc)| {
            finding("PW004", Severity::Low, loc, format!("table {} has row-level security enabled and no policies, so non-owner roles see no rows", t.name))
        })
        .collect()
}

fn check_view_bypasses_rls(s: &Schema, _: &Options) -> Vec<Finding> {
    let mut out = Vec::new();
    for view in s.views.values().filter(|v| !v.security_invoker) {
        for read in &view.reads {
            if let Some(table) = s.tables.get(read) {
                if table.rls.is_some() && !table.forced {
                    out.push(finding(
                        "PW005",
                        Severity::High,
                        view.loc,
                        format!("view {} reads {}, which has row-level security, and runs as its owner (who bypasses it), so every user of the view sees every row", view.name, table.name),
                    ));
                }
            }
        }
    }
    out
}

// ---- PW006 ------------------------------------------------------------------

fn check_public_grant(s: &Schema, _: &Options) -> Vec<Finding> {
    let mut out = Vec::new();
    for g in s
        .grants
        .iter()
        .filter(|g| !g.revoke && g.grantees.iter().any(|x| x == "public"))
    {
        let has = |names: &[&str]| g.privileges.iter().any(|p| names.contains(&p.as_str()));
        let target = if g.default_privileges {
            "future objects (ALTER DEFAULT PRIVILEGES)".to_string()
        } else if g.all_in_schema {
            format!(
                "every object in schema {}",
                g.objects.first().map_or("?", String::as_str)
            )
        } else {
            g.objects.join(", ")
        };
        let (severity, message) = match g.kind {
            Kind::Schema if has(&["all", "create"]) => (
                Severity::High,
                format!(
                    "grants PUBLIC CREATE on schema {target}: any login can plant objects there"
                ),
            ),
            Kind::Table if has(&["all", "insert", "update", "delete", "truncate"]) => (
                Severity::High,
                format!(
                    "grants PUBLIC write privileges on {target}: any login can change the data"
                ),
            ),
            Kind::Table => (
                Severity::Medium,
                format!("grants PUBLIC read access to {target}, including to roles created later"),
            ),
            Kind::Sequence if has(&["all", "update", "usage"]) => {
                (Severity::Medium, format!("grants PUBLIC use of {target}"))
            }
            _ => continue,
        };
        out.push(finding("PW006", severity, g.loc, message));
    }
    out
}

// ---- PW007 / PW008 ----------------------------------------------------------

fn check_risky_role(s: &Schema, _: &Options) -> Vec<Finding> {
    let mut out = Vec::new();
    for r in s.roles.values() {
        let mut flags = Vec::new();
        // The built-in superuser has every attribute by definition; listing them is noise.
        if r.name == "postgres" {
            continue;
        }
        if r.superuser {
            flags.push(("SUPERUSER", Severity::High));
        }
        if r.bypassrls {
            flags.push(("BYPASSRLS", Severity::High));
        }
        if r.createrole {
            flags.push(("CREATEROLE", Severity::Medium));
        }
        for (flag, severity) in flags {
            out.push(finding(
                "PW007",
                severity,
                r.loc,
                format!(
                    "role {} has {flag}, which an application role should not",
                    r.name
                ),
            ));
        }
    }
    out
}

fn check_password(s: &Schema, _: &Options) -> Vec<Finding> {
    let mut out = Vec::new();
    for r in s.roles.values() {
        let Some(p) = &r.verifier else { continue };
        let is_md5 =
            p.len() == 35 && p.starts_with("md5") && p[3..].chars().all(|c| c.is_ascii_hexdigit());
        let (severity, what) = if p.starts_with("SCRAM-SHA-256$") {
            (Severity::Low, "contains a SCRAM verifier")
        } else if is_md5 {
            (Severity::Medium, "contains an MD5 password hash, which is enough to authenticate and can be cracked offline")
        } else {
            (Severity::High, "sets a plaintext password")
        };
        out.push(finding(
            "PW008",
            severity,
            r.loc,
            format!("the SQL for role {} {what}", r.name),
        ));
    }
    out
}

// ---- PW009 ------------------------------------------------------------------

const UNTRUSTED_LANGUAGES: &[&str] = &[
    "plpythonu",
    "plpython2u",
    "plpython3u",
    "plperlu",
    "pltclu",
    "plsh",
    "plrubyu",
];
const REACHING_EXTENSIONS: &[&str] = &[
    "dblink",
    "file_fdw",
    "adminpack",
    "plpython3u",
    "plpythonu",
    "plperlu",
    "pltclu",
];

fn check_untrusted(s: &Schema, _: &Options) -> Vec<Finding> {
    let mut out = Vec::new();
    for f in s
        .functions
        .values()
        .filter(|f| UNTRUSTED_LANGUAGES.contains(&f.language.as_str()))
    {
        out.push(finding("PW009", Severity::Medium, f.loc, format!("function {}() is written in {}, an untrusted language that can reach the server's OS", f.name, f.language)));
    }
    for e in s
        .extensions
        .iter()
        .filter(|e| REACHING_EXTENSIONS.contains(&e.name.as_str()))
    {
        out.push(finding(
            "PW009",
            Severity::Medium,
            e.loc,
            format!(
                "extension {} reaches outside the database (network, files or the OS)",
                e.name
            ),
        ));
    }
    out
}

// ---- PW010 / PW011 ----------------------------------------------------------

fn check_tenant(s: &Schema, options: &Options) -> Vec<Finding> {
    let configured: Vec<String> = if options.tenant_columns.is_empty() {
        DEFAULT_TENANT_COLUMNS
            .iter()
            .map(|c| (*c).to_string())
            .collect()
    } else {
        options
            .tenant_columns
            .iter()
            .map(|c| c.to_lowercase())
            .collect()
    };
    s.tables
        .values()
        .filter(|t| t.rls.is_none())
        .filter_map(|t| configured.iter().find(|name| t.columns.iter().any(|c| c.name.to_lowercase() == **name)).map(|name| (t, name)))
        .map(|(t, name)| {
            finding("PW010", Severity::Medium, t.loc, format!("table {} has a column named {name} but no row-level security, so tenant isolation depends on every query filtering by it", t.name))
        })
        .collect()
}

const SECRET_WORDS: &[&str] = &[
    "password",
    "passwd",
    "secret",
    "api_key",
    "apikey",
    "token",
    "private_key",
];
/// A name with one of these in it says the value is not the raw secret, wherever
/// it sits in the name (encrypted_password).
const SAFE_PARTS: &[&str] = &["encrypted", "hashed", "hash", "digest", "bcrypt", "argon2"];
const SAFE_SUFFIXES: &[&str] = &[
    "hash",
    "hashed",
    "digest",
    "encrypted",
    "enc",
    "salt",
    "fingerprint",
    "id",
    "at",
    "type",
    "count",
];

fn check_secret_column(s: &Schema, _: &Options) -> Vec<Finding> {
    let mut out = Vec::new();
    for t in s.tables.values() {
        for c in &t.columns {
            let name = c.name.to_lowercase();
            let is_secret_name = SECRET_WORDS
                .iter()
                .any(|w| name == *w || name.ends_with(&format!("_{w}")));
            let text_like = ["text", "varchar", "character", "citext", "bytea", "char"]
                .iter()
                .any(|k| c.ty.contains(k));
            let looks_safe = SAFE_SUFFIXES
                .iter()
                .any(|x| name.ends_with(&format!("_{x}")))
                || name.split('_').any(|part| SAFE_PARTS.contains(&part));
            if is_secret_name && text_like && !looks_safe {
                out.push(finding(
                    "PW011",
                    Severity::Low,
                    t.loc,
                    format!(
                        "column {}.{} is a {} that looks like a secret stored in the clear",
                        t.name, c.name, c.ty
                    ),
                ));
            }
        }
    }
    out
}
