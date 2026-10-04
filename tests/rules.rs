use pgwarden::rules::{Options, Severity};
use pgwarden::scan::scan_sources;

/// Scan one SQL file; returns `RULE:line` for each finding.
fn found(sql: &str) -> Vec<String> {
    scan(&[("a.sql", sql)], &Options::default())
}

fn scan(files: &[(&str, &str)], options: &Options) -> Vec<String> {
    let sources: Vec<(String, String)> = files
        .iter()
        .map(|(n, t)| ((*n).to_string(), (*t).to_string()))
        .collect();
    let (findings, _, _, errors) = scan_sources(&sources, options);
    assert!(errors.is_empty(), "{errors:?}");
    findings
        .iter()
        .map(|(_, f)| format!("{}:{}", f.rule, f.loc.line))
        .collect()
}

fn only(rule: &str, sql: &str) -> Vec<String> {
    found(sql)
        .into_iter()
        .filter(|f| f.starts_with(rule))
        .collect()
}

// ---- PW001 / PW002 ---------------------------------------------------------------

#[test]
fn definer_without_a_pinned_search_path() {
    let bad = "CREATE FUNCTION f() RETURNS void LANGUAGE sql SECURITY DEFINER AS $$ SELECT 1 $$;";
    assert_eq!(only("PW001", bad), vec!["PW001:1"]);
    let set = "CREATE FUNCTION f() RETURNS void LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog AS $$ SELECT 1 $$;";
    assert!(only("PW001", set).is_empty());
    let invoker = "CREATE FUNCTION f() RETURNS void LANGUAGE sql AS $$ SELECT 1 $$;";
    assert!(only("PW001", invoker).is_empty());
    let explicit =
        "CREATE FUNCTION f() RETURNS void SECURITY INVOKER LANGUAGE sql AS $$ SELECT 1 $$;";
    assert!(only("PW001", explicit).is_empty());
}

#[test]
fn security_definer_in_the_body_text_is_not_a_property_of_the_function() {
    let sql = "CREATE FUNCTION f() RETURNS void LANGUAGE plpgsql AS $$ BEGIN -- SECURITY DEFINER set search_path\nEND $$;";
    assert!(only("PW001", sql).is_empty());
}

#[test]
fn alter_function_can_fix_or_break_a_function() {
    let fixed = "CREATE FUNCTION f() RETURNS void LANGUAGE sql SECURITY DEFINER AS $$ SELECT 1 $$;\nALTER FUNCTION f() SET search_path = pg_catalog;";
    assert!(only("PW001", fixed).is_empty());
    let broken = "CREATE FUNCTION f() RETURNS void LANGUAGE sql AS $$ SELECT 1 $$;\nALTER FUNCTION public.f() SECURITY DEFINER;";
    assert_eq!(only("PW001", broken), vec!["PW001:1"]);
}

#[test]
fn definer_public_execute() {
    let create = "CREATE FUNCTION public.f(a int) RETURNS void LANGUAGE sql SECURITY DEFINER SET search_path = '' AS $$ SELECT 1 $$;\n";
    assert_eq!(only("PW002", create), vec!["PW002:1"]);
    assert!(only(
        "PW002",
        &format!("{create}REVOKE ALL ON FUNCTION public.f(integer) FROM PUBLIC;")
    )
    .is_empty());
    assert!(only(
        "PW002",
        &format!("{create}REVOKE EXECUTE ON FUNCTION f FROM public;")
    )
    .is_empty());
    // Granting to one role does not take PUBLIC's grant away.
    assert_eq!(
        only(
            "PW002",
            &format!("{create}GRANT EXECUTE ON FUNCTION f(int) TO app;")
        ),
        vec!["PW002:1"]
    );
    assert!(only(
        "PW002",
        &format!("{create}REVOKE ALL ON ALL FUNCTIONS IN SCHEMA public FROM PUBLIC;")
    )
    .is_empty());
    assert!(only(
        "PW002",
        &format!("ALTER DEFAULT PRIVILEGES REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;\n{create}")
    )
    .is_empty());
}

#[test]
fn a_trigger_function_cannot_be_called_so_public_execute_is_moot() {
    let sql = "CREATE FUNCTION audit() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path = '' AS $$ BEGIN RETURN NEW; END $$;";
    assert!(only("PW002", sql).is_empty());
}

// ---- PW003 / PW004 / PW005 ---------------------------------------------------------

const T: &str = "CREATE TABLE t (id int, tenant_id int);\n";

#[test]
fn policy_without_rls() {
    assert_eq!(
        only("PW003", &format!("{T}CREATE POLICY p ON t USING (true);")),
        vec!["PW003:2"]
    );
    assert!(only(
        "PW003",
        &format!("{T}ALTER TABLE t ENABLE ROW LEVEL SECURITY;\nCREATE POLICY p ON t USING (true);")
    )
    .is_empty());
    assert_eq!(only("PW003", &format!("{T}ALTER TABLE t ENABLE ROW LEVEL SECURITY;\nALTER TABLE t DISABLE ROW LEVEL SECURITY;\nCREATE POLICY p ON t USING (true);")), vec!["PW003:4"]);
}

#[test]
fn rls_without_a_policy() {
    assert_eq!(
        only(
            "PW004",
            &format!("{T}ALTER TABLE ONLY public.t ENABLE ROW LEVEL SECURITY;")
        ),
        vec!["PW004:2"]
    );
    assert!(only("PW004", &format!("{T}ALTER TABLE t ENABLE ROW LEVEL SECURITY;\nCREATE POLICY p ON public.t FOR SELECT TO app USING (true);")).is_empty());
    // A dropped policy leaves the table closed again.
    assert_eq!(only("PW004", &format!("{T}ALTER TABLE t ENABLE ROW LEVEL SECURITY;\nCREATE POLICY p ON t USING (true);\nDROP POLICY p ON t;")), vec!["PW004:2"]);
}

#[test]
fn view_over_an_rls_table() {
    let rls = format!(
        "{T}ALTER TABLE t ENABLE ROW LEVEL SECURITY;\nCREATE POLICY p ON t USING (true);\n"
    );
    assert_eq!(
        only("PW005", &format!("{rls}CREATE VIEW v AS SELECT * FROM t;")),
        vec!["PW005:4"]
    );
    assert_eq!(
        only(
            "PW005",
            &format!("{rls}CREATE VIEW v AS SELECT a.id FROM other a JOIN public.t b ON true;")
        ),
        vec!["PW005:4"]
    );
    assert!(only(
        "PW005",
        &format!("{rls}CREATE VIEW v WITH (security_invoker = true) AS SELECT * FROM t;")
    )
    .is_empty());
    assert!(only(
        "PW005",
        &format!("{rls}CREATE VIEW v WITH (security_invoker) AS SELECT * FROM t;")
    )
    .is_empty());
    assert_eq!(
        only(
            "PW005",
            &format!("{rls}CREATE VIEW v WITH (security_invoker = false) AS SELECT * FROM t;")
        ),
        vec!["PW005:4"]
    );
    assert!(only(
        "PW005",
        &format!("{rls}ALTER TABLE t FORCE ROW LEVEL SECURITY;\nCREATE VIEW v AS SELECT * FROM t;")
    )
    .is_empty());
    assert!(only("PW005", &format!("{T}CREATE VIEW v AS SELECT * FROM t;")).is_empty());
}

// ---- PW006 -------------------------------------------------------------------------

#[test]
fn grants_to_public() {
    let sev = |sql: &str| {
        let sources = vec![("a.sql".to_string(), sql.to_string())];
        let (f, _, _, _) = scan_sources(&sources, &Options::default());
        f.iter()
            .filter(|(_, x)| x.rule == "PW006")
            .map(|(_, x)| x.severity)
            .collect::<Vec<_>>()
    };
    assert_eq!(
        sev("GRANT ALL ON SCHEMA public TO PUBLIC;"),
        vec![Severity::High]
    );
    assert_eq!(
        sev("GRANT CREATE ON SCHEMA s TO public;"),
        vec![Severity::High]
    );
    assert_eq!(
        sev("GRANT USAGE ON SCHEMA s TO public;"),
        Vec::<Severity>::new()
    );
    assert_eq!(
        sev("GRANT INSERT, SELECT ON TABLE t TO PUBLIC;"),
        vec![Severity::High]
    );
    assert_eq!(sev("GRANT SELECT ON t TO PUBLIC;"), vec![Severity::Medium]);
    assert_eq!(
        sev("GRANT SELECT ON ALL TABLES IN SCHEMA s TO PUBLIC;"),
        vec![Severity::Medium]
    );
    assert_eq!(
        sev("ALTER DEFAULT PRIVILEGES IN SCHEMA s GRANT SELECT ON TABLES TO PUBLIC;"),
        vec![Severity::Medium]
    );
    assert_eq!(
        sev("GRANT USAGE ON SEQUENCE sq TO PUBLIC;"),
        vec![Severity::Medium]
    );
    assert_eq!(
        sev("GRANT EXECUTE ON FUNCTION f() TO PUBLIC;"),
        Vec::<Severity>::new()
    );
    assert_eq!(
        sev("GRANT SELECT ON t TO app, PUBLIC;"),
        vec![Severity::Medium]
    );
    assert_eq!(sev("GRANT SELECT ON t TO app;"), Vec::<Severity>::new());
    assert_eq!(
        sev("REVOKE ALL ON SCHEMA public FROM PUBLIC;"),
        Vec::<Severity>::new()
    );
    assert_eq!(
        sev("GRANT SELECT (a, b) ON t TO PUBLIC;"),
        vec![Severity::Medium]
    );
}

#[test]
fn the_grant_message_names_the_target() {
    let sources = vec![(
        "a.sql".to_string(),
        "GRANT INSERT ON invoices TO PUBLIC;".to_string(),
    )];
    let (f, _, _, _) = scan_sources(&sources, &Options::default());
    assert_eq!(
        f[0].1.message,
        "grants PUBLIC write privileges on invoices: any login can change the data"
    );
}

// ---- PW007 / PW008 ------------------------------------------------------------------

#[test]
fn risky_roles() {
    assert_eq!(
        only("PW007", "CREATE ROLE a WITH LOGIN SUPERUSER;"),
        vec!["PW007:1"]
    );
    assert_eq!(only("PW007", "CREATE USER a BYPASSRLS;"), vec!["PW007:1"]);
    assert_eq!(only("PW007", "CREATE ROLE a CREATEROLE;"), vec!["PW007:1"]);
    assert!(only(
        "PW007",
        "CREATE ROLE a WITH LOGIN NOSUPERUSER NOCREATEROLE NOBYPASSRLS;"
    )
    .is_empty());
    assert!(only("PW007", "CREATE ROLE postgres SUPERUSER;").is_empty());
    assert_eq!(
        only("PW007", "CREATE ROLE a;\nALTER ROLE a WITH SUPERUSER;"),
        vec!["PW007:1"]
    );
    assert!(only(
        "PW007",
        "CREATE ROLE a SUPERUSER;\nALTER ROLE a NOSUPERUSER;"
    )
    .is_empty());
    assert!(only("PW007", "CREATE ROLE a SUPERUSER;\nDROP ROLE a;").is_empty());
}

#[test]
fn role_passwords() {
    let sev = |sql: &str| {
        let sources = vec![("a.sql".to_string(), sql.to_string())];
        let (f, _, _, _) = scan_sources(&sources, &Options::default());
        f.iter()
            .filter(|(_, x)| x.rule == "PW008")
            .map(|(_, x)| x.severity)
            .collect::<Vec<_>>()
    };
    assert_eq!(
        sev("CREATE ROLE a LOGIN PASSWORD 'hunter2';"),
        vec![Severity::High]
    );
    assert_eq!(
        sev("CREATE ROLE a LOGIN ENCRYPTED PASSWORD 'hunter2';"),
        vec![Severity::High]
    );
    assert_eq!(
        sev(&format!(
            "CREATE ROLE a PASSWORD 'md5{}';",
            "0123456789abcdef".repeat(2)
        )),
        vec![Severity::Medium]
    );
    assert_eq!(
        sev("CREATE ROLE a PASSWORD 'SCRAM-SHA-256$4096:salt$stored:server';"),
        vec![Severity::Low]
    );
    assert_eq!(
        sev("CREATE ROLE a LOGIN PASSWORD NULL;"),
        Vec::<Severity>::new()
    );
    assert_eq!(sev("CREATE ROLE a LOGIN;"), Vec::<Severity>::new());
    // md5 followed by something that is not 32 hex digits is just a password.
    assert_eq!(
        sev("CREATE ROLE a PASSWORD 'md5notahash';"),
        vec![Severity::High]
    );
}

// ---- PW009 -------------------------------------------------------------------------

#[test]
fn untrusted_code() {
    assert_eq!(
        only(
            "PW009",
            "CREATE FUNCTION f() RETURNS void LANGUAGE plpython3u AS $$ pass $$;"
        ),
        vec!["PW009:1"]
    );
    assert_eq!(
        only(
            "PW009",
            "CREATE FUNCTION f() RETURNS void AS $$ x $$ LANGUAGE 'plperlu';"
        ),
        vec!["PW009:1"]
    );
    assert!(only(
        "PW009",
        "CREATE FUNCTION f() RETURNS void LANGUAGE plpgsql AS $$ BEGIN END $$;"
    )
    .is_empty());
    assert_eq!(
        only(
            "PW009",
            "CREATE EXTENSION IF NOT EXISTS dblink WITH SCHEMA public;"
        ),
        vec!["PW009:1"]
    );
    assert!(only("PW009", "CREATE EXTENSION pgcrypto;").is_empty());
}

// ---- PW010 / PW011 -----------------------------------------------------------------

#[test]
fn tenant_tables() {
    assert_eq!(
        only("PW010", "CREATE TABLE t (id int, tenant_id uuid);"),
        vec!["PW010:1"]
    );
    assert_eq!(
        only("PW010", "CREATE TABLE t (id int, \"Org_ID\" uuid);"),
        vec!["PW010:1"]
    );
    assert!(only("PW010", "CREATE TABLE t (id int, name text);").is_empty());
    assert!(only(
        "PW010",
        "CREATE TABLE t (id int, tenant_id uuid);\nALTER TABLE t ENABLE ROW LEVEL SECURITY;"
    )
    .is_empty());
    // A column added by a later migration counts.
    assert_eq!(
        only(
            "PW010",
            "CREATE TABLE t (id int);\nALTER TABLE t ADD COLUMN tenant_id uuid;"
        ),
        vec!["PW010:1"]
    );
    assert!(only("PW010", "CREATE TABLE t (id int, tenant_id uuid);\nALTER TABLE t RENAME TO t2;\nALTER TABLE t2 ENABLE ROW LEVEL SECURITY;").is_empty());
}

#[test]
fn tenant_columns_are_configurable() {
    let opts = Options {
        tenant_columns: vec!["shop_id".to_string()],
    };
    let sql = "CREATE TABLE a (shop_id int);\nCREATE TABLE b (tenant_id int);";
    assert_eq!(
        scan(&[("a.sql", sql)], &opts)
            .into_iter()
            .filter(|f| f.starts_with("PW010"))
            .collect::<Vec<_>>(),
        vec!["PW010:1"]
    );
}

#[test]
fn secret_columns() {
    assert_eq!(
        only("PW011", "CREATE TABLE u (id int, password text);"),
        vec!["PW011:1"]
    );
    assert_eq!(
        only(
            "PW011",
            "CREATE TABLE u (id int, access_token character varying(255));"
        ),
        vec!["PW011:1"]
    );
    assert_eq!(
        only("PW011", "CREATE TABLE u (api_key varchar);"),
        vec!["PW011:1"]
    );
    assert!(only(
        "PW011",
        "CREATE TABLE u (password_hash text, token_hash bytea, secret_encrypted text);"
    )
    .is_empty());
    assert!(only("PW011", "CREATE TABLE u (token_expires_at timestamptz, password_reset_count int, secret_id bigint);").is_empty());
    assert!(only("PW011", "CREATE TABLE u (password boolean);").is_empty());
}

// ---- schema state across files and statements ---------------------------------------

#[test]
fn state_carries_across_files_in_order() {
    let files = [
        (
            "001.sql",
            "CREATE TABLE t (id int, tenant_id int);\nCREATE POLICY p ON t USING (true);",
        ),
        ("002.sql", "ALTER TABLE t ENABLE ROW LEVEL SECURITY;"),
    ];
    assert!(scan(&files, &Options::default()).is_empty());
    let only_first = scan(&files[..1], &Options::default());
    assert!(only_first.contains(&"PW003:2".to_string()));
}

#[test]
fn a_dropped_table_takes_its_policies_with_it() {
    let sql = "CREATE TABLE t (id int);\nCREATE POLICY p ON t USING (true);\nDROP TABLE IF EXISTS public.t CASCADE;";
    assert!(found(sql).is_empty());
}

#[test]
fn create_or_replace_function_replaces() {
    let sql = "CREATE FUNCTION f() RETURNS void LANGUAGE sql SECURITY DEFINER AS $$ SELECT 1 $$;\nCREATE OR REPLACE FUNCTION f() RETURNS void LANGUAGE sql AS $$ SELECT 1 $$;";
    assert!(only("PW001", sql).is_empty());
}

#[test]
fn create_table_shapes_are_tolerated() {
    // Partitions, CTAS, temp tables, constraints and generated columns must not panic or lose columns.
    let sql = "CREATE TABLE a PARTITION OF b FOR VALUES IN (1);\nCREATE TABLE c AS SELECT 1;\nCREATE TEMP TABLE d (x int);\n\
               CREATE TABLE e (id int GENERATED ALWAYS AS IDENTITY, tenant_id int NOT NULL DEFAULT 5, CONSTRAINT pk PRIMARY KEY (id), CHECK (id > 0));";
    assert_eq!(only("PW010", sql), vec!["PW010:4"]);
}

#[test]
fn a_quoted_and_a_bare_name_are_the_same_table() {
    let sql =
        "CREATE TABLE \"t\" (tenant_id int);\nALTER TABLE public.t ENABLE ROW LEVEL SECURITY;";
    assert!(only("PW010", sql).is_empty());
}

// ---- suppression -------------------------------------------------------------------

#[test]
fn a_suppression_needs_a_reason() {
    let with_function_finding = |c: &str| {
        let src = vec![("a.sql".to_string(), format!("{c}\nCREATE FUNCTION g() RETURNS void LANGUAGE sql SECURITY DEFINER AS $$ SELECT 1 $$;\nREVOKE ALL ON FUNCTION g() FROM PUBLIC;"))];
        let (found, suppressed, _, _) = scan_sources(&src, &Options::default());
        (
            found.iter().map(|(_, x)| x.rule).collect::<Vec<_>>(),
            suppressed,
        )
    };
    assert_eq!(
        with_function_finding("-- pgwarden:ignore PW001 -- the caller's role pins it"),
        (vec![], 1)
    );
    assert_eq!(
        with_function_finding("-- pgwarden:ignore PW001: reviewed"),
        (vec![], 1)
    );
    assert_eq!(
        with_function_finding("-- pgwarden:ignore PW001"),
        (vec!["PW000", "PW001"], 0)
    );
    assert_eq!(
        with_function_finding("-- pgwarden:ignore PW001 --   "),
        (vec!["PW000", "PW001"], 0)
    );
    assert_eq!(
        with_function_finding("-- pgwarden:ignore PW002 -- wrong rule"),
        (vec!["PW001"], 0)
    );
    assert_eq!(
        with_function_finding("-- pgwarden:ignore PW0011 -- almost"),
        (vec!["PW001"], 0)
    );
    assert_eq!(
        with_function_finding("-- unrelated comment"),
        (vec!["PW001"], 0)
    );
}

#[test]
fn a_suppression_covers_only_the_statement_below_it() {
    let sql = "-- pgwarden:ignore PW001 -- reviewed\nCREATE FUNCTION a() RETURNS void LANGUAGE sql SECURITY DEFINER AS $$ SELECT 1 $$;\nCREATE FUNCTION b() RETURNS void LANGUAGE sql SECURITY DEFINER AS $$ SELECT 1 $$;\nREVOKE ALL ON ALL FUNCTIONS IN SCHEMA public FROM PUBLIC;";
    assert_eq!(found(sql), vec!["PW001:3"]);
}

#[test]
fn findings_are_ordered_by_file_then_line() {
    let files = [
        ("b.sql", "CREATE TABLE t (tenant_id int);"),
        ("a.sql", "CREATE ROLE r SUPERUSER;"),
    ];
    let sources: Vec<(String, String)> = files
        .iter()
        .map(|(n, t)| ((*n).to_string(), (*t).to_string()))
        .collect();
    let (f, _, _, _) = scan_sources(&sources, &Options::default());
    assert_eq!(
        f.iter()
            .map(|(n, x)| format!("{n}:{}", x.rule))
            .collect::<Vec<_>>(),
        vec!["a.sql:PW007", "b.sql:PW010"]
    );
}

#[test]
fn every_rule_is_documented_and_ids_are_ordered() {
    let mut prev = "";
    for r in pgwarden::rules::RULES {
        assert!(r.id > prev, "{} out of order", r.id);
        prev = r.id;
        assert!(
            !r.name.is_empty() && !r.title.is_empty() && !r.why.is_empty() && !r.fix.is_empty(),
            "{}",
            r.id
        );
    }
}

// Each of these came from running pgwarden on real schemas (pagila, Supabase).

#[test]
fn a_customer_or_account_column_is_not_a_tenant_marker_by_default() {
    assert!(only(
        "PW010",
        "CREATE TABLE rental (id int, customer_id int, account_id int);"
    )
    .is_empty());
    assert_eq!(
        only("PW010", "CREATE TABLE rental (id int, workspace_id int);"),
        vec!["PW010:1"]
    );
}

#[test]
fn a_column_named_encrypted_or_hashed_is_not_a_plaintext_secret() {
    assert!(only("PW011", "CREATE TABLE users (encrypted_password character varying(255), hashed_token text, token_digest text);").is_empty());
    assert_eq!(
        only(
            "PW011",
            "CREATE TABLE users (confirmation_token character varying(255));"
        ),
        vec!["PW011:1"]
    );
}

#[test]
fn the_builtin_postgres_role_is_not_reported_for_its_attributes() {
    assert!(only(
        "PW007",
        "ALTER ROLE postgres WITH SUPERUSER CREATEROLE BYPASSRLS;"
    )
    .is_empty());
    assert_eq!(
        only("PW007", "CREATE ROLE supabase_admin SUPERUSER CREATEROLE;").len(),
        2
    );
}

// Found by mutation checks: nothing yet pinned these two.

#[test]
fn only_md5_plus_exactly_32_hex_digits_is_an_md5_hash() {
    let sev = |pw: &str| {
        let sources = vec![(
            "a.sql".to_string(),
            format!("CREATE ROLE a PASSWORD '{pw}';"),
        )];
        let (f, _, _, _) = scan_sources(&sources, &Options::default());
        f.iter()
            .filter(|(_, x)| x.rule == "PW008")
            .map(|(_, x)| x.severity)
            .collect::<Vec<_>>()
    };
    assert_eq!(
        sev(&format!("md5{}", "ab".repeat(16))),
        vec![Severity::Medium]
    );
    assert_eq!(
        sev(&format!("md5{}", "ab".repeat(20))),
        vec![Severity::High],
        "40 hex digits is a password that starts with md5"
    );
    assert_eq!(
        sev(&format!("md5{}", "ab".repeat(15))),
        vec![Severity::High]
    );
}

#[test]
fn granting_execute_to_public_is_not_a_revoke() {
    let f = "CREATE FUNCTION f() RETURNS void LANGUAGE sql SECURITY DEFINER SET search_path = '' AS $$ SELECT 1 $$;\n";
    assert_eq!(
        only(
            "PW002",
            &format!("{f}GRANT EXECUTE ON FUNCTION f() TO PUBLIC;")
        ),
        vec!["PW002:1"]
    );
}
