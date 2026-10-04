use pgwarden::lexer::{lex, Tok};
use pgwarden::schema::split;

fn kinds(sql: &str) -> Vec<Tok> {
    lex(sql)
        .expect("lexes")
        .into_iter()
        .map(|t| t.tok)
        .collect()
}

fn word(w: &str) -> Tok {
    Tok::Word(w.to_string())
}

fn stmts(sql: &str) -> usize {
    split(&lex(sql).expect("lexes"), 0).len()
}

#[test]
fn words_are_folded_to_lower_case_and_quoted_identifiers_are_not() {
    assert_eq!(
        kinds(r#"CREATE TABLE "MixedCase" (Id int)"#)[2],
        Tok::Ident("MixedCase".into())
    );
    assert_eq!(kinds("CREATE")[0], word("create"));
}

#[test]
fn a_semicolon_inside_a_string_does_not_end_the_statement() {
    assert_eq!(stmts("SELECT 'a;b'; SELECT 2;"), 2);
}

#[test]
fn a_semicolon_inside_a_dollar_quoted_body_does_not_end_the_statement() {
    let sql = "CREATE FUNCTION f() RETURNS void LANGUAGE plpgsql AS $$ BEGIN PERFORM 1; PERFORM 2; END; $$; SELECT 1;";
    assert_eq!(stmts(sql), 2);
    assert!(kinds(sql)
        .iter()
        .any(|t| matches!(t, Tok::Dollar(body) if body.contains("PERFORM 2;"))));
}

#[test]
fn tagged_dollar_quotes_must_match_their_tag() {
    let sql = "SELECT $fn$ has $$ inside; and $other$ too $fn$; SELECT 2;";
    let toks = kinds(sql);
    assert!(matches!(&toks[1], Tok::Dollar(b) if b.contains("$$ inside; and $other$ too")));
    assert_eq!(stmts(sql), 2);
}

#[test]
fn a_positional_parameter_is_not_a_dollar_quote() {
    let toks = kinds("SELECT $1, $2 FROM t; SELECT 3;");
    assert!(!toks.iter().any(|t| matches!(t, Tok::Dollar(_))));
    assert_eq!(stmts("SELECT $1, $2 FROM t; SELECT 3;"), 2);
}

#[test]
fn comments_nest_and_are_skipped() {
    let toks =
        kinds("SELECT /* outer /* inner; */ still outer; */ 1; -- trailing; comment\nSELECT 2;");
    assert_eq!(toks.iter().filter(|t| **t == Tok::Punct(';')).count(), 2);
    assert!(!toks
        .iter()
        .any(|t| matches!(t, Tok::Word(w) if w == "inner" || w == "trailing")));
}

#[test]
fn a_standard_string_keeps_its_backslashes_and_an_e_string_does_not() {
    assert_eq!(kinds(r"SELECT 'a\'; SELECT 2;")[1], Tok::Str("a\\".into()));
    assert_eq!(stmts(r"SELECT 'a\'; SELECT 2;"), 2);
    // E'' treats \' as an escaped quote, so this string runs to the last quote.
    let toks = kinds(r"SELECT E'it\'s; fine'; SELECT 2;");
    assert_eq!(toks[1], Tok::Str("it's; fine".into()));
    assert_eq!(stmts(r"SELECT E'it\'s; fine'; SELECT 2;"), 2);
}

#[test]
fn doubled_quotes_are_an_escaped_quote() {
    assert_eq!(kinds("SELECT 'it''s'")[1], Tok::Str("it's".into()));
    assert_eq!(kinds(r#"SELECT "a""b""#)[1], Tok::Ident("a\"b".into()));
}

#[test]
fn copy_data_is_skipped_up_to_the_terminator() {
    let sql = "COPY public.t (a, b) FROM stdin;\n1\tCREATE TABLE evil (x int);\n2\t';--\n\\.\nCREATE TABLE real (x int);\n";
    let toks = kinds(sql);
    assert!(!toks
        .iter()
        .any(|t| matches!(t, Tok::Word(w) if w == "evil")));
    assert!(toks.contains(&word("real")));
    assert_eq!(stmts(sql), 2);
}

#[test]
fn copy_to_stdout_is_an_ordinary_statement() {
    assert_eq!(stmts("COPY t TO stdout;\nSELECT 1;\n"), 2);
}

#[test]
fn psql_meta_commands_are_skipped() {
    let toks = kinds("\\connect mydb\n\\restrict abc123\nSELECT 1;\n\\unrestrict abc123\n");
    assert_eq!(
        toks,
        vec![word("select"), Tok::Num("1".into()), Tok::Punct(';')]
    );
}

#[test]
fn line_numbers_follow_multi_line_tokens() {
    let toks = lex("SELECT $$a\nb\nc$$;\n/* x\ny */\nSELECT 'p\nq';\nSELECT 3;").unwrap();
    let line_of = |w: &str| toks.iter().rev().find(|t| t.tok == word(w)).map(|t| t.line);
    assert_eq!(
        toks.iter()
            .filter(|t| t.tok == word("select"))
            .map(|t| t.line)
            .collect::<Vec<_>>(),
        vec![1, 6, 8]
    );
    assert_eq!(line_of("select"), Some(8));
}

#[test]
fn begin_atomic_bodies_are_one_statement() {
    let sql = "CREATE FUNCTION f() RETURNS int LANGUAGE sql BEGIN ATOMIC SELECT 1; SELECT 2; END; SELECT 3;";
    assert_eq!(stmts(sql), 2);
    // An ordinary BEGIN (a transaction) is not an atomic body.
    assert_eq!(stmts("BEGIN; SELECT 1; COMMIT;"), 3);
}

#[test]
fn unterminated_input_is_an_error_with_a_line() {
    for (sql, expect) in [
        (
            "SELECT 1;\nSELECT 'oops",
            "line 2: unterminated string literal",
        ),
        ("/* never closed", "line 1: unterminated /* comment"),
        (
            "SELECT $$ never closed",
            "line 1: unterminated dollar-quoted string $$",
        ),
        ("SELECT \"never", "line 1: unterminated quoted identifier"),
        (
            "COPY t FROM stdin;\n1\n2\n",
            "COPY data is never terminated",
        ),
    ] {
        let err = lex(sql).unwrap_err().to_string();
        assert!(err.contains(expect), "{sql:?} gave {err:?}");
    }
}

#[test]
fn crlf_line_endings_are_handled() {
    let sql = "SELECT 1;\r\nCOPY t FROM stdin;\r\n1\r\n\\.\r\nSELECT 2;\r\n";
    assert_eq!(stmts(sql), 3);
}

#[test]
fn non_ascii_identifiers_and_strings_are_kept() {
    assert_eq!(
        kinds("SELECT 'café', naïve FROM t")[1],
        Tok::Str("café".into())
    );
    assert!(kinds("SELECT naïve").contains(&word("naïve")));
}
