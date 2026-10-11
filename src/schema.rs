//! The schema as the SQL leaves it.
//!
//! Statements are applied in order, so a migration that creates a table in one
//! file, enables row-level security in a second and drops a policy in a third is
//! judged by where it ends up, not by any one file. Names are folded the way
//! PostgreSQL folds them, and `public.x` and `x` are the same table.

use crate::lexer::{Tok, Token};
use std::collections::BTreeMap;

/// Where something was defined: an index into the list of files, and a line.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Loc {
    pub file: usize,
    pub line: usize,
}

#[derive(Debug, Clone)]
pub struct Statement {
    pub tokens: Vec<Token>,
    pub file: usize,
}

impl Statement {
    pub fn loc(&self) -> Loc {
        Loc {
            file: self.file,
            line: self.tokens.first().map_or(1, |t| t.line),
        }
    }
}

/// Split tokens into statements at `;`, except inside a `BEGIN ATOMIC ... END`
/// function body, whose own statements end in `;` too.
pub fn split(tokens: &[Token], file: usize) -> Vec<Statement> {
    let mut out = Vec::new();
    let mut current: Vec<Token> = Vec::new();
    let mut atomic = false;
    for (i, t) in tokens.iter().enumerate() {
        if let Tok::Word(w) = &t.tok {
            if w == "begin"
                && matches!(tokens.get(i + 1).map(|n| &n.tok), Some(Tok::Word(a)) if a == "atomic")
            {
                atomic = true;
            }
        }
        if t.tok == Tok::Punct(';') {
            let ends_body =
                matches!(current.last().map(|n| &n.tok), Some(Tok::Word(w)) if w == "end");
            if atomic && !ends_body {
                current.push(t.clone());
                continue;
            }
            atomic = false;
            if !current.is_empty() {
                out.push(Statement {
                    tokens: std::mem::take(&mut current),
                    file,
                });
            }
            continue;
        }
        current.push(t.clone());
    }
    if !current.is_empty() {
        out.push(Statement {
            tokens: current,
            file,
        });
    }
    out
}

#[derive(Debug, Clone)]
pub struct Column {
    pub name: String,
    pub ty: String,
}

#[derive(Debug, Clone)]
pub struct Table {
    pub name: String,
    pub loc: Loc,
    pub columns: Vec<Column>,
    /// Where row-level security was enabled, if it is.
    pub rls: Option<Loc>,
    pub forced: bool,
}

#[derive(Debug, Clone)]
pub struct Policy {
    pub name: String,
    pub table: String,
    pub loc: Loc,
}

#[derive(Debug, Clone)]
pub struct Function {
    pub name: String,
    pub loc: Loc,
    pub definer: bool,
    pub search_path_set: bool,
    pub language: String,
    /// Trigger functions cannot be called directly, so PUBLIC execute is moot.
    pub returns_trigger: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Table,
    Sequence,
    Function,
    Schema,
    Other,
}

#[derive(Debug, Clone)]
pub struct Grant {
    pub loc: Loc,
    pub revoke: bool,
    /// Lower-cased privilege names; `all` for ALL [PRIVILEGES].
    pub privileges: Vec<String>,
    pub kind: Kind,
    /// Objects named (normalised), or the schema for `ALL ... IN SCHEMA`.
    pub objects: Vec<String>,
    pub all_in_schema: bool,
    pub grantees: Vec<String>,
    /// Set for ALTER DEFAULT PRIVILEGES.
    pub default_privileges: bool,
}

#[derive(Debug, Clone)]
pub struct Role {
    pub name: String,
    pub loc: Loc,
    pub superuser: bool,
    pub createrole: bool,
    pub bypassrls: bool,
    pub verifier: Option<String>,
}

#[derive(Debug, Clone)]
pub struct View {
    pub name: String,
    pub loc: Loc,
    pub security_invoker: bool,
    /// Names that appear after FROM or JOIN, normalised.
    pub reads: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct Extension {
    pub name: String,
    pub loc: Loc,
}

#[derive(Debug, Default)]
pub struct Schema {
    pub tables: BTreeMap<String, Table>,
    pub policies: Vec<Policy>,
    pub functions: BTreeMap<String, Function>,
    pub grants: Vec<Grant>,
    pub roles: BTreeMap<String, Role>,
    pub views: BTreeMap<String, View>,
    pub extensions: Vec<Extension>,
}

// ---- a cursor over a statement's tokens ---------------------------------------

struct Cur<'a> {
    toks: &'a [Token],
    i: usize,
}

impl<'a> Cur<'a> {
    fn new(toks: &'a [Token]) -> Self {
        Cur { toks, i: 0 }
    }

    fn peek(&self) -> Option<&'a Tok> {
        self.toks.get(self.i).map(|t| &t.tok)
    }

    fn word(&self) -> Option<&'a str> {
        match self.peek() {
            Some(Tok::Word(w)) => Some(w),
            _ => None,
        }
    }

    fn eat(&mut self, w: &str) -> bool {
        if self.word() == Some(w) {
            self.i += 1;
            true
        } else {
            false
        }
    }

    fn eat_all(&mut self, ws: &[&str]) -> bool {
        let save = self.i;
        for w in ws {
            if !self.eat(w) {
                self.i = save;
                return false;
            }
        }
        true
    }

    fn eat_punct(&mut self, c: char) -> bool {
        if self.peek() == Some(&Tok::Punct(c)) {
            self.i += 1;
            true
        } else {
            false
        }
    }

    /// A possibly schema-qualified name, normalised.
    fn name(&mut self) -> Option<String> {
        let mut parts = Vec::new();
        loop {
            match self.peek() {
                Some(Tok::Word(w)) => parts.push(w.clone()),
                Some(Tok::Ident(w)) => parts.push(w.clone()),
                _ => break,
            }
            self.i += 1;
            if self.peek() == Some(&Tok::Punct('.')) {
                self.i += 1;
            } else {
                break;
            }
        }
        if parts.is_empty() {
            None
        } else {
            Some(normalise(&parts))
        }
    }

    /// Skip a balanced `( ... )` if the cursor is on `(`.
    fn skip_parens(&mut self) {
        if self.peek() != Some(&Tok::Punct('(')) {
            return;
        }
        let mut depth = 0;
        while let Some(t) = self.peek() {
            match t {
                Tok::Punct('(') => depth += 1,
                Tok::Punct(')') => {
                    depth -= 1;
                    if depth == 0 {
                        self.i += 1;
                        return;
                    }
                }
                _ => {}
            }
            self.i += 1;
        }
    }

    fn rest(&self) -> &'a [Token] {
        &self.toks[self.i.min(self.toks.len())..]
    }
}

/// `public.x` is `x`; other schemas keep their qualifier.
pub fn normalise(parts: &[String]) -> String {
    let joined = parts.join(".");
    joined
        .strip_prefix("public.")
        .map(str::to_string)
        .unwrap_or(joined)
}

fn words(toks: &[Token]) -> Vec<&str> {
    toks.iter()
        .filter_map(|t| match &t.tok {
            Tok::Word(w) => Some(w.as_str()),
            _ => None,
        })
        .collect()
}

// ---- building the schema ------------------------------------------------------

impl Schema {
    pub fn build(statements: &[Statement]) -> Schema {
        let mut schema = Schema::default();
        for st in statements {
            schema.apply(st);
        }
        schema
    }

    fn apply(&mut self, st: &Statement) {
        let loc = st.loc();
        let mut c = Cur::new(&st.tokens);
        match c.word() {
            Some("create") => {
                c.i += 1;
                self.create(&mut c, loc);
            }
            Some("alter") => {
                c.i += 1;
                self.alter(&mut c, loc);
            }
            Some("drop") => {
                c.i += 1;
                self.drop(&mut c);
            }
            Some("grant") => {
                c.i += 1;
                self.grant(&mut c, loc, false, false);
            }
            Some("revoke") => {
                c.i += 1;
                self.grant(&mut c, loc, true, false);
            }
            _ => {}
        }
    }

    fn create(&mut self, c: &mut Cur<'_>, loc: Loc) {
        let or_replace = c.eat_all(&["or", "replace"]);
        let _ = or_replace;
        // Skip modifiers that sit between CREATE and the object kind.
        while matches!(
            c.word(),
            Some(
                "temporary"
                    | "temp"
                    | "unlogged"
                    | "global"
                    | "local"
                    | "recursive"
                    | "materialized"
                    | "constraint"
            )
        ) {
            c.i += 1;
        }
        match c.word() {
            Some("table") => {
                c.i += 1;
                self.create_table(c, loc);
            }
            Some("policy") => {
                c.i += 1;
                if let Some(name) = c.name() {
                    if c.eat("on") {
                        if let Some(table) = c.name() {
                            self.policies.push(Policy { name, table, loc });
                        }
                    }
                }
            }
            Some("function" | "procedure") => {
                c.i += 1;
                self.create_function(c, loc);
            }
            Some("view") => {
                c.i += 1;
                self.create_view(c, loc);
            }
            Some("role" | "user" | "group") => {
                c.i += 1;
                if let Some(name) = c.name() {
                    let mut role = Role {
                        name: name.clone(),
                        loc,
                        superuser: false,
                        createrole: false,
                        bypassrls: false,
                        verifier: None,
                    };
                    role_attributes(c.rest(), &mut role);
                    self.roles.insert(name, role);
                }
            }
            Some("extension") => {
                c.i += 1;
                c.eat_all(&["if", "not", "exists"]);
                if let Some(name) = c.name() {
                    self.extensions.push(Extension { name, loc });
                }
            }
            _ => {}
        }
    }

    fn create_table(&mut self, c: &mut Cur<'_>, loc: Loc) {
        c.eat_all(&["if", "not", "exists"]);
        let Some(name) = c.name() else { return };
        // `CREATE TABLE a PARTITION OF b` and `AS SELECT` have no column list here.
        let mut columns = Vec::new();
        if c.eat_punct('(') {
            let mut depth = 1;
            let mut item: Vec<&Token> = Vec::new();
            while let Some(t) = c.toks.get(c.i) {
                c.i += 1;
                match t.tok {
                    Tok::Punct('(') => depth += 1,
                    Tok::Punct(')') => {
                        depth -= 1;
                        if depth == 0 {
                            break;
                        }
                    }
                    _ => {}
                }
                if depth == 1 && t.tok == Tok::Punct(',') {
                    if let Some(col) = column(&item) {
                        columns.push(col);
                    }
                    item.clear();
                } else {
                    item.push(t);
                }
            }
            if let Some(col) = column(&item) {
                columns.push(col);
            }
        }
        self.tables.insert(
            name.clone(),
            Table {
                name,
                loc,
                columns,
                rls: None,
                forced: false,
            },
        );
    }

    fn create_function(&mut self, c: &mut Cur<'_>, loc: Loc) {
        let Some(name) = c.name() else { return };
        let rest = c.rest();
        let mut f = Function {
            name: name.clone(),
            loc,
            definer: false,
            search_path_set: false,
            language: String::new(),
            returns_trigger: false,
        };
        function_options(rest, &mut f);
        self.functions.insert(name, f);
    }

    fn create_view(&mut self, c: &mut Cur<'_>, loc: Loc) {
        c.eat_all(&["if", "not", "exists"]);
        let Some(name) = c.name() else { return };
        let rest = c.rest();
        let mut security_invoker = false;
        // WITH ( security_invoker = true | on | 1 )
        for (k, t) in rest.iter().enumerate() {
            if t.tok == Tok::Word("security_invoker".into()) {
                let value = rest[k + 1..].iter().find_map(|v| match &v.tok {
                    Tok::Word(w) => Some(w.as_str()),
                    Tok::Num(n) => Some(n.as_str()),
                    Tok::Str(s) => Some(s.as_str()),
                    _ => None,
                });
                security_invoker = !matches!(value, Some("false" | "off" | "0" | "no"));
            }
        }
        let mut reads = Vec::new();
        let mut k = 0;
        while k < rest.len() {
            if matches!(&rest[k].tok, Tok::Word(w) if w == "from" || w == "join") {
                let mut cur = Cur::new(&rest[k + 1..]);
                cur.eat("only");
                if let Some(n) = cur.name() {
                    reads.push(n);
                }
            }
            k += 1;
        }
        self.views.insert(
            name.clone(),
            View {
                name,
                loc,
                security_invoker,
                reads,
            },
        );
    }

    fn alter(&mut self, c: &mut Cur<'_>, loc: Loc) {
        match c.word() {
            Some("table") => {
                c.i += 1;
                c.eat_all(&["if", "exists"]);
                c.eat("only");
                let Some(name) = c.name() else { return };
                let rest = words(c.rest());
                let find = |w: &[&str]| rest.windows(w.len()).any(|x| x == w);
                if let Some(table) = self.tables.get_mut(&name) {
                    if find(&["enable", "row", "level", "security"]) {
                        table.rls = Some(loc);
                    }
                    if find(&["disable", "row", "level", "security"]) {
                        table.rls = None;
                    }
                    if find(&["no", "force", "row", "level", "security"]) {
                        table.forced = false;
                    } else if find(&["force", "row", "level", "security"]) {
                        table.forced = true;
                    }
                    if find(&["add", "column"]) || rest.first() == Some(&"add") {
                        add_column(table, c.rest());
                    }
                }
                if let Some(pos) = rest.iter().position(|w| *w == "rename") {
                    if rest.get(pos + 1) == Some(&"to") {
                        if let Some(Tok::Word(new) | Tok::Ident(new)) = c
                            .rest()
                            .iter()
                            .filter(|t| !matches!(t.tok, Tok::Punct(_)))
                            .next_back()
                            .map(|t| &t.tok)
                        {
                            if let Some(mut table) = self.tables.remove(&name) {
                                let renamed = new.clone();
                                table.name = renamed.clone();
                                self.tables.insert(renamed, table);
                            }
                        }
                    }
                }
            }
            Some("function" | "procedure") => {
                c.i += 1;
                let Some(name) = c.name() else { return };
                if let Some(f) = self.functions.get_mut(&name) {
                    function_options(c.rest(), f);
                }
            }
            Some("role" | "user") => {
                c.i += 1;
                let Some(name) = c.name() else { return };
                let role = self.roles.entry(name.clone()).or_insert(Role {
                    name,
                    loc,
                    superuser: false,
                    createrole: false,
                    bypassrls: false,
                    verifier: None,
                });
                role_attributes(c.rest(), role);
            }
            Some("default") => {
                c.i += 1;
                if c.eat("privileges") {
                    // ALTER DEFAULT PRIVILEGES [FOR ROLE x] [IN SCHEMA y] GRANT ...
                    while let Some(w) = c.word() {
                        if w == "grant" || w == "revoke" {
                            break;
                        }
                        c.i += 1;
                    }
                    let revoke = c.word() == Some("revoke");
                    c.i += 1;
                    self.grant(c, loc, revoke, true);
                }
            }
            _ => {}
        }
    }

    fn drop(&mut self, c: &mut Cur<'_>) {
        let kind = c.word().map(str::to_string);
        c.i += 1;
        c.eat_all(&["if", "exists"]);
        match kind.as_deref() {
            Some("table") => {
                while let Some(n) = c.name() {
                    self.tables.remove(&n);
                    self.policies.retain(|p| p.table != n);
                    if !c.eat_punct(',') {
                        break;
                    }
                }
            }
            Some("policy") => {
                if let Some(name) = c.name() {
                    if c.eat("on") {
                        if let Some(table) = c.name() {
                            self.policies
                                .retain(|p| !(p.name == name && p.table == table));
                        }
                    }
                }
            }
            Some("function" | "procedure") => {
                if let Some(n) = c.name() {
                    self.functions.remove(&n);
                }
            }
            Some("view") => {
                if let Some(n) = c.name() {
                    self.views.remove(&n);
                }
            }
            Some("role" | "user") => {
                if let Some(n) = c.name() {
                    self.roles.remove(&n);
                }
            }
            _ => {}
        }
    }

    /// GRANT / REVOKE, and the body of ALTER DEFAULT PRIVILEGES.
    fn grant(&mut self, c: &mut Cur<'_>, loc: Loc, revoke: bool, default_privileges: bool) {
        if revoke {
            c.eat_all(&["grant", "option", "for"]);
        }
        let mut privileges = Vec::new();
        while let Some(t) = c.peek() {
            match t {
                Tok::Word(w) if w == "on" => break,
                Tok::Word(w) if w == "to" || w == "from" => break,
                Tok::Word(w) => {
                    if w == "all" {
                        privileges.push("all".to_string());
                        c.i += 1;
                        c.eat("privileges");
                        continue;
                    }
                    privileges.push(w.clone());
                    c.i += 1;
                    if c.peek() == Some(&Tok::Punct('(')) {
                        c.skip_parens();
                    }
                }
                _ => c.i += 1,
            }
        }
        let mut kind = Kind::Table;
        let mut objects = Vec::new();
        let mut all_in_schema = false;
        if c.eat("on") {
            if c.eat("all") {
                all_in_schema = true;
                kind = match c.word() {
                    Some("tables") => Kind::Table,
                    Some("sequences") => Kind::Sequence,
                    Some("functions" | "routines" | "procedures") => Kind::Function,
                    _ => Kind::Other,
                };
                c.i += 1;
                c.eat_all(&["in", "schema"]);
            } else if default_privileges {
                kind = match c.word() {
                    Some("tables") => Kind::Table,
                    Some("sequences") => Kind::Sequence,
                    Some("functions" | "routines") => Kind::Function,
                    Some("schemas") => Kind::Schema,
                    _ => Kind::Other,
                };
                c.i += 1;
            } else {
                kind = match c.word() {
                    Some("table") => {
                        c.i += 1;
                        Kind::Table
                    }
                    Some("sequence") => {
                        c.i += 1;
                        Kind::Sequence
                    }
                    Some("function" | "procedure" | "routine") => {
                        c.i += 1;
                        Kind::Function
                    }
                    Some("schema") => {
                        c.i += 1;
                        Kind::Schema
                    }
                    Some(
                        "database" | "domain" | "language" | "type" | "tablespace" | "foreign"
                        | "large",
                    ) => Kind::Other,
                    _ => Kind::Table,
                };
            }
            // ALTER DEFAULT PRIVILEGES names a kind of object, not objects.
            if !default_privileges {
                while let Some(n) = c.name() {
                    objects.push(n);
                    // A function's argument list.
                    if c.peek() == Some(&Tok::Punct('(')) {
                        c.skip_parens();
                    }
                    if !c.eat_punct(',') {
                        break;
                    }
                }
            }
        }
        let mut grantees = Vec::new();
        if c.eat("to") || c.eat("from") {
            c.eat("group");
            while let Some(t) = c.peek() {
                match t {
                    Tok::Word(w)
                        if w == "with" || w == "granted" || w == "cascade" || w == "restrict" =>
                    {
                        break
                    }
                    Tok::Word(w) => grantees.push(w.clone()),
                    Tok::Ident(w) => grantees.push(w.clone()),
                    _ => {}
                }
                c.i += 1;
            }
        }
        self.grants.push(Grant {
            loc,
            revoke,
            privileges,
            kind,
            objects,
            all_in_schema,
            grantees,
            default_privileges,
        });
    }
}

fn column(item: &[&Token]) -> Option<Column> {
    let first = item.first()?;
    let name = match &first.tok {
        Tok::Word(w) => {
            if matches!(
                w.as_str(),
                "constraint"
                    | "primary"
                    | "unique"
                    | "check"
                    | "foreign"
                    | "like"
                    | "exclude"
                    | "period"
            ) {
                return None;
            }
            w.clone()
        }
        Tok::Ident(w) => w.clone(),
        _ => return None,
    };
    let mut ty = Vec::new();
    for t in &item[1..] {
        match &t.tok {
            Tok::Word(w)
                if matches!(
                    w.as_str(),
                    "not"
                        | "null"
                        | "default"
                        | "references"
                        | "check"
                        | "primary"
                        | "unique"
                        | "generated"
                        | "collate"
                        | "constraint"
                ) =>
            {
                break
            }
            Tok::Word(w) => ty.push(w.clone()),
            _ => {}
        }
    }
    Some(Column {
        name,
        ty: ty.join(" "),
    })
}

fn add_column(table: &mut Table, rest: &[Token]) {
    let refs: Vec<&Token> = rest.iter().collect();
    // After `ADD [COLUMN] [IF NOT EXISTS]`
    let mut k = 0;
    while k < refs.len() {
        if matches!(&refs[k].tok, Tok::Word(w) if w == "add") {
            k += 1;
            if matches!(refs.get(k).map(|t| &t.tok), Some(Tok::Word(w)) if w == "column") {
                k += 1;
            }
            while matches!(refs.get(k).map(|t| &t.tok), Some(Tok::Word(w)) if w == "if" || w == "not" || w == "exists")
            {
                k += 1;
            }
            if let Some(col) = column(&refs[k..]) {
                table.columns.push(col);
            }
            return;
        }
        k += 1;
    }
}

fn function_options(rest: &[Token], f: &mut Function) {
    let mut depth = 0;
    for (k, t) in rest.iter().enumerate() {
        match &t.tok {
            Tok::Punct('(') => depth += 1,
            Tok::Punct(')') => depth -= 1,
            Tok::Word(w) if depth == 0 => match w.as_str() {
                "security" => match rest.get(k + 1).map(|n| &n.tok) {
                    Some(Tok::Word(x)) if x == "definer" => f.definer = true,
                    Some(Tok::Word(x)) if x == "invoker" => f.definer = false,
                    _ => {}
                },
                "set" => {
                    if matches!(rest.get(k + 1).map(|n| &n.tok), Some(Tok::Word(x)) if x == "search_path")
                    {
                        f.search_path_set = true;
                    }
                }
                "returns" => {
                    if matches!(rest.get(k + 1).map(|n| &n.tok), Some(Tok::Word(x)) if x == "trigger" || x == "event_trigger")
                    {
                        f.returns_trigger = true;
                    }
                }
                "language" => {
                    if let Some(Tok::Word(x) | Tok::Str(x)) = rest.get(k + 1).map(|n| &n.tok) {
                        f.language = x.to_lowercase();
                    }
                }
                _ => {}
            },
            _ => {}
        }
    }
}

fn role_attributes(rest: &[Token], role: &mut Role) {
    let mut k = 0;
    while k < rest.len() {
        if let Tok::Word(w) = &rest[k].tok {
            let negated = k > 0 && matches!(&rest[k - 1].tok, Tok::Word(p) if p == "no");
            match w.as_str() {
                "superuser" => role.superuser = !negated,
                "nosuperuser" => role.superuser = false,
                "createrole" => role.createrole = !negated,
                "nocreaterole" => role.createrole = false,
                "bypassrls" => role.bypassrls = !negated,
                "nobypassrls" => role.bypassrls = false,
                "password" => {
                    if let Some(Tok::Str(p)) = rest.get(k + 1).map(|n| &n.tok) {
                        role.verifier = Some(p.clone());
                    }
                }
                "encrypted" | "unencrypted" => {
                    if matches!(rest.get(k + 1).map(|n| &n.tok), Some(Tok::Word(p)) if p == "password")
                    {
                        if let Some(Tok::Str(p)) = rest.get(k + 2).map(|n| &n.tok) {
                            role.verifier = Some(p.clone());
                        }
                    }
                }
                _ => {}
            }
        }
        k += 1;
    }
}
