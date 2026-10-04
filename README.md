# pgwarden

[![CI](https://github.com/sriharifortitude/pgwarden/actions/workflows/ci.yml/badge.svg)](https://github.com/sriharifortitude/pgwarden/actions/workflows/ci.yml)

A security linter for PostgreSQL schemas. It reads `pg_dump` output or a
folder of migrations and reports the privilege and isolation mistakes that
look fine in review: `SECURITY DEFINER` functions anyone can call, row-level
security policies that were never switched on, views that quietly bypass them.
Rust, one dependency (`serde_json`), MIT.

## Why

Postgres has good security features and several ways to defeat them without an
error message. A table can have a policy and no `ENABLE ROW LEVEL SECURITY`;
every row is visible and the schema still reads as restricted. A view over a
row-level-security table runs as its owner, who bypasses the policy, so the
view shows every tenant's rows. A `SECURITY DEFINER` function is executable by
`PUBLIC` unless someone revoked it, and without a pinned `search_path` it
resolves names through whatever the caller set.

None of these fails a test, and all of them are visible in the SQL. pgwarden
reads the SQL, applies it in order, and reports where it ends up.

## What it finds

Three migration files in `testdata/vulnerable/`: a small multi-tenant billing
schema, the functions added later, and the roles.

<!-- demo:start -->
```
testdata/vulnerable/001_schema.sql:2  LOW      PW011  column accounts.api_token is a text that looks like a secret stored in the clear
testdata/vulnerable/001_schema.sql:9  MEDIUM   PW010  table invoices has a column named tenant_id but no row-level security, so tenant isolation depends on every query filtering by it
testdata/vulnerable/001_schema.sql:16  HIGH     PW003  table invoices has 1 policy but row-level security is not enabled, so they are not enforced
testdata/vulnerable/001_schema.sql:19  LOW      PW004  table accounts has row-level security enabled and no policies, so non-owner roles see no rows
testdata/vulnerable/002_functions.sql:1  HIGH     PW001  function close_invoice() is SECURITY DEFINER and has no SET search_path, so names inside it resolve through the caller's search_path
testdata/vulnerable/002_functions.sql:1  HIGH     PW002  function close_invoice() is SECURITY DEFINER and nothing revokes EXECUTE from PUBLIC, so any role that can connect can call it with the owner's privileges
testdata/vulnerable/002_functions.sql:9  MEDIUM   PW009  function run_report() is written in plpython3u, an untrusted language that can reach the server's OS
testdata/vulnerable/002_functions.sql:13  HIGH     PW005  view invoice_totals reads accounts, which has row-level security, and runs as its owner (who bypasses it), so every user of the view sees every row
testdata/vulnerable/002_functions.sql:16  MEDIUM   PW009  extension dblink reaches outside the database (network, files or the OS)
testdata/vulnerable/003_roles.sql:1  HIGH     PW007  role app_admin has SUPERUSER, which an application role should not
testdata/vulnerable/003_roles.sql:1  HIGH     PW008  the SQL for role app_admin sets a plaintext password
testdata/vulnerable/003_roles.sql:2  HIGH     PW007  role reporting has BYPASSRLS, which an application role should not
testdata/vulnerable/003_roles.sql:2  MEDIUM   PW008  the SQL for role reporting contains an MD5 password hash, which is enough to authenticate and can be cracked offline
testdata/vulnerable/003_roles.sql:3  HIGH     PW006  grants PUBLIC CREATE on schema public: any login can plant objects there
testdata/vulnerable/003_roles.sql:4  HIGH     PW006  grants PUBLIC write privileges on invoices: any login can change the data

15 finding(s): 9 high, 4 medium, 2 low, in 3 SQL file(s)
```
<!-- demo:end -->

| Rule | Severity | What |
| --- | --- | --- |
| PW001 | high | `SECURITY DEFINER` function with no `SET search_path` |
| PW002 | high | `SECURITY DEFINER` function nobody revoked `EXECUTE` on from `PUBLIC` |
| PW003 | high | policies on a table where RLS is not enabled |
| PW004 | low | RLS enabled with no policies |
| PW005 | high | view over an RLS table without `security_invoker` |
| PW006 | medium, high | `GRANT ... TO PUBLIC`: write on tables, `CREATE` on a schema |
| PW007 | medium, high | `SUPERUSER`, `BYPASSRLS`, `CREATEROLE` |
| PW008 | low to high | role password in the SQL: plaintext, MD5 hash, SCRAM verifier |
| PW009 | medium | untrusted languages, `dblink`, `file_fdw`, `adminpack` |
| PW010 | medium | table with a `tenant_id`-style column and no RLS |
| PW011 | low | column named `password` / `token` / `secret` that is not a hash |

`pgwarden rules` prints each with why it matters and how to fix it.

Three of these deserve a sentence.

**PW003** is the quiet one. `CREATE POLICY` does nothing until `ALTER TABLE ...
ENABLE ROW LEVEL SECURITY`. In `testdata/vulnerable/` the `invoices` table has a
tenant policy and returns every tenant's rows to any role with `SELECT`.

**PW005** is the one reviewers miss. The `invoice_totals` view reads a table
with RLS enabled. A view runs as its owner, and an owner bypasses RLS on its
own tables unless `FORCE ROW LEVEL SECURITY` is set, so the policy protects
the table and not the view. `WITH (security_invoker = true)` (PostgreSQL 15 and
later) fixes it.

**PW002** follows from a default rather than a mistake. PostgreSQL grants
`EXECUTE` on new functions to `PUBLIC`. pgwarden knows that, so a
`SECURITY DEFINER` function is only quiet once a `REVOKE ... FROM PUBLIC`
(or `ALTER DEFAULT PRIVILEGES ... REVOKE`) covers it. Trigger functions are
exempt, since nobody can call them directly.

## Usage

```bash
cargo install --git https://github.com/sriharifortitude/pgwarden --tag v0.1.0

pg_dump --schema-only --no-owner mydb > schema.sql
pgwarden scan schema.sql                  # a dump
pgwarden scan db/migrations/              # a folder, searched recursively
pgwarden scan --brief --fail-on medium .
pgwarden scan --format sarif . > pgwarden.sarif
pgwarden scan --tenant-column shop_id .   # what marks a tenant table
```

Every file is applied, in path order, to **one schema**: a table created in
`001.sql`, secured in `007.sql` and re-created in `012.sql` is judged by where
it ends up. `DROP`, `ALTER TABLE ... RENAME`, `ADD COLUMN`, `CREATE OR REPLACE
FUNCTION` and `ALTER FUNCTION` are followed
([ADR 2](docs/adr/0002-the-schema-is-where-the-sql-ends-up.md)). For roles,
scan the output of `pg_dumpall --roles-only`.

Exit codes: 0 nothing at or above `--fail-on` (default `high`), 1 at least one
finding is, 2 a usage error or a file that could not be read. A file it cannot
lex (an unterminated string, a file that is not UTF-8) fails the run even when
everything else is clean, because a check that exits 0 having read nothing
looks like a result.

Suppress a finding with a reason, on the comment line directly above the
statement:

```sql
-- pgwarden:ignore PW001 -- the owner role has no other schemas to shadow
CREATE FUNCTION public.refresh() ...
```

A suppression without a reason suppresses nothing and is itself reported
(PW000).

## It reads SQL, it does not split on semicolons

`pg_dump` output and migrations break the usual shortcuts. A `;` inside a string
or a `$$ ... $$` function body is not a statement end. `/* */` comments nest.
`E'it\'s'` treats a backslash as an escape and `'a\'` does not.
`COPY ... FROM stdin;` is followed by raw data up to `\.`, which is not SQL (a
data dump has tens of megabytes of it). A `BEGIN ATOMIC ... END` function body is
full of its own semicolons. pgwarden has a lexer that handles each, and the
rules work on tokens rather than text, so a function body that mentions
`SECURITY DEFINER` in a comment is not a `SECURITY DEFINER` function
([ADR 1](docs/adr/0001-lex-the-sql.md)).

## Run on real schemas

**pagila** (a real `pg_dump` of a DVD-rental database, 7 files, 33 MB with its
data): 4 findings, in about 1.5 seconds on this machine. One is a
`SECURITY DEFINER` function (PW001 and PW002), one is `staff.password` as plain
text, one is `GRANT ALL ON SCHEMA public TO PUBLIC`.

**Supabase's `postgres` repository** (243 SQL files): 29 findings, mostly
the platform's own roles (`supabase_admin` has `SUPERUSER`, `BYPASSRLS` and
`CREATEROLE`; several have passwords in the init scripts), plus `dblink` and
`file_fdw` in test setup and `auth.refresh_tokens.token` as plain text. These are
largely intended for that product. They are what the rules exist to point at.

**PostgreSQL's own regression-test SQL** (241 files, 5 MB): used only to check
the lexer on hostile input. 240 files lexed; the other is Windows-1252, not
UTF-8, and was refused. The 56 findings it produces are the tests deliberately
exercising odd states (the files reuse table names, so applying them as one
schema is meaningless), and I make no claim about them.

Running them found real mistakes in the first version, now fixed with tests:
58 false PW010 findings in pagila because `customer_id` is a customer column,
not a tenant marker (the defaults are now `tenant_id`, `org_id`,
`organization_id`, `workspace_id`, `company_id`); `auth.users.encrypted_password`
reported as a plaintext secret; and the built-in `postgres` role reported for
having the attributes a superuser has by definition.

What this does and does not show. It shows the lexer and schema builder cope
with real dumps and migrations. It does not show the rules are complete: there
is no ground truth for those schemas, and I have not compared the output with
other tools.

## Tested

```bash
cargo test    # 60 tests
```

The lexer has tests for each case above plus line numbers across multi-line
tokens, CRLF files, and every kind of unterminated input. Each rule has cases
that must fire and cases that must not. Fourteen of the tests were run against
deliberately broken copies of the code to check they fail: nested comments,
`E''` escapes, `COPY` data skipping, `BEGIN ATOMIC`, default-privilege parsing,
the trigger-function exemption, `security_invoker`, `FORCE ROW LEVEL SECURITY`,
the reason requirement, the size cap, the exit code for an unreadable file, the
`postgres` role exemption, MD5 detection and what counts as a revoke. Two
survived at first (an MD5 string of the wrong length, and a `GRANT TO PUBLIC`
counting as a revoke) and now have tests. CI builds on Rust 1.77, the version in
`Cargo.toml`, and on stable, and diffs the example above against a fresh run.

**Not tested:** against a live database. pgwarden has never connected to
PostgreSQL and I have not run its output through `psql`; it was checked against
dump files only.

## Not covered

- A running database. It reads SQL text, so it cannot see grants made by hand,
  role membership, who owns what, or `search_path` settings on roles. PW005
  assumes a view's owner is its table's owner, the usual case.
- What a policy says. `USING (true)` is a policy; pgwarden does not judge it.
- Dynamic SQL (`EXECUTE format(...)` in a function body or `DO` block).
- `REVOKE ... ON FUNCTION` is matched by function name, not by argument types,
  so one revoke covers every overload of that name.
- Names are folded as PostgreSQL folds them and `public.x` is `x`; other
  schemas are kept apart, but `search_path` is not modelled.
- Memory is about four times the file size (the lexer works on characters);
  files over 64 MiB are refused.

See [`docs/adr/`](docs/adr/) for the decisions behind it.

## Licence

MIT.
