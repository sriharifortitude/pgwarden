# 0002. Judge the schema where the SQL ends up, across files

**Status:** accepted

## Decision

All the files in a scan are applied, in path order, to one in-memory schema.
`CREATE`, `ALTER TABLE` (RLS enabled, disabled, forced; columns added;
renamed), `ALTER FUNCTION`, `ALTER ROLE`, `DROP` and `GRANT` / `REVOKE` change
it as they would change a database. Rules run once, on the final state, and
report the file and line where the thing in question was defined.

## Reasoning

Migrations are the common input, and in a migration folder the table, its
policy and the statement that turns RLS on are in different files, written
months apart. Judging each file alone would flag every table at birth
(`CREATE TABLE` with no RLS yet) and miss the one case that matters: a later
migration that *disables* RLS, drops the policy, or replaces a function with
a `SECURITY DEFINER` one.

Judging the end state makes the answer the same question a reviewer asks:
what is true once all of this has run?

## Costs

Order matters, and path order is only right if migrations are named to sort
(`001_`, a timestamp). A folder of files that are not meant to be applied
together (a test suite reusing table names, such as PostgreSQL's own regression
tests) is meaningless as one schema. pgwarden does not try to detect that.

Statements are not executed, so a `DO` block or `EXECUTE format(...)` that
changes the schema at run time is invisible.
