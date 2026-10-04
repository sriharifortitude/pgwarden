# 0001. Lex the SQL; do not split it on semicolons or search it with regular expressions

**Status:** accepted

## Decision

pgwarden tokenises each file with a lexer for PostgreSQL's SQL (words,
quoted identifiers, strings, dollar-quoted bodies, numbers, punctuation),
splits the tokens into statements, and builds its model from tokens. No rule
searches raw SQL text.

The lexer handles: `--` comments; nested `/* */` comments; `'` strings with
`''` escapes; `E'...'` strings with backslash escapes; `"quoted"` identifiers;
`$tag$ ... $tag$` bodies matched by tag; psql meta-commands such as `\connect`
and `\restrict`; the raw data after `COPY ... FROM stdin;` up to `\.`; and
`BEGIN ATOMIC ... END` function bodies, whose inner `;` do not end the
statement.

## Reasoning

The tempting version is `sql.split(';')` and a regular expression per rule.
That is wrong in ways that matter for exactly the files this tool reads:

- a function body is full of semicolons, so a split cuts `CREATE FUNCTION` in
  half and the `SECURITY DEFINER` clause lands in a fragment nobody parses;
- a data dump contains arbitrary text after `COPY`; a row that reads
  `CREATE TABLE evil (x int);` would be parsed as a statement. There is a test
  for exactly that;
- `SECURITY DEFINER` inside a comment or a string is not a property of the
  function, and a text search cannot tell.

A lexer is a few hundred lines and makes every later rule a question about
tokens. It is also what makes line numbers right: a finding points at the
statement's first token, even after a multi-line string or comment.

## Costs

It is not a full SQL parser. It does not build expression trees, so it cannot
say what a `USING` clause means or which columns a view really reads (PW005
looks at the names after `FROM` and `JOIN`). It works on a vector of
characters, so memory is about four times the file's size, which is why files
over 64 MiB are refused.
