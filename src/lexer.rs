//! A lexer for PostgreSQL's SQL, as far as a linter needs it.
//!
//! Splitting SQL on `;` is wrong in four ways that matter for `pg_dump`
//! output and migrations: a semicolon inside a string or a dollar-quoted
//! function body is not a statement end; `/* */` comments nest; an `E'...'`
//! string treats a backslash as an escape where a plain string does not; and
//! `COPY ... FROM stdin;` is followed by raw data lines up to `\.` that are not
//! SQL at all. This lexer gets those four right, and turns everything else into
//! words, identifiers, strings and punctuation.

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Tok {
    /// An unquoted identifier or keyword, lower-cased (PostgreSQL folds them).
    Word(String),
    /// A "quoted identifier", case preserved.
    Ident(String),
    /// A string literal's contents.
    Str(String),
    /// A dollar-quoted body, usually a function definition.
    Dollar(String),
    Num(String),
    Punct(char),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Token {
    pub tok: Tok,
    pub line: usize,
}

#[derive(Debug, PartialEq, Eq)]
pub struct LexError {
    pub line: usize,
    pub message: String,
}

impl std::fmt::Display for LexError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "line {}: {}", self.line, self.message)
    }
}

fn is_ident_start(c: char) -> bool {
    c == '_' || c.is_alphabetic() || !c.is_ascii()
}

fn is_ident_part(c: char) -> bool {
    is_ident_start(c) || c.is_ascii_digit() || c == '$'
}

/// If `chars[i..]` starts a dollar-quote tag (`$$` or `$tag$`), its length.
fn dollar_tag_len(chars: &[char], i: usize) -> Option<usize> {
    if chars.get(i) != Some(&'$') {
        return None;
    }
    let mut j = i + 1;
    if j < chars.len() && chars[j] == '$' {
        return Some(2);
    }
    if j >= chars.len() || !(chars[j] == '_' || chars[j].is_alphabetic() || !chars[j].is_ascii()) {
        return None;
    }
    while j < chars.len() && (chars[j] == '_' || chars[j].is_alphanumeric() || !chars[j].is_ascii())
    {
        j += 1;
    }
    if chars.get(j) == Some(&'$') {
        Some(j + 1 - i)
    } else {
        None
    }
}

/// Tokenise a whole file. psql meta-commands (`\connect`, `\restrict`) are
/// skipped, and so is the data block after `COPY ... FROM stdin;`.
pub fn lex(src: &str) -> Result<Vec<Token>, LexError> {
    let chars: Vec<char> = src.chars().collect();
    let mut out: Vec<Token> = Vec::new();
    let mut i = 0;
    let mut line = 1;
    let mut at_line_start = true;
    // For skipping COPY data: the first word of the statement being read, and
    // whether `stdin` appeared in it.
    let mut first_word: Option<String> = None;
    let mut saw_stdin = false;

    while i < chars.len() {
        let c = chars[i];
        if c == '\n' {
            line += 1;
            i += 1;
            at_line_start = true;
            continue;
        }
        if c.is_whitespace() {
            i += 1;
            continue;
        }
        let start_line = line;

        // psql meta-command: a backslash at the start of a line, to the end of it.
        if c == '\\' && at_line_start {
            while i < chars.len() && chars[i] != '\n' {
                i += 1;
            }
            continue;
        }
        at_line_start = false;

        // -- comment
        if c == '-' && chars.get(i + 1) == Some(&'-') {
            while i < chars.len() && chars[i] != '\n' {
                i += 1;
            }
            continue;
        }
        // /* nested */ comment
        if c == '/' && chars.get(i + 1) == Some(&'*') {
            let mut depth = 1;
            i += 2;
            while depth > 0 {
                if i >= chars.len() {
                    return Err(LexError {
                        line: start_line,
                        message: "unterminated /* comment".into(),
                    });
                }
                if chars[i] == '/' && chars.get(i + 1) == Some(&'*') {
                    depth += 1;
                    i += 2;
                } else if chars[i] == '*' && chars.get(i + 1) == Some(&'/') {
                    depth -= 1;
                    i += 2;
                } else {
                    if chars[i] == '\n' {
                        line += 1;
                    }
                    i += 1;
                }
            }
            continue;
        }
        // 'string', with '' as an escaped quote
        if c == '\'' {
            let (text, next, lines) = read_string(&chars, i, false, start_line)?;
            line += lines;
            i = next;
            out.push(Token {
                tok: Tok::Str(text),
                line: start_line,
            });
            continue;
        }
        // "quoted identifier"
        if c == '"' {
            let mut text = String::new();
            i += 1;
            loop {
                match chars.get(i) {
                    None => {
                        return Err(LexError {
                            line: start_line,
                            message: "unterminated quoted identifier".into(),
                        })
                    }
                    Some('"') if chars.get(i + 1) == Some(&'"') => {
                        text.push('"');
                        i += 2;
                    }
                    Some('"') => {
                        i += 1;
                        break;
                    }
                    Some(&ch) => {
                        if ch == '\n' {
                            line += 1;
                        }
                        text.push(ch);
                        i += 1;
                    }
                }
            }
            out.push(Token {
                tok: Tok::Ident(text),
                line: start_line,
            });
            continue;
        }
        // $tag$ ... $tag$
        if let Some(tag_len) = dollar_tag_len(&chars, i) {
            let tag: String = chars[i..i + tag_len].iter().collect();
            let body_start = i + tag_len;
            let mut j = body_start;
            let mut found = None;
            while j + tag_len <= chars.len() {
                if chars[j..j + tag_len].iter().collect::<String>() == tag {
                    found = Some(j);
                    break;
                }
                j += 1;
            }
            let Some(end) = found else {
                return Err(LexError {
                    line: start_line,
                    message: format!("unterminated dollar-quoted string {tag}"),
                });
            };
            let body: String = chars[body_start..end].iter().collect();
            line += body.chars().filter(|&ch| ch == '\n').count();
            i = end + tag_len;
            out.push(Token {
                tok: Tok::Dollar(body),
                line: start_line,
            });
            continue;
        }
        if c.is_ascii_digit() {
            let mut j = i;
            while j < chars.len() && (chars[j].is_ascii_alphanumeric() || chars[j] == '.') {
                j += 1;
            }
            out.push(Token {
                tok: Tok::Num(chars[i..j].iter().collect()),
                line: start_line,
            });
            i = j;
            continue;
        }
        if is_ident_start(c) {
            let mut j = i + 1;
            while j < chars.len() && is_ident_part(chars[j]) {
                j += 1;
            }
            let word: String = chars[i..j].iter().collect::<String>().to_lowercase();
            // E'..' has backslash escapes; b'..', x'..', n'..' are plain.
            if chars.get(j) == Some(&'\'') && matches!(word.as_str(), "e" | "b" | "x" | "n") {
                let (text, next, lines) = read_string(&chars, j, word == "e", start_line)?;
                line += lines;
                i = next;
                out.push(Token {
                    tok: Tok::Str(text),
                    line: start_line,
                });
                continue;
            }
            if first_word.is_none() {
                first_word = Some(word.clone());
            }
            if word == "stdin" {
                saw_stdin = true;
            }
            out.push(Token {
                tok: Tok::Word(word),
                line: start_line,
            });
            i = j;
            continue;
        }
        if c == ';' {
            let copy_data = first_word.as_deref() == Some("copy") && saw_stdin;
            first_word = None;
            saw_stdin = false;
            out.push(Token {
                tok: Tok::Punct(';'),
                line: start_line,
            });
            i += 1;
            if copy_data {
                // Skip raw data lines up to a line that is exactly `\.`.
                while i < chars.len() && chars[i] != '\n' {
                    i += 1;
                }
                loop {
                    if i >= chars.len() {
                        return Err(LexError {
                            line: start_line,
                            message: "COPY data is never terminated by \\.".into(),
                        });
                    }
                    i += 1; // the newline
                    line += 1;
                    let line_start = i;
                    while i < chars.len() && chars[i] != '\n' {
                        i += 1;
                    }
                    let text: String = chars[line_start..i].iter().collect();
                    if text.trim_end_matches('\r') == "\\." {
                        break;
                    }
                }
                at_line_start = false;
            }
            continue;
        }
        out.push(Token {
            tok: Tok::Punct(c),
            line: start_line,
        });
        i += 1;
    }
    Ok(out)
}

/// Read a quoted string starting at the opening quote. Returns the text, the
/// index after the closing quote, and how many newlines it spanned.
fn read_string(
    chars: &[char],
    open: usize,
    escapes: bool,
    line: usize,
) -> Result<(String, usize, usize), LexError> {
    let mut text = String::new();
    let mut i = open + 1;
    let mut lines = 0;
    loop {
        match chars.get(i) {
            None => {
                return Err(LexError {
                    line,
                    message: "unterminated string literal".into(),
                })
            }
            Some('\'') if chars.get(i + 1) == Some(&'\'') => {
                text.push('\'');
                i += 2;
            }
            Some('\'') => return Ok((text, i + 1, lines)),
            Some('\\') if escapes => {
                if let Some(&next) = chars.get(i + 1) {
                    if next == '\n' {
                        lines += 1;
                    }
                    text.push(next);
                    i += 2;
                } else {
                    i += 1;
                }
            }
            Some(&ch) => {
                if ch == '\n' {
                    lines += 1;
                }
                text.push(ch);
                i += 1;
            }
        }
    }
}
