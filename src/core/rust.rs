//! Rust function analysis (line/token based).
//!
//! The mirror of `frontend.rs` for Rust: given a file's source text it returns
//! one `FunctionSnapshot` per `fn`, with parameter count, an approximate
//! cyclomatic complexity / nesting, and the rule signals (`unsafe`, empty
//! guards). It is deliberately line/token based — there is no `syn` dependency —
//! so it is approximate but cheap, and (for the keyword scan) comment/string
//! aware so prose never trips it.

use super::model::{FileSnapshot, FunctionSignals, FunctionSnapshot};

pub(crate) fn scan_rust_functions(file: &FileSnapshot, content: &str) -> Vec<FunctionSnapshot> {
    let mut functions = Vec::new();
    let lines: Vec<&str> = content.lines().collect();
    let mut i = 0;

    while i < lines.len() {
        let line = lines[i].trim_start();
        if let Some(name) = extract_rust_fn_name(line) {
            let start = i + 1;
            let end = find_function_end(&lines, i).unwrap_or(lines.len());
            let line_count = end.saturating_sub(start).max(1);
            let (cyclomatic, max_nesting) = rust_complexity(&lines[i..end]);
            let signals = rust_signals(&lines[i..end]);
            functions.push(FunctionSnapshot {
                file: file.path.clone(),
                name,
                language: "rust",
                start_line: start,
                end_line: end,
                lines: line_count,
                param_count: count_rust_params(&lines, i),
                // Usage analysis needs a real AST; the Rust scanner is line
                // based, so it reports the parameter count only.
                params: Vec::new(),
                unused_params: Vec::new(),
                cyclomatic,
                max_nesting,
                references: 0,
                referenced_by: Vec::new(),
                signals,
            });
            i = end;
            continue;
        }
        i += 1;
    }

    functions
}

fn extract_rust_fn_name(line: &str) -> Option<String> {
    let keywords = ["pub fn ", "fn ", "pub(crate) fn ", "pub(super) fn "];
    for keyword in keywords {
        if let Some(rest) = line.strip_prefix(keyword) {
            let name = rest
                .split(|c: char| c == '(' || c == '<' || c.is_whitespace())
                .next()
                .unwrap_or_default();
            if !name.is_empty() {
                return Some(name.to_string());
            }
        }
    }
    None
}

fn find_function_end(lines: &[&str], start: usize) -> Option<usize> {
    let mut brace_depth = 0usize;
    let mut seen_open = false;

    for (idx, line) in lines.iter().enumerate().skip(start) {
        for ch in line.chars() {
            match ch {
                '{' => {
                    brace_depth += 1;
                    seen_open = true;
                }
                '}' => {
                    brace_depth = brace_depth.saturating_sub(1);
                    if seen_open && brace_depth == 0 {
                        return Some(idx + 1);
                    }
                }
                _ => {}
            }
        }
    }

    None
}

/// Counts the formal parameters of a Rust function from its signature.
///
/// Walks from the `fn` line until the parameter parentheses balance, counting
/// commas that sit at the top level of the parameter list (commas inside
/// generics, tuples or nested types do not separate parameters). A leading
/// `self` receiver is not counted as a parameter.
fn count_rust_params(lines: &[&str], start: usize) -> usize {
    let mut paren = 0i32;
    let mut nested = 0i32;
    let mut started = false;
    let mut params: Vec<String> = Vec::new();
    let mut current = String::new();
    let mut prev = ' ';

    'outer: for line in lines.iter().skip(start) {
        for ch in line.chars() {
            match ch {
                '(' => {
                    paren += 1;
                    if paren == 1 && !started {
                        started = true;
                        prev = ch;
                        continue;
                    }
                    current.push(ch);
                }
                ')' => {
                    paren -= 1;
                    if paren == 0 && started {
                        push_param(&mut params, &current);
                        break 'outer;
                    }
                    current.push(ch);
                }
                '[' | '{' | '<' => {
                    nested += 1;
                    if started {
                        current.push(ch);
                    }
                }
                ']' | '}' => {
                    nested -= 1;
                    if started {
                        current.push(ch);
                    }
                }
                '>' => {
                    // Avoid treating the `>` of a `->` return arrow as a
                    // closing generic bracket.
                    if prev != '-' && nested > 0 {
                        nested -= 1;
                    }
                    if started {
                        current.push(ch);
                    }
                }
                ',' if started && paren == 1 && nested == 0 => {
                    push_param(&mut params, &current);
                    current.clear();
                }
                _ => {
                    if started {
                        current.push(ch);
                    }
                }
            }
            prev = ch;
        }
        if started {
            current.push(' ');
            prev = ' ';
        }
    }

    let mut count = params.len();
    if params.first().is_some_and(|first| is_self_receiver(first)) {
        count -= 1;
    }
    count
}

fn push_param(params: &mut Vec<String>, current: &str) {
    let trimmed = current.trim();
    if !trimmed.is_empty() {
        params.push(trimmed.to_string());
    }
}

fn is_self_receiver(param: &str) -> bool {
    let mut s = param.trim();
    if let Some(rest) = s.strip_prefix('&') {
        s = rest.trim_start();
    }
    if let Some(rest) = s.strip_prefix('\'') {
        s = rest
            .trim_start_matches(|c: char| c.is_alphanumeric() || c == '_')
            .trim_start();
    }
    if let Some(rest) = s.strip_prefix("mut ") {
        s = rest.trim_start();
    }
    s == "self" || s.starts_with("self:")
}

/// Approximate cyclomatic complexity and max nesting for a Rust function from
/// its source lines. Token based (no real AST): counts branch/loop keywords and
/// `=>` match arms for complexity, and brace depth for nesting. Approximate —
/// it does not strip comments/strings and counts non-control braces (closures,
/// struct literals, match blocks), so it can read slightly high.
fn rust_complexity(func_lines: &[&str]) -> (usize, usize) {
    let mut decisions = 0usize;
    let mut brace_depth = 0i32;
    let mut max_brace = 0i32;

    for line in func_lines {
        let mut token = String::new();
        let mut prev = ' ';
        for ch in line.chars() {
            if ch == '_' || ch.is_alphanumeric() {
                token.push(ch);
            } else {
                if is_branch_keyword(&token) {
                    decisions += 1;
                }
                token.clear();
                match ch {
                    '{' => {
                        brace_depth += 1;
                        max_brace = max_brace.max(brace_depth);
                    }
                    '}' => brace_depth -= 1,
                    // `=>` is a match arm in Rust (closures use `|x|`).
                    '>' if prev == '=' => decisions += 1,
                    _ => {}
                }
            }
            prev = ch;
        }
        if is_branch_keyword(&token) {
            decisions += 1;
        }
    }

    let cyclomatic = decisions + 1;
    // Subtract the function's own body brace so a flat function nests at 0.
    let max_nesting = (max_brace - 1).max(0) as usize;
    (cyclomatic, max_nesting)
}

fn is_branch_keyword(token: &str) -> bool {
    matches!(token, "if" | "for" | "while" | "loop")
}

/// Extra Rust signals for the rule layer, gathered from a function's source
/// lines with the same token/brace approximation as `rust_complexity` (no real
/// AST). Counts `unsafe` keywords and empty control-flow bodies. Frontend-only
/// signals (bool chains, ternaries, subscriptions) are left at their defaults.
///
/// Comments and string/char literals are skipped, so the keyword scan only sees
/// real code — in real Rust, `unsafe` is a reserved word, so every token it
/// counts is genuine. Still approximate: a guard body is "the next `{ }` after
/// an `if` / `else` / `while` / `for` / `loop` / `match`", so a struct literal
/// inside a condition can occasionally be miscounted.
fn rust_signals(func_lines: &[&str]) -> FunctionSignals {
    let chars: Vec<char> = func_lines.join("\n").chars().collect();
    let n = chars.len();
    let mut unsafe_count = 0usize;
    let mut empty_blocks = 0usize;
    let mut token = String::new();
    let mut guard_armed = false;

    // Resolves the just-finished identifier token (called whenever it ends — at
    // punctuation, whitespace, or the start of a comment / literal).
    let flush = |token: &mut String, unsafe_count: &mut usize, guard_armed: &mut bool| {
        match token.as_str() {
            "unsafe" => *unsafe_count += 1,
            "if" | "else" | "while" | "for" | "loop" | "match" => *guard_armed = true,
            _ => {}
        }
        token.clear();
    };

    let mut i = 0;
    while i < n {
        let ch = chars[i];

        // ---- skip comments and literals (their contents are not code) ----
        if ch == '/' && chars.get(i + 1) == Some(&'/') {
            flush(&mut token, &mut unsafe_count, &mut guard_armed);
            i += 2;
            while i < n && chars[i] != '\n' {
                i += 1;
            }
            continue;
        }
        if ch == '/' && chars.get(i + 1) == Some(&'*') {
            flush(&mut token, &mut unsafe_count, &mut guard_armed);
            i += 2;
            let mut depth = 1usize; // Rust block comments nest.
            while i < n && depth > 0 {
                if chars[i] == '/' && chars.get(i + 1) == Some(&'*') {
                    depth += 1;
                    i += 2;
                } else if chars[i] == '*' && chars.get(i + 1) == Some(&'/') {
                    depth -= 1;
                    i += 2;
                } else {
                    i += 1;
                }
            }
            continue;
        }
        if ch == '"' {
            flush(&mut token, &mut unsafe_count, &mut guard_armed);
            i += 1;
            while i < n {
                match chars[i] {
                    '\\' => i += 2,
                    '"' => {
                        i += 1;
                        break;
                    }
                    _ => i += 1,
                }
            }
            continue;
        }
        if ch == '\'' {
            // A char literal (`'x'`, `'\n'`) — but a lifetime (`'a`) is just a
            // tick, so only skip when it really closes like a char literal.
            flush(&mut token, &mut unsafe_count, &mut guard_armed);
            if chars.get(i + 1) == Some(&'\\') {
                i += 2;
                while i < n && chars[i] != '\'' {
                    i += 1;
                }
                i += 1;
                continue;
            }
            if chars.get(i + 2) == Some(&'\'') {
                i += 3;
                continue;
            }
            i += 1; // lifetime tick
            continue;
        }

        if ch == '_' || ch.is_alphanumeric() {
            token.push(ch);
            i += 1;
            continue;
        }

        flush(&mut token, &mut unsafe_count, &mut guard_armed);

        if ch == '{' && guard_armed {
            let mut j = i + 1;
            while j < n && chars[j].is_whitespace() {
                j += 1;
            }
            if chars.get(j) == Some(&'}') {
                empty_blocks += 1;
            }
            guard_armed = false;
        }
        i += 1;
    }
    flush(&mut token, &mut unsafe_count, &mut guard_armed);

    FunctionSignals {
        unsafe_count,
        empty_blocks,
        ..FunctionSignals::default()
    }
}

/// Returns `content` with the interior of line/block comments and string/char
/// literals replaced by spaces (newlines preserved). Pattern scans for
/// `unwrap(` / `.clone()` / `panic!(` etc. run over this so a match inside a
/// comment or a string literal is not miscounted as real code — the same
/// reason `rust_signals` is comment/string aware.
pub(crate) fn strip_noise(content: &str) -> String {
    let chars: Vec<char> = content.chars().collect();
    let n = chars.len();
    let mut out = String::with_capacity(n);
    let blank = |out: &mut String, ch: char| out.push(if ch == '\n' { '\n' } else { ' ' });

    let mut i = 0;
    while i < n {
        let ch = chars[i];
        if ch == '/' && chars.get(i + 1) == Some(&'/') {
            while i < n && chars[i] != '\n' {
                blank(&mut out, chars[i]);
                i += 1;
            }
            continue;
        }
        if ch == '/' && chars.get(i + 1) == Some(&'*') {
            let mut depth = 1usize;
            out.push(' ');
            out.push(' ');
            i += 2;
            while i < n && depth > 0 {
                if chars[i] == '/' && chars.get(i + 1) == Some(&'*') {
                    depth += 1;
                    out.push(' ');
                    out.push(' ');
                    i += 2;
                } else if chars[i] == '*' && chars.get(i + 1) == Some(&'/') {
                    depth -= 1;
                    out.push(' ');
                    out.push(' ');
                    i += 2;
                } else {
                    blank(&mut out, chars[i]);
                    i += 1;
                }
            }
            continue;
        }
        if ch == '"' {
            out.push(' ');
            i += 1;
            while i < n {
                match chars[i] {
                    '\\' => {
                        out.push(' ');
                        out.push(' ');
                        i += 2;
                    }
                    '"' => {
                        out.push(' ');
                        i += 1;
                        break;
                    }
                    other => {
                        blank(&mut out, other);
                        i += 1;
                    }
                }
            }
            continue;
        }
        if ch == '\'' {
            // Char literal (`'x'` / `'\n'`); a lifetime (`'a`) is just a tick.
            if chars.get(i + 1) == Some(&'\\') {
                out.push(' ');
                i += 1;
                while i < n && chars[i] != '\'' {
                    out.push(' ');
                    i += 1;
                }
                if i < n {
                    out.push(' ');
                    i += 1;
                }
                continue;
            }
            if chars.get(i + 2) == Some(&'\'') {
                out.push_str("   ");
                i += 3;
                continue;
            }
            out.push('\'');
            i += 1;
            continue;
        }
        out.push(ch);
        i += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::classify::FileCategory;

    fn rust_file(content: &str) -> FileSnapshot {
        FileSnapshot {
            path: "x.rs".to_string(),
            name: "x.rs".to_string(),
            lines: content.lines().count().max(1),
            bytes: content.len() as u64,
            depth: 1,
            category: FileCategory::Source,
            content: Some(content.to_string()),
        }
    }

    #[test]
    fn counts_basic_rust_params() {
        let src = "fn add(a: i32, b: i32) -> i32 { a + b }\n";
        let functions = scan_rust_functions(&rust_file(src), src);
        assert_eq!(functions.len(), 1);
        assert_eq!(functions[0].name, "add");
        assert_eq!(functions[0].language, "rust");
        assert_eq!(functions[0].param_count, 2);
    }

    #[test]
    fn ignores_self_receiver() {
        let src = "fn method(&mut self, value: u8) {}\n";
        let functions = scan_rust_functions(&rust_file(src), src);
        assert_eq!(functions[0].param_count, 1);
    }

    #[test]
    fn ignores_commas_inside_generics() {
        let src = "fn build(map: HashMap<String, u8>, n: usize) -> bool { true }\n";
        let functions = scan_rust_functions(&rust_file(src), src);
        assert_eq!(functions[0].param_count, 2);
    }

    #[test]
    fn handles_no_params() {
        let src = "fn now() -> u64 { 0 }\n";
        let functions = scan_rust_functions(&rust_file(src), src);
        assert_eq!(functions[0].param_count, 0);
    }

    #[test]
    fn handles_closure_param_with_return_arrow() {
        let src = "fn run(cb: impl Fn(u8) -> bool, n: u8) {}\n";
        let functions = scan_rust_functions(&rust_file(src), src);
        assert_eq!(functions[0].param_count, 2);
    }

    #[test]
    fn computes_rust_complexity_and_nesting() {
        // if (+1) + while (+1) → cyclomatic 3; if > while → nesting 2.
        let src = "fn f(x: i32) {\n    if x > 0 {\n        while x > 1 {}\n    }\n}\n";
        let functions = scan_rust_functions(&rust_file(src), src);
        assert_eq!(functions[0].cyclomatic, 3);
        assert_eq!(functions[0].max_nesting, 2);
    }

    #[test]
    fn counts_match_arms_as_decisions() {
        // 2 match arms → 2 decisions → cyclomatic 3.
        let src =
            "fn f(x: i32) -> i32 {\n    match x {\n        0 => 1,\n        _ => 2,\n    }\n}\n";
        let functions = scan_rust_functions(&rust_file(src), src);
        assert_eq!(functions[0].cyclomatic, 3);
    }

    #[test]
    fn extracts_unsafe_and_empty_guard_signals() {
        let src = "fn f(p: *const u8) {\n    if p.is_null() {}\n    unsafe { let _ = *p; }\n}\n";
        let functions = scan_rust_functions(&rust_file(src), src);
        let signals = &functions[0].signals;
        assert_eq!(signals.unsafe_count, 1);
        assert_eq!(signals.empty_blocks, 1);
    }

    #[test]
    fn empty_function_body_is_not_an_empty_guard() {
        let src = "fn noop() {}\n";
        let functions = scan_rust_functions(&rust_file(src), src);
        assert_eq!(functions[0].signals.empty_blocks, 0);
        assert_eq!(functions[0].signals.unsafe_count, 0);
    }

    #[test]
    fn strip_noise_blanks_comments_and_strings() {
        // `unwrap(` appears in a line comment, a block comment, and a string —
        // none should survive; the real call should.
        let src = "let x = y.unwrap(); // call unwrap() here\n\
                   /* unwrap() in block */\n\
                   let s = \"unwrap() in string\";\n";
        let stripped = strip_noise(src);
        assert_eq!(stripped.matches("unwrap(").count(), 1);
        // Line structure is preserved so offsets stay sane.
        assert_eq!(stripped.lines().count(), src.lines().count());
    }
}
