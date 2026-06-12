//! Lightweight, line-based stylesheet (CSS/SCSS/Sass/Less) observability.
//!
//! Deliberately not a full CSS parser: brace-depth tracking is enough to
//! approximate rules, nesting, the largest rule block, repeated selectors and
//! `!important` usage without the cost of a real CSS AST. Kept separate from the
//! SWC/JS analysis it has nothing in common with.

use std::collections::HashMap;

use crate::core::model::{FileSnapshot, StylesheetSnapshot};

/// Reads a stylesheet with a single line scan. This is deliberately not a full
/// CSS parser: it tracks brace depth to approximate rules, nesting, the largest
/// rule block and repeated selectors — enough to be useful without the cost of
/// a real CSS AST.
pub(super) fn scan_stylesheet(file: &FileSnapshot, content: &str) -> StylesheetSnapshot {
    let mut rule_count = 0usize;
    let mut selector_count = 0usize;
    let mut declaration_count = 0usize;
    let mut variable_count = 0usize;
    let mut import_count = 0usize;
    let mut max_nesting_depth = 0usize;
    let mut largest_rule_lines = 0usize;
    let mut important_count = 0usize;
    let mut brace_depth = 0usize;
    let mut block_starts: Vec<usize> = Vec::new();
    let mut selector_occurrences: HashMap<String, usize> = HashMap::new();

    for (idx, raw_line) in content.lines().enumerate() {
        let line = strip_line_comment(raw_line).trim();
        if line.is_empty() || line.starts_with("/*") || line.starts_with('*') {
            continue;
        }

        important_count += line.matches("!important").count();

        let is_at_rule = line.starts_with('@');
        if is_at_rule
            && (line.starts_with("@import")
                || line.starts_with("@use")
                || line.starts_with("@forward"))
        {
            import_count += 1;
        }
        if !is_at_rule && (line.starts_with('$') || line.starts_with("--")) && line.contains(':') {
            variable_count += 1;
        }

        let opens = line.matches('{').count();
        let closes = line.matches('}').count();

        // Count property declarations by their terminating `;`. This also
        // captures declarations written inline with their selector, e.g.
        // `.a { color: red; }`. Variables and at-rules are excluded.
        if !is_at_rule && !line.starts_with('$') && !line.starts_with("--") {
            declaration_count += line.matches(';').count();
        }

        if opens > 0 {
            if !is_at_rule && let Some(selector) = line.split('{').next() {
                let selector = selector.trim();
                if !selector.is_empty() {
                    selector_count += 1;
                    *selector_occurrences
                        .entry(normalize_selector(selector))
                        .or_insert(0) += 1;
                }
            }
            rule_count += opens;
            for _ in 0..opens {
                block_starts.push(idx);
                brace_depth += 1;
                max_nesting_depth = max_nesting_depth.max(brace_depth.saturating_sub(1));
            }
        }

        for _ in 0..closes {
            if let Some(start) = block_starts.pop() {
                largest_rule_lines = largest_rule_lines.max(idx.saturating_sub(start) + 1);
            }
            brace_depth = brace_depth.saturating_sub(1);
        }
    }

    let duplicate_selector_count = selector_occurrences
        .values()
        .filter(|&&count| count > 1)
        .count();

    StylesheetSnapshot {
        file: file.path.clone(),
        name: file.name.clone(),
        lines: file.lines,
        bytes: file.bytes,
        rule_count,
        selector_count,
        declaration_count,
        variable_count,
        import_count,
        max_nesting_depth,
        largest_rule_lines,
        duplicate_selector_count,
        important_count,
    }
}

fn strip_line_comment(line: &str) -> &str {
    match line.find("//") {
        Some(pos) => &line[..pos],
        None => line,
    }
}

fn normalize_selector(selector: &str) -> String {
    selector.split_whitespace().collect::<Vec<_>>().join(" ")
}
