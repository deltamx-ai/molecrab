//! Rule layer.
//!
//! A "rule" is one named, lint-like check (e.g. `long-function`, `unsafe-block`,
//! `subscribe-clean`). Rules are deliberately concrete data + a function pointer,
//! not a trait-object plugin framework — the project favours clear, small units
//! over abstraction. The responsibilities are split three ways:
//!
//! - **detect**: each `check` is a free function reading the structured snapshot
//!   (function signals extracted by the language layers in `scanner.rs` /
//!   `frontend.rs`) plus the configured thresholds, and returning raw `RuleHit`s.
//! - **register**: [`builtin_rules`] is the single registry listing every rule
//!   with its language group, target metric, reviewer category and severity.
//! - **apply**: [`evaluate`] filters rules by the `[rules]` config (language
//!   group toggles + per-rule `disable`), runs them, and stamps each hit into a
//!   [`Finding`] tagged with the rule's id/metric/category/severity.
//!
//! The findings flow back into `metrics::evaluate`, which subtracts each
//! finding's penalty from its target metric — so rules drive the scores.

use std::collections::HashSet;

use super::config::ReviewConfig;
use super::metrics::{is_rust_source, is_source, max_source_line_length, scan_pattern};
use super::model::{
    Finding, FunctionSnapshot, RepositorySnapshot, Severity, is_dead_code_candidate,
};

/// Per-rule cap on emitted findings, so a large repo cannot flood the report
/// from a single rule. The strongest (highest-penalty) hits are kept.
const MAX_HITS_PER_RULE: usize = 12;

/// The language layer a rule targets — also how presets are grouped in config.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum RuleLang {
    /// Works on any function/file (size, complexity, dead code, hygiene).
    Common,
    /// Needs Rust-specific signals (unsafe, panic-prone, clone).
    Rust,
    /// Needs frontend (TS/JS) signals (subscriptions, console, expressions).
    Frontend,
}

/// One raw detection produced by a rule, before it is stamped with rule metadata.
pub struct RuleHit {
    pub file: Option<String>,
    /// 1-based source line, when the rule can point at one (typically the
    /// offending function's start line).
    pub line: Option<usize>,
    pub message: String,
    pub suggestion: String,
    pub penalty: u32,
}

/// A registered rule: metadata + its detection function.
pub struct Rule {
    pub id: &'static str,
    pub lang: RuleLang,
    /// The metric whose score this rule deducts from.
    pub metric: &'static str,
    /// Reviewer-facing problem category shown in the report.
    pub category: &'static str,
    pub severity: Severity,
    pub check: fn(&RepositorySnapshot, &ReviewConfig) -> Vec<RuleHit>,
}

/// The single registry of every built-in rule.
pub fn builtin_rules() -> Vec<Rule> {
    use RuleLang::{Common, Frontend, Rust};
    use Severity::{Info, Warning};
    vec![
        // ---- Common (language-agnostic) ----
        Rule {
            id: "long-function",
            lang: Common,
            metric: "maintainability",
            category: "Complexity",
            severity: Warning,
            check: rule_long_function,
        },
        Rule {
            id: "complex-function",
            lang: Common,
            metric: "maintainability",
            category: "Complexity",
            severity: Warning,
            check: rule_complex_function,
        },
        Rule {
            id: "deeply-nested-function",
            lang: Common,
            metric: "maintainability",
            category: "Complexity",
            severity: Warning,
            check: rule_deeply_nested,
        },
        Rule {
            id: "many-parameters",
            lang: Common,
            metric: "maintainability",
            category: "Complexity",
            severity: Warning,
            check: rule_many_parameters,
        },
        Rule {
            id: "god-function",
            lang: Common,
            metric: "maintainability",
            category: "Complexity",
            severity: Warning,
            check: rule_god_function,
        },
        Rule {
            id: "unused-parameter",
            lang: Common,
            metric: "maintainability",
            category: "Dead code",
            severity: Info,
            check: rule_unused_parameter,
        },
        Rule {
            id: "dead-code",
            lang: Common,
            metric: "maintainability",
            category: "Dead code",
            severity: Info,
            check: rule_dead_code,
        },
        Rule {
            id: "empty-guard",
            lang: Common,
            metric: "robustness",
            category: "Error handling",
            severity: Warning,
            check: rule_empty_guard,
        },
        Rule {
            id: "large-file",
            lang: Common,
            metric: "readability",
            category: "Readability",
            severity: Warning,
            check: rule_large_file,
        },
        Rule {
            id: "long-line",
            lang: Common,
            metric: "readability",
            category: "Readability",
            severity: Warning,
            check: rule_long_line,
        },
        Rule {
            id: "todo-fixme",
            lang: Common,
            metric: "readability",
            category: "Hygiene",
            severity: Info,
            check: rule_todo_fixme,
        },
        // ---- Rust ----
        Rule {
            id: "panic-prone",
            lang: Rust,
            metric: "robustness",
            category: "Error handling",
            severity: Warning,
            check: rule_panic_prone,
        },
        Rule {
            id: "unsafe-block",
            lang: Rust,
            metric: "robustness",
            category: "Safety",
            severity: Warning,
            check: rule_unsafe_block,
        },
        Rule {
            id: "excessive-clone",
            lang: Rust,
            metric: "performance",
            category: "Performance",
            severity: Info,
            check: rule_excessive_clone,
        },
        // ---- Frontend (TS/JS) ----
        Rule {
            id: "complex-expression",
            lang: Frontend,
            metric: "maintainability",
            category: "Complexity",
            severity: Warning,
            check: rule_complex_expression,
        },
        Rule {
            id: "subscribe-clean",
            lang: Frontend,
            metric: "robustness",
            category: "Resource leak",
            severity: Warning,
            check: rule_subscribe_clean,
        },
        Rule {
            id: "console-log",
            lang: Frontend,
            metric: "readability",
            category: "Hygiene",
            severity: Info,
            check: rule_console_log,
        },
        Rule {
            id: "no-explicit-any",
            lang: Frontend,
            metric: "robustness",
            category: "Type safety",
            severity: Warning,
            check: rule_no_explicit_any,
        },
        Rule {
            id: "unsafe-cast",
            lang: Frontend,
            metric: "robustness",
            category: "Type safety",
            severity: Warning,
            check: rule_unsafe_cast,
        },
        Rule {
            id: "non-null-assertion",
            lang: Frontend,
            metric: "robustness",
            category: "Type safety",
            severity: Info,
            check: rule_non_null_assertion,
        },
        Rule {
            id: "unhandled-promise",
            lang: Frontend,
            metric: "robustness",
            category: "Error handling",
            severity: Warning,
            check: rule_unhandled_promise,
        },
        Rule {
            id: "react-effect-deps",
            lang: Frontend,
            metric: "robustness",
            category: "React",
            severity: Warning,
            check: rule_react_effect_deps,
        },
        // NOTE: `magic-number` is intentionally not implemented yet — a reliable
        // cross-language numeric-literal signal is more work than it is worth for
        // now; add it as a frontend signal + Common rule when needed.
    ]
}

/// Whether a rule runs under the current config: its language group must be on
/// and its id must not be in the `disable` list.
fn is_enabled(rule: &Rule, config: &ReviewConfig) -> bool {
    let group_on = match rule.lang {
        RuleLang::Common => config.rules.common,
        RuleLang::Rust => config.rules.rust,
        RuleLang::Frontend => config.rules.frontend,
    };
    group_on && !config.rules.disable.iter().any(|id| id == rule.id)
}

/// Runs every enabled rule and turns its hits into [`Finding`]s. Each rule's
/// hits are kept strongest-first and capped at [`MAX_HITS_PER_RULE`].
pub fn evaluate(snapshot: &RepositorySnapshot, config: &ReviewConfig) -> Vec<Finding> {
    let mut findings = Vec::new();
    for rule in builtin_rules() {
        if !is_enabled(&rule, config) {
            continue;
        }
        let mut hits = (rule.check)(snapshot, config);
        hits.sort_by(|a, b| b.penalty.cmp(&a.penalty));
        for hit in hits.into_iter().take(MAX_HITS_PER_RULE) {
            findings.push(Finding {
                severity: rule.severity,
                file: hit.file,
                line: hit.line,
                metric: rule.metric,
                category: rule.category,
                rule: Some(rule.id),
                message: hit.message,
                suggestion: hit.suggestion,
                score_penalty: hit.penalty,
            });
        }
    }
    findings
}

// --------------------------------------------------------------------------
// Helpers
// --------------------------------------------------------------------------

/// A file-scoped (or repo-scoped) hit, with no specific line.
fn hit(file: Option<String>, message: String, suggestion: &str, penalty: u32) -> RuleHit {
    RuleHit {
        file,
        line: None,
        message,
        suggestion: suggestion.to_string(),
        penalty,
    }
}

/// A hit that points at a specific function, carrying its file and start line.
fn fn_hit(func: &FunctionSnapshot, message: String, suggestion: &str, penalty: u32) -> RuleHit {
    RuleHit {
        file: Some(func.file.clone()),
        line: Some(func.start_line),
        message,
        suggestion: suggestion.to_string(),
        penalty,
    }
}

fn source_path_set(snapshot: &RepositorySnapshot) -> HashSet<&str> {
    snapshot
        .files
        .iter()
        .filter(|f| f.is_source())
        .map(|f| f.path.as_str())
        .collect()
}

// --------------------------------------------------------------------------
// Common rules
// --------------------------------------------------------------------------

fn rule_long_function(snapshot: &RepositorySnapshot, config: &ReviewConfig) -> Vec<RuleHit> {
    let max = config.thresholds.max_function_lines as usize;
    snapshot
        .functions
        .iter()
        .filter(|f| f.lines > max)
        .map(|f| {
            let over = f.lines - max;
            let penalty = ((over as u32 / 40) + 2).min(8);
            fn_hit(
                f,
                format!(
                    "long function `{}` ({} lines, limit {})",
                    f.name, f.lines, max
                ),
                "break it into smaller, focused functions",
                penalty,
            )
        })
        .collect()
}

fn rule_complex_function(snapshot: &RepositorySnapshot, config: &ReviewConfig) -> Vec<RuleHit> {
    let max = config.thresholds.max_cyclomatic as usize;
    snapshot
        .functions
        .iter()
        .filter(|f| f.cyclomatic > max)
        .map(|f| {
            let over = (f.cyclomatic - max) as u32;
            let penalty = ((over * 2) + 2).min(8);
            fn_hit(
                f,
                format!(
                    "complex function `{}` (cyclomatic ~{}, limit {})",
                    f.name, f.cyclomatic, max
                ),
                "simplify the branching or extract helper functions",
                penalty,
            )
        })
        .collect()
}

fn rule_deeply_nested(snapshot: &RepositorySnapshot, config: &ReviewConfig) -> Vec<RuleHit> {
    let max = config.thresholds.max_function_nesting as usize;
    snapshot
        .functions
        .iter()
        .filter(|f| f.max_nesting > max)
        .map(|f| {
            let over = (f.max_nesting - max) as u32;
            let penalty = ((over * 3) + 2).min(6);
            fn_hit(
                f,
                format!(
                    "deeply nested function `{}` (depth {}, limit {})",
                    f.name, f.max_nesting, max
                ),
                "flatten with early returns or guard clauses",
                penalty,
            )
        })
        .collect()
}

fn rule_many_parameters(snapshot: &RepositorySnapshot, config: &ReviewConfig) -> Vec<RuleHit> {
    let max = config.thresholds.max_function_params as usize;
    snapshot
        .functions
        .iter()
        .filter(|f| f.param_count > max)
        .map(|f| {
            let over = (f.param_count - max) as u32;
            let penalty = ((over * 3) + 2).min(8);
            fn_hit(
                f,
                format!(
                    "function `{}` takes many parameters ({}, limit {})",
                    f.name, f.param_count, max
                ),
                "group related parameters into a struct or options object",
                penalty,
            )
        })
        .collect()
}

/// A function that is both very long and highly branchy — a "does too much"
/// outlier worth calling out beyond the individual length/complexity rules.
fn rule_god_function(snapshot: &RepositorySnapshot, config: &ReviewConfig) -> Vec<RuleHit> {
    let max_lines = config.thresholds.max_function_lines as usize;
    let max_cc = config.thresholds.max_cyclomatic as usize;
    snapshot
        .functions
        .iter()
        .filter(|f| f.lines > max_lines * 2 && f.cyclomatic > max_cc)
        .map(|f| {
            fn_hit(
                f,
                format!(
                    "god function `{}` ({} lines, cyclomatic ~{}) — does too much",
                    f.name, f.lines, f.cyclomatic
                ),
                "split it into smaller functions with single responsibilities",
                6,
            )
        })
        .collect()
}

fn rule_unused_parameter(snapshot: &RepositorySnapshot, _config: &ReviewConfig) -> Vec<RuleHit> {
    let unused_total: usize = snapshot
        .functions
        .iter()
        .map(|f| f.unused_params.len())
        .sum();
    let with_unused = snapshot
        .functions
        .iter()
        .filter(|f| !f.unused_params.is_empty())
        .count();
    if with_unused == 0 {
        return Vec::new();
    }
    vec![hit(
        None,
        format!(
            "{} unused parameter(s) across {} function(s)",
            unused_total, with_unused
        ),
        "remove unused parameters or prefix them with `_`",
        (unused_total as u32).min(8),
    )]
}

fn rule_dead_code(snapshot: &RepositorySnapshot, _config: &ReviewConfig) -> Vec<RuleHit> {
    let sources = source_path_set(snapshot);
    let dead: Vec<&str> = snapshot
        .functions
        .iter()
        .filter(|f| is_dead_code_candidate(f, sources.contains(f.file.as_str())))
        .map(|f| f.name.as_str())
        .collect();
    if dead.is_empty() {
        return Vec::new();
    }
    let named = dead.iter().take(3).copied().collect::<Vec<_>>().join(", ");
    let more = dead.len().saturating_sub(3);
    let suffix = if more > 0 {
        format!(" (+{more} more)")
    } else {
        String::new()
    };
    vec![hit(
        None,
        format!(
            "{} function(s) appear unreferenced — possible dead code: {}{}",
            dead.len(),
            named,
            suffix
        ),
        "remove them, or confirm they are public API / entry points",
        (dead.len() as u32 * 2).min(12),
    )]
}

fn rule_empty_guard(snapshot: &RepositorySnapshot, _config: &ReviewConfig) -> Vec<RuleHit> {
    snapshot
        .functions
        .iter()
        .filter(|f| f.signals.empty_blocks > 0)
        .map(|f| {
            fn_hit(
                f,
                format!(
                    "empty guard/branch in `{}` ({} empty block(s))",
                    f.name, f.signals.empty_blocks
                ),
                "remove the empty branch or handle the case explicitly",
                3,
            )
        })
        .collect()
}

fn rule_large_file(snapshot: &RepositorySnapshot, config: &ReviewConfig) -> Vec<RuleHit> {
    let max = config.thresholds.max_file_lines as usize;
    let Some(file) = snapshot
        .files
        .iter()
        .filter(|f| f.is_source())
        .max_by_key(|f| f.lines)
    else {
        return Vec::new();
    };
    if file.lines <= max {
        return Vec::new();
    }
    let over = (file.lines - max) as u32;
    let penalty = ((over / 50) + 1).min(20);
    vec![hit(
        Some(file.path.clone()),
        format!(
            "file is over the configured limit ({} > {} lines)",
            file.lines, max
        ),
        "split the file into smaller units",
        penalty,
    )]
}

fn rule_long_line(snapshot: &RepositorySnapshot, config: &ReviewConfig) -> Vec<RuleHit> {
    let max = config.thresholds.max_long_lines as usize;
    let Some((file, max_len)) = max_source_line_length(snapshot) else {
        return Vec::new();
    };
    if max_len <= max {
        return Vec::new();
    }
    let over = (max_len - max) as u32;
    let penalty = ((over / 20) + 1).min(12);
    vec![hit(
        Some(file),
        format!(
            "contains very long lines (max {} chars, limit {})",
            max_len, max
        ),
        "wrap long expressions or break chained calls into lines",
        penalty,
    )]
}

fn rule_todo_fixme(snapshot: &RepositorySnapshot, _config: &ReviewConfig) -> Vec<RuleHit> {
    let (todos, todo_at) = scan_pattern(snapshot, "TODO", is_source);
    let (fixmes, fixme_at) = scan_pattern(snapshot, "FIXME", is_source);
    let count = todos + fixmes;
    if count == 0 {
        return Vec::new();
    }
    vec![hit(
        todo_at.or(fixme_at),
        format!("found {} TODO/FIXME markers", count),
        "replace temporary notes with proper work items",
        (count as u32 * 2).min(16),
    )]
}

// --------------------------------------------------------------------------
// Rust rules
// --------------------------------------------------------------------------

fn rule_panic_prone(snapshot: &RepositorySnapshot, config: &ReviewConfig) -> Vec<RuleHit> {
    let t = &config.thresholds;
    // (needle, per-occurrence penalty weight, label, soft limit)
    let patterns: [(&str, i32, &str, usize); 5] = [
        ("unwrap(", 6, "unwrap", t.max_unwrap_count as usize),
        ("expect(", 5, "expect", t.max_expect_count as usize),
        ("panic!(", 10, "panic!", t.max_panic_count as usize),
        ("todo!(", 8, "todo!", 0),
        ("unimplemented!(", 8, "unimplemented!", 0),
    ];
    let mut hits = Vec::new();
    for (needle, weight, label, limit) in patterns {
        let (count, offender) = scan_pattern(snapshot, needle, is_rust_source);
        if count == 0 || (limit > 0 && count <= limit) {
            continue;
        }
        let over = if limit > 0 { count - limit } else { count };
        let penalty = (((over as i32) * weight) / 2).min(30) as u32;
        hits.push(hit(
            offender,
            format!("found {} occurrence(s) of {} in Rust source", count, label),
            "replace panic-prone code with proper Result handling",
            penalty,
        ));
    }
    hits
}

fn rule_unsafe_block(snapshot: &RepositorySnapshot, _config: &ReviewConfig) -> Vec<RuleHit> {
    snapshot
        .functions
        .iter()
        .filter(|f| f.signals.unsafe_count > 0)
        .map(|f| {
            let penalty = (f.signals.unsafe_count as u32 * 5).min(15);
            fn_hit(
                f,
                format!(
                    "`{}` uses {} unsafe block(s)",
                    f.name, f.signals.unsafe_count
                ),
                "document the safety invariants, or use a safe abstraction instead",
                penalty,
            )
        })
        .collect()
}

fn rule_excessive_clone(snapshot: &RepositorySnapshot, config: &ReviewConfig) -> Vec<RuleHit> {
    let max = config.thresholds.max_clone_count as usize;
    let (count, offender) = scan_pattern(snapshot, ".clone()", is_rust_source);
    if count <= max {
        return Vec::new();
    }
    let over = (count - max) as u32;
    let penalty = ((over / 2) + 1).min(15);
    vec![hit(
        offender,
        format!(
            "found {} clone call(s) in Rust source (limit {})",
            count, max
        ),
        "check whether expensive cloning can be replaced with borrowing",
        penalty,
    )]
}

// --------------------------------------------------------------------------
// Frontend rules
// --------------------------------------------------------------------------

fn rule_complex_expression(snapshot: &RepositorySnapshot, config: &ReviewConfig) -> Vec<RuleHit> {
    let max_bool = config.thresholds.max_bool_operands as usize;
    let max_ternary = config.thresholds.max_ternary_depth as usize;
    snapshot
        .functions
        .iter()
        .filter_map(|f| {
            let bool_over = f.signals.max_bool_chain > max_bool;
            let ternary_over = f.signals.max_ternary_depth > max_ternary;
            if !bool_over && !ternary_over {
                return None;
            }
            let message = if bool_over {
                format!(
                    "complex boolean expression in `{}` ({} operands, limit {})",
                    f.name, f.signals.max_bool_chain, max_bool
                )
            } else {
                format!(
                    "deeply nested ternary in `{}` (depth {}, limit {})",
                    f.name, f.signals.max_ternary_depth, max_ternary
                )
            };
            Some(fn_hit(
                f,
                message,
                "extract the condition into a named variable or helper",
                3,
            ))
        })
        .collect()
}

/// RxJS subscriptions with no visible teardown leak. A subscription is treated
/// as cleaned up if the same function shows teardown (`takeUntil`, `unsubscribe`,
/// `.add(`, a `Subscription`) — or, since teardown often lives in a sibling
/// lifecycle method, if the file mentions any of those anywhere.
fn rule_subscribe_clean(snapshot: &RepositorySnapshot, _config: &ReviewConfig) -> Vec<RuleHit> {
    let file_has_cleanup = |path: &str| {
        snapshot
            .files
            .iter()
            .find(|f| f.path == path)
            .and_then(|f| f.content.as_deref())
            .map(file_mentions_cleanup)
            .unwrap_or(false)
    };
    snapshot
        .functions
        .iter()
        .filter(|f| f.signals.subscribe_calls > 0 && !f.signals.subscribe_cleanup)
        .filter(|f| !file_has_cleanup(&f.file))
        .map(|f| {
            fn_hit(
                f,
                format!(
                    "`{}` subscribes ({} call(s)) without visible cleanup — possible memory leak",
                    f.name, f.signals.subscribe_calls
                ),
                "store the Subscription and unsubscribe, or use takeUntil / the async pipe",
                6,
            )
        })
        .collect()
}

fn file_mentions_cleanup(content: &str) -> bool {
    ["unsubscribe", "takeUntil", "Subscription", "DestroyRef"]
        .iter()
        .any(|token| content.contains(token))
}

fn rule_console_log(snapshot: &RepositorySnapshot, _config: &ReviewConfig) -> Vec<RuleHit> {
    let total: usize = snapshot
        .functions
        .iter()
        .map(|f| f.signals.console_calls)
        .sum();
    if total == 0 {
        return Vec::new();
    }
    let offender = snapshot
        .functions
        .iter()
        .filter(|f| f.signals.console_calls > 0)
        .max_by_key(|f| f.signals.console_calls)
        .map(|f| f.file.clone());
    vec![hit(
        offender,
        format!("{} console call(s) left in source", total),
        "remove debug logging or route it through a proper logger",
        (total as u32).min(6),
    )]
}

fn rule_no_explicit_any(snapshot: &RepositorySnapshot, _config: &ReviewConfig) -> Vec<RuleHit> {
    snapshot
        .functions
        .iter()
        .filter(|f| f.signals.any_types > 0)
        .map(|f| {
            fn_hit(
                f,
                format!(
                    "`{}` uses the `any` type {} time(s)",
                    f.name, f.signals.any_types
                ),
                "give a precise type, or use `unknown` and narrow it",
                (f.signals.any_types as u32 * 2).min(10),
            )
        })
        .collect()
}

fn rule_unsafe_cast(snapshot: &RepositorySnapshot, config: &ReviewConfig) -> Vec<RuleHit> {
    let max_casts = config.thresholds.max_as_casts as usize;
    snapshot
        .functions
        .iter()
        .filter(|f| f.signals.unknown_casts > 0 || f.signals.as_casts > max_casts)
        .map(|f| {
            let (message, penalty) = if f.signals.unknown_casts > 0 {
                (
                    format!(
                        "`{}` force-casts via `as unknown as` ({}x) — bypasses the type system",
                        f.name, f.signals.unknown_casts
                    ),
                    (f.signals.unknown_casts as u32 * 4).min(12),
                )
            } else {
                (
                    format!(
                        "`{}` has many type assertions ({} `as` casts, limit {})",
                        f.name, f.signals.as_casts, max_casts
                    ),
                    ((f.signals.as_casts - max_casts) as u32 + 1).min(8),
                )
            };
            fn_hit(
                f,
                message,
                "prefer real types or runtime validation over casts",
                penalty,
            )
        })
        .collect()
}

fn rule_non_null_assertion(snapshot: &RepositorySnapshot, config: &ReviewConfig) -> Vec<RuleHit> {
    let max = config.thresholds.max_non_null_assertions as usize;
    snapshot
        .functions
        .iter()
        .filter(|f| f.signals.non_null_assertions > max)
        .map(|f| {
            fn_hit(
                f,
                format!(
                    "`{}` uses the `!` non-null assertion {} time(s) (limit {})",
                    f.name, f.signals.non_null_assertions, max
                ),
                "guard the value with a check instead of asserting non-null",
                ((f.signals.non_null_assertions - max) as u32 + 1).min(8),
            )
        })
        .collect()
}

/// A `.then(...)` chain with no `.catch(...)` in the same function — a rejected
/// promise will go unhandled.
fn rule_unhandled_promise(snapshot: &RepositorySnapshot, _config: &ReviewConfig) -> Vec<RuleHit> {
    snapshot
        .functions
        .iter()
        .filter(|f| f.signals.then_calls > 0 && f.signals.catch_calls == 0)
        .map(|f| {
            fn_hit(
                f,
                format!(
                    "`{}` chains `.then(...)` without a `.catch(...)` — rejections go unhandled",
                    f.name
                ),
                "add a `.catch(...)`, or use try/await with error handling",
                5,
            )
        })
        .collect()
}

fn rule_react_effect_deps(snapshot: &RepositorySnapshot, _config: &ReviewConfig) -> Vec<RuleHit> {
    snapshot
        .functions
        .iter()
        .filter(|f| f.signals.use_effect_missing_deps > 0)
        .map(|f| {
            fn_hit(
                f,
                format!(
                    "`{}` calls useEffect with no dependency array ({}x) — runs every render",
                    f.name, f.signals.use_effect_missing_deps
                ),
                "pass a dependency array (`[]` for run-once, or the real deps)",
                4,
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::model::{
        FunctionSignals, FunctionSnapshot, RepositoryProfile, RepositorySnapshot,
    };

    fn func(
        name: &str,
        lines: usize,
        cyclomatic: usize,
        signals: FunctionSignals,
    ) -> FunctionSnapshot {
        FunctionSnapshot {
            file: "src/a.ts".to_string(),
            name: name.to_string(),
            language: "typescript",
            start_line: 1,
            end_line: lines,
            lines,
            param_count: 0,
            params: Vec::new(),
            unused_params: Vec::new(),
            cyclomatic,
            max_nesting: 0,
            references: 1,
            referenced_by: Vec::new(),
            signals,
        }
    }

    fn snapshot(functions: Vec<FunctionSnapshot>) -> RepositorySnapshot {
        RepositorySnapshot::new(
            RepositoryProfile::new("r", 0, 0, 0, 0),
            Vec::new(),
            functions,
            Vec::new(),
            None,
        )
    }

    #[test]
    fn subscribe_without_cleanup_is_flagged() {
        let signals = FunctionSignals {
            subscribe_calls: 1,
            ..FunctionSignals::default()
        };
        let snap = snapshot(vec![func("ngOnInit", 5, 1, signals)]);
        let findings = evaluate(&snap, &ReviewConfig::default());
        assert!(findings.iter().any(|f| f.rule == Some("subscribe-clean")));
    }

    #[test]
    fn complex_expression_is_flagged() {
        let signals = FunctionSignals {
            max_bool_chain: 6,
            ..FunctionSignals::default()
        };
        let snap = snapshot(vec![func("validate", 5, 1, signals)]);
        let findings = evaluate(&snap, &ReviewConfig::default());
        let f = findings
            .iter()
            .find(|f| f.rule == Some("complex-expression"))
            .expect("complex-expression should fire");
        assert_eq!(f.metric, "maintainability");
        assert_eq!(f.category, "Complexity");
    }

    #[test]
    fn disabling_a_rule_suppresses_it() {
        let signals = FunctionSignals {
            max_bool_chain: 6,
            ..FunctionSignals::default()
        };
        let snap = snapshot(vec![func("validate", 5, 1, signals)]);
        let mut config = ReviewConfig::default();
        config.rules.disable.push("complex-expression".to_string());
        let findings = evaluate(&snap, &config);
        assert!(
            !findings
                .iter()
                .any(|f| f.rule == Some("complex-expression"))
        );
    }

    #[test]
    fn turning_off_a_language_group_suppresses_its_rules() {
        let signals = FunctionSignals {
            subscribe_calls: 1,
            ..FunctionSignals::default()
        };
        let snap = snapshot(vec![func("ngOnInit", 5, 1, signals)]);
        let mut config = ReviewConfig::default();
        config.rules.frontend = false;
        let findings = evaluate(&snap, &config);
        assert!(!findings.iter().any(|f| f.rule == Some("subscribe-clean")));
    }

    #[test]
    fn long_function_penalty_targets_maintainability() {
        let snap = snapshot(vec![func("big", 500, 1, FunctionSignals::default())]);
        let findings = evaluate(&snap, &ReviewConfig::default());
        let f = findings
            .iter()
            .find(|f| f.rule == Some("long-function"))
            .expect("long-function should fire");
        assert_eq!(f.metric, "maintainability");
        assert!(f.score_penalty > 0);
    }

    #[test]
    fn explicit_any_is_flagged_as_type_safety_with_line() {
        let signals = FunctionSignals {
            any_types: 2,
            ..FunctionSignals::default()
        };
        let mut function = func("parse", 5, 1, signals);
        function.start_line = 42;
        let snap = snapshot(vec![function]);
        let findings = evaluate(&snap, &ReviewConfig::default());
        let f = findings
            .iter()
            .find(|f| f.rule == Some("no-explicit-any"))
            .expect("no-explicit-any should fire");
        assert_eq!(f.category, "Type safety");
        assert_eq!(f.metric, "robustness");
        assert_eq!(f.line, Some(42));
    }

    #[test]
    fn unsafe_double_cast_is_flagged() {
        let signals = FunctionSignals {
            unknown_casts: 1,
            ..FunctionSignals::default()
        };
        let snap = snapshot(vec![func("coerce", 5, 1, signals)]);
        let findings = evaluate(&snap, &ReviewConfig::default());
        assert!(findings.iter().any(|f| f.rule == Some("unsafe-cast")));
    }

    #[test]
    fn then_without_catch_is_unhandled_promise() {
        let signals = FunctionSignals {
            then_calls: 1,
            catch_calls: 0,
            ..FunctionSignals::default()
        };
        let snap = snapshot(vec![func("load", 5, 1, signals)]);
        let findings = evaluate(&snap, &ReviewConfig::default());
        let f = findings
            .iter()
            .find(|f| f.rule == Some("unhandled-promise"))
            .expect("unhandled-promise should fire");
        assert_eq!(f.category, "Error handling");
    }

    #[test]
    fn then_with_catch_is_not_flagged() {
        let signals = FunctionSignals {
            then_calls: 1,
            catch_calls: 1,
            ..FunctionSignals::default()
        };
        let snap = snapshot(vec![func("load", 5, 1, signals)]);
        let findings = evaluate(&snap, &ReviewConfig::default());
        assert!(!findings.iter().any(|f| f.rule == Some("unhandled-promise")));
    }

    #[test]
    fn use_effect_without_deps_is_react_risk() {
        let signals = FunctionSignals {
            use_effect_missing_deps: 1,
            ..FunctionSignals::default()
        };
        let snap = snapshot(vec![func("Widget", 5, 1, signals)]);
        let findings = evaluate(&snap, &ReviewConfig::default());
        assert!(
            findings
                .iter()
                .any(|f| f.rule == Some("react-effect-deps") && f.category == "React")
        );
    }
}
