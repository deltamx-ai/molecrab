use std::collections::HashSet;

use super::config::ReviewConfig;
use super::model::{
    FileSnapshot, Finding, MetricResult, RepositorySnapshot, Severity, is_dead_code_candidate,
};

pub trait Metric {
    fn name(&self) -> &'static str;
    fn weight(&self) -> u8;
    fn analyze(&self, snapshot: &RepositorySnapshot, config: &ReviewConfig) -> MetricResult;
}

pub fn builtin_metrics() -> Vec<Box<dyn Metric>> {
    vec![
        Box::new(ReadabilityMetric),
        Box::new(MaintainabilityMetric),
        Box::new(RobustnessMetric),
        Box::new(PerformanceMetric),
        Box::new(TestabilityMetric),
    ]
}

pub fn evaluate(snapshot: &RepositorySnapshot, config: &ReviewConfig) -> Vec<MetricResult> {
    builtin_metrics()
        .into_iter()
        .map(|metric| metric.analyze(snapshot, config))
        .collect()
}

struct ReadabilityMetric;
struct MaintainabilityMetric;
struct RobustnessMetric;
struct PerformanceMetric;
struct TestabilityMetric;

impl Metric for ReadabilityMetric {
    fn name(&self) -> &'static str {
        "readability"
    }

    fn weight(&self) -> u8 {
        25
    }

    fn analyze(&self, snapshot: &RepositorySnapshot, config: &ReviewConfig) -> MetricResult {
        let mut score: i32 = 100;
        let mut findings = Vec::new();
        let max_file_lines = config.thresholds.max_file_lines as usize;
        let max_long_lines = config.thresholds.max_long_lines as usize;

        // Largest *source* file — generated files (lock files, bundles) are not
        // something a human should split up, so they are excluded.
        if let Some(file) = snapshot
            .files
            .iter()
            .filter(|file| file.is_source())
            .max_by_key(|file| file.lines)
            && file.lines > max_file_lines
        {
            let over = file.lines.saturating_sub(max_file_lines);
            let deduction = ((over as i32 / 50) + 1).min(20);
            score -= deduction;
            findings.push(finding(
                Severity::Warning,
                Some(file.path.clone()),
                self.name(),
                format!(
                    "file is over the configured limit ({} > {} lines)",
                    file.lines, max_file_lines
                ),
                "split the file into smaller units",
                deduction as u32,
            ));
        }

        let (todo_count, todo_file) = {
            let (todos, todo_at) = scan_pattern(snapshot, "TODO", is_source);
            let (fixmes, fixme_at) = scan_pattern(snapshot, "FIXME", is_source);
            (todos + fixmes, todo_at.or(fixme_at))
        };
        if todo_count > 0 {
            let deduction = (todo_count as i32 * 2).min(16);
            score -= deduction;
            findings.push(finding(
                Severity::Info,
                todo_file,
                self.name(),
                format!("found {} TODO/FIXME markers", todo_count),
                "replace temporary notes with proper work items",
                deduction as u32,
            ));
        }

        if let Some((file, max_len)) = max_source_line_length(snapshot)
            && max_len > max_long_lines
        {
            let over = max_len.saturating_sub(max_long_lines);
            let deduction = ((over as i32 / 20) + 1).min(12);
            score -= deduction;
            findings.push(finding(
                Severity::Warning,
                Some(file),
                self.name(),
                format!(
                    "contains very long lines (max {} chars, limit {})",
                    max_len, max_long_lines
                ),
                "wrap long expressions or break chained calls into lines",
                deduction as u32,
            ));
        }

        MetricResult {
            name: self.name(),
            weight: self.weight(),
            score: clamp_score(score),
            findings,
        }
    }
}

impl Metric for MaintainabilityMetric {
    fn name(&self) -> &'static str {
        "maintainability"
    }

    fn weight(&self) -> u8 {
        25
    }

    fn analyze(&self, snapshot: &RepositorySnapshot, config: &ReviewConfig) -> MetricResult {
        let mut score: i32 = 100;
        let mut findings = Vec::new();
        let max_path_depth = config.thresholds.max_path_depth as usize;
        let max_source_files = config.thresholds.max_source_file_count as usize;

        // Count first-party source, not lock files / docs / vendored code.
        let source_count = snapshot.profile().source_file_count();
        if source_count > max_source_files {
            let over = source_count.saturating_sub(max_source_files);
            let deduction = ((over as i32 / 10) + 8).min(20);
            score -= deduction;
            findings.push(finding(
                Severity::Warning,
                None,
                self.name(),
                format!(
                    "repository has many source files ({} over limit {})",
                    source_count, max_source_files
                ),
                "consider grouping related logic and pruning dead files",
                deduction as u32,
            ));
        } else if source_count > max_source_files / 2 {
            score -= 8;
            findings.push(finding(
                Severity::Info,
                None,
                self.name(),
                format!(
                    "source tree is growing ({} files, threshold {})",
                    source_count, max_source_files
                ),
                "keep modules focused and boundaries clear",
                8,
            ));
        }

        if let Some(file) = snapshot
            .files
            .iter()
            .filter(|file| file.is_source())
            .max_by_key(|file| file.depth)
            && file.depth > max_path_depth
        {
            let over = file.depth.saturating_sub(max_path_depth);
            let deduction = ((over as i32 / 2) + 1).min(15);
            score -= deduction;
            findings.push(finding(
                Severity::Warning,
                Some(file.path.clone()),
                self.name(),
                format!(
                    "deep file path (depth {}, limit {})",
                    file.depth, max_path_depth
                ),
                "flatten directory nesting where possible",
                deduction as u32,
            ));
        }

        check_function_health(snapshot, config, self.name(), &mut score, &mut findings);

        MetricResult {
            name: self.name(),
            weight: self.weight(),
            score: clamp_score(score),
            findings,
        }
    }
}

impl Metric for RobustnessMetric {
    fn name(&self) -> &'static str {
        "robustness"
    }

    fn weight(&self) -> u8 {
        20
    }

    fn analyze(&self, snapshot: &RepositorySnapshot, config: &ReviewConfig) -> MetricResult {
        let mut score: i32 = 100;
        let mut findings = Vec::new();
        let max_unwrap_count = config.thresholds.max_unwrap_count as usize;
        let max_expect_count = config.thresholds.max_expect_count as usize;
        let max_panic_count = config.thresholds.max_panic_count as usize;

        // These are Rust-specific panic-prone patterns. Scanning them across the
        // whole repo would, for example, count Jest/Vitest `expect(...)` test
        // assertions — so they are only counted in Rust source files.
        for (needle, penalty, label, limit) in [
            ("unwrap(", 6, "unwrap", max_unwrap_count),
            ("expect(", 5, "expect", max_expect_count),
            ("panic!(", 10, "panic!", max_panic_count),
            ("todo!(", 8, "todo!", 0usize),
            ("unimplemented!(", 8, "unimplemented!", 0usize),
        ] {
            let (count, offender) = scan_pattern(snapshot, needle, is_rust_source);
            if count == 0 || (limit > 0 && count <= limit) {
                continue;
            }

            let over = if limit > 0 {
                count.saturating_sub(limit)
            } else {
                count
            };
            let deduction = ((over as i32 * penalty) / 2).min(30);
            score -= deduction;
            findings.push(finding(
                Severity::Warning,
                offender,
                self.name(),
                format!("found {} occurrence(s) of {} in Rust source", count, label),
                "replace panic-prone code with proper Result handling",
                deduction as u32,
            ));
        }

        MetricResult {
            name: self.name(),
            weight: self.weight(),
            score: clamp_score(score),
            findings,
        }
    }
}

impl Metric for PerformanceMetric {
    fn name(&self) -> &'static str {
        "performance"
    }

    fn weight(&self) -> u8 {
        15
    }

    fn analyze(&self, snapshot: &RepositorySnapshot, config: &ReviewConfig) -> MetricResult {
        let mut score: i32 = 100;
        let mut findings = Vec::new();
        let max_clone_count = config.thresholds.max_clone_count as usize;
        let max_source_files = config.thresholds.max_source_file_count as usize;

        let (clone_count, offender) = scan_pattern(snapshot, ".clone()", is_rust_source);
        if clone_count > max_clone_count {
            let over = clone_count.saturating_sub(max_clone_count);
            let deduction = ((over as i32) / 2 + 1).min(15);
            score -= deduction;
            findings.push(finding(
                Severity::Info,
                offender,
                self.name(),
                format!(
                    "found {} clone call(s) in Rust source (limit {})",
                    clone_count, max_clone_count
                ),
                "check whether expensive cloning can be replaced with borrowing",
                deduction as u32,
            ));
        }

        let source_count = snapshot.profile().source_file_count();
        if source_count > max_source_files {
            score -= 8;
            findings.push(finding(
                Severity::Info,
                None,
                self.name(),
                format!(
                    "analysis surface is large ({} source files, limit {})",
                    source_count, max_source_files
                ),
                "watch for repeated scans or duplicate reads in hot paths",
                8,
            ));
        }

        MetricResult {
            name: self.name(),
            weight: self.weight(),
            score: clamp_score(score),
            findings,
        }
    }
}

impl Metric for TestabilityMetric {
    fn name(&self) -> &'static str {
        "testability"
    }

    fn weight(&self) -> u8 {
        15
    }

    fn analyze(&self, snapshot: &RepositorySnapshot, config: &ReviewConfig) -> MetricResult {
        let mut score: i32 = 100;
        let mut findings = Vec::new();
        let min_test_indicators = config.thresholds.min_test_indicators as usize;

        let test_indicators = scan_pattern(snapshot, "#[test]", is_first_party).0
            + scan_pattern(snapshot, "#[cfg(test)]", is_first_party).0
            + snapshot.profile().test_file_count();

        if test_indicators < min_test_indicators {
            let missing = min_test_indicators.saturating_sub(test_indicators);
            let deduction = 35.min((missing as i32) * 10 + 5);
            score -= deduction;
            findings.push(finding(
                Severity::Error,
                None,
                self.name(),
                format!(
                    "test indicators below configured minimum ({} < {})",
                    test_indicators, min_test_indicators
                ),
                "add unit tests or integration tests around core logic",
                deduction as u32,
            ));
        } else if test_indicators < 3 {
            score -= 12;
            findings.push(finding(
                Severity::Warning,
                None,
                self.name(),
                format!("only {} test indicator(s) found", test_indicators),
                "add a few more focused tests around important flows",
                12,
            ));
        }

        MetricResult {
            name: self.name(),
            weight: self.weight(),
            score: clamp_score(score),
            findings,
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn finding(
    severity: Severity,
    file: Option<String>,
    metric: &'static str,
    message: impl Into<String>,
    suggestion: impl Into<String>,
    score_penalty: u32,
) -> Finding {
    Finding {
        severity,
        file,
        metric,
        message: message.into(),
        suggestion: suggestion.into(),
        score_penalty,
    }
}

fn clamp_score(score: i32) -> u8 {
    score.clamp(0, 100) as u8
}

/// Flags the worst long function and the worst over-parameterized function as
/// maintainability findings, so function quality shows up in the priorities.
fn check_function_health(
    snapshot: &RepositorySnapshot,
    config: &ReviewConfig,
    metric: &'static str,
    score: &mut i32,
    findings: &mut Vec<Finding>,
) {
    let max_lines = config.thresholds.max_function_lines as usize;
    let max_params = config.thresholds.max_function_params as usize;

    if let Some(func) = snapshot.functions.iter().max_by_key(|f| f.lines)
        && func.lines > max_lines
    {
        let over = func.lines - max_lines;
        let deduction = ((over as i32 / 40) + 4).min(15);
        *score -= deduction;
        findings.push(finding(
            Severity::Warning,
            Some(func.file.clone()),
            metric,
            format!(
                "long function `{}` ({} lines, limit {})",
                func.name, func.lines, max_lines
            ),
            "break it into smaller, focused functions",
            deduction as u32,
        ));
    }

    if let Some(func) = snapshot.functions.iter().max_by_key(|f| f.param_count)
        && func.param_count > max_params
    {
        let over = func.param_count - max_params;
        let deduction = ((over as i32 * 3) + 3).min(12);
        *score -= deduction;
        findings.push(finding(
            Severity::Warning,
            Some(func.file.clone()),
            metric,
            format!(
                "function `{}` takes many parameters ({}, limit {})",
                func.name, func.param_count, max_params
            ),
            "group related parameters into a struct or options object",
            deduction as u32,
        ));
    }

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
    if with_unused > 0 {
        let deduction = (unused_total as i32).min(8);
        *score -= deduction;
        findings.push(finding(
            Severity::Info,
            None,
            metric,
            format!(
                "{} unused parameter(s) across {} function(s)",
                unused_total, with_unused
            ),
            "remove unused parameters or prefix them with `_`",
            deduction as u32,
        ));
    }

    let source_paths: HashSet<&str> = snapshot
        .files
        .iter()
        .filter(|f| f.is_source())
        .map(|f| f.path.as_str())
        .collect();
    let dead = snapshot
        .functions
        .iter()
        .filter(|f| is_dead_code_candidate(f, source_paths.contains(f.file.as_str())))
        .count();
    if dead > 0 {
        let deduction = (dead as i32 * 2).min(12);
        *score -= deduction;
        findings.push(finding(
            Severity::Info,
            None,
            metric,
            format!(
                "{} function(s) appear unreferenced (possible dead code)",
                dead
            ),
            "remove them, or confirm they are public API / entry points",
            deduction as u32,
        ));
    }
}

fn is_source(file: &FileSnapshot) -> bool {
    file.is_source()
}

fn is_rust_source(file: &FileSnapshot) -> bool {
    file.is_source() && file.name.ends_with(".rs")
}

fn is_first_party(file: &FileSnapshot) -> bool {
    file.is_first_party_code()
}

/// Counts occurrences of `needle` across the files matching `pred`, returning
/// the total and the path of the file with the most occurrences (the real top
/// offender, rather than just the first file that happened to match).
fn scan_pattern<P>(snapshot: &RepositorySnapshot, needle: &str, pred: P) -> (usize, Option<String>)
where
    P: Fn(&FileSnapshot) -> bool,
{
    let mut total = 0usize;
    let mut top: Option<(String, usize)> = None;
    for file in &snapshot.files {
        if !pred(file) {
            continue;
        }
        let Some(content) = file.content.as_deref() else {
            continue;
        };
        let count = content.matches(needle).count();
        if count == 0 {
            continue;
        }
        total += count;
        if top.as_ref().is_none_or(|(_, best)| count > *best) {
            top = Some((file.path.clone(), count));
        }
    }
    (total, top.map(|(path, _)| path))
}

fn max_source_line_length(snapshot: &RepositorySnapshot) -> Option<(String, usize)> {
    snapshot
        .files
        .iter()
        .filter(|file| file.is_source())
        .filter_map(|file| {
            file.content.as_deref().map(|content| {
                let max_len = content
                    .lines()
                    .map(|line| line.chars().count())
                    .max()
                    .unwrap_or(0);
                (file.path.clone(), max_len)
            })
        })
        .max_by_key(|(_, len)| *len)
}
