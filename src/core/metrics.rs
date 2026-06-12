use super::config::ReviewConfig;
use super::model::{FileSnapshot, Finding, MetricResult, RepositorySnapshot, Severity};

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

/// Scores every metric, then folds the rule layer's findings into the scores.
///
/// Each metric first computes its *structural* base score and findings (repo
/// shape: file count, path depth, test indicators). The per-function / per-file
/// lint-like checks live in `core::rules`; their findings are distributed here,
/// each one deducting its penalty from the metric it targets. This keeps the
/// rule registry as the single home for those checks while the scores stay here.
pub fn evaluate(snapshot: &RepositorySnapshot, config: &ReviewConfig) -> Vec<MetricResult> {
    let mut results: Vec<MetricResult> = builtin_metrics()
        .into_iter()
        .map(|metric| metric.analyze(snapshot, config))
        .collect();
    fold_rule_findings(&mut results, super::rules::evaluate(snapshot, config));
    results
}

/// Distributes rule findings onto the metric each one targets, deducting its
/// penalty (re-clamped) and attaching the finding for the report.
fn fold_rule_findings(results: &mut [MetricResult], findings: Vec<Finding>) {
    for finding in findings {
        if let Some(metric) = results.iter_mut().find(|m| m.name == finding.metric) {
            metric.score = clamp_score(i32::from(metric.score) - finding.score_penalty as i32);
            metric.findings.push(finding);
        }
    }
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

    fn analyze(&self, _snapshot: &RepositorySnapshot, _config: &ReviewConfig) -> MetricResult {
        // Readability has no repo-shape structural check of its own; its score is
        // driven entirely by rules (large-file / long-line / todo-fixme /
        // console-log) folded in by `evaluate`.
        MetricResult {
            name: self.name(),
            weight: self.weight(),
            score: 100,
            findings: Vec::new(),
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

    fn analyze(&self, _snapshot: &RepositorySnapshot, _config: &ReviewConfig) -> MetricResult {
        // Robustness has no structural check; its score comes from rules
        // (panic-prone / unsafe-block / empty-guard / subscribe-clean).
        MetricResult {
            name: self.name(),
            weight: self.weight(),
            score: 100,
            findings: Vec::new(),
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
        let max_source_files = config.thresholds.max_source_file_count as usize;

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
    let message = message.into();
    let category = category_for(metric, &message);
    Finding {
        severity,
        file,
        metric,
        category,
        rule: None,
        line: None,
        message,
        suggestion: suggestion.into(),
        score_penalty,
    }
}

/// Maps a finding to a reviewer-facing problem category — "what kind of problem
/// is this". Most metrics map to one category; maintainability splits by what
/// the finding is actually about. Kept in one place so the taxonomy is easy to
/// read and change (and is locked by a test).
fn category_for(metric: &str, message: &str) -> &'static str {
    match metric {
        "robustness" => "Error handling",
        "performance" => "Performance",
        "testability" => "Testing",
        "readability" => {
            if message.contains("TODO") || message.contains("FIXME") {
                "Hygiene"
            } else {
                "Readability"
            }
        }
        "maintainability" => {
            if message.contains("unused parameter") || message.contains("unreferenced") {
                "Dead code"
            } else if message.starts_with("long function")
                || message.contains("many parameters")
                || message.starts_with("complex function")
                || message.contains("nested")
            {
                "Complexity"
            } else {
                "Structure"
            }
        }
        _ => "Other",
    }
}

fn clamp_score(score: i32) -> u8 {
    score.clamp(0, 100) as u8
}

pub(crate) fn is_source(file: &FileSnapshot) -> bool {
    file.is_source()
}

pub(crate) fn is_rust_source(file: &FileSnapshot) -> bool {
    file.is_source() && file.name.ends_with(".rs")
}

fn is_first_party(file: &FileSnapshot) -> bool {
    file.is_first_party_code()
}

/// Counts occurrences of `needle` across the files matching `pred`, returning
/// the total and the path of the file with the most occurrences (the real top
/// offender, rather than just the first file that happened to match).
pub(crate) fn scan_pattern<P>(
    snapshot: &RepositorySnapshot,
    needle: &str,
    pred: P,
) -> (usize, Option<String>)
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

/// Like [`scan_pattern`] but restricted to Rust source and run over a
/// comment/string-stripped copy of each file, so panic-prone patterns
/// (`unwrap(`, `panic!(`, `.clone()`, …) inside comments or string literals are
/// not miscounted as real code.
pub(crate) fn scan_rust_pattern(
    snapshot: &RepositorySnapshot,
    needle: &str,
) -> (usize, Option<String>) {
    let mut total = 0usize;
    let mut top: Option<(String, usize)> = None;
    for file in &snapshot.files {
        if !is_rust_source(file) {
            continue;
        }
        let Some(content) = file.content.as_deref() else {
            continue;
        };
        let count = super::rust::strip_noise(content).matches(needle).count();
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

pub(crate) fn max_source_line_length(snapshot: &RepositorySnapshot) -> Option<(String, usize)> {
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

#[cfg(test)]
mod tests {
    use super::category_for;

    #[test]
    fn categorizes_findings_by_problem_type() {
        assert_eq!(
            category_for(
                "robustness",
                "found 22 occurrence(s) of unwrap in Rust source"
            ),
            "Error handling"
        );
        assert_eq!(
            category_for("maintainability", "long function `f` (267 lines, limit 60)"),
            "Complexity"
        );
        assert_eq!(
            category_for(
                "maintainability",
                "function `f` takes many parameters (8, limit 5)"
            ),
            "Complexity"
        );
        assert_eq!(
            category_for(
                "maintainability",
                "complex function `f` (cyclomatic ~12, limit 10)"
            ),
            "Complexity"
        );
        assert_eq!(
            category_for(
                "maintainability",
                "deeply nested function `f` (depth 6, limit 4)"
            ),
            "Complexity"
        );
        assert_eq!(
            category_for(
                "maintainability",
                "3 function(s) appear unreferenced (possible dead code)"
            ),
            "Dead code"
        );
        assert_eq!(
            category_for(
                "maintainability",
                "2 unused parameter(s) across 2 function(s)"
            ),
            "Dead code"
        );
        assert_eq!(
            category_for("maintainability", "deep file path (depth 8, limit 6)"),
            "Structure"
        );
        assert_eq!(
            category_for("readability", "found 4 TODO/FIXME markers"),
            "Hygiene"
        );
        assert_eq!(
            category_for(
                "readability",
                "file is over the configured limit (480 > 400 lines)"
            ),
            "Readability"
        );
        assert_eq!(
            category_for("testability", "test indicators below minimum"),
            "Testing"
        );
        assert_eq!(
            category_for("performance", "found 37 clone call(s)"),
            "Performance"
        );
    }
}
