use super::config::ReviewConfig;
use super::model::{Finding, MetricResult, RepositorySnapshot, Severity};

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
        Box::new(ObservabilityMetric),
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
struct ObservabilityMetric;

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

        if let Some(file) = snapshot
            .files
            .iter()
            .filter(|file| file.content.is_some())
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
            ));
        }

        let todo_count = count_pattern(snapshot, "TODO") + count_pattern(snapshot, "FIXME");
        if todo_count > 0 {
            let deduction = (todo_count as i32 * 2).min(16);
            score -= deduction;
            findings.push(finding(
                Severity::Info,
                None,
                self.name(),
                format!("found {} TODO/FIXME markers", todo_count),
                "replace temporary notes with proper work items",
            ));
        }

        if let Some((file, max_len)) = max_line_length(snapshot)
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

        let file_count = snapshot.profile().file_count();
        if file_count > max_source_files {
            let over = file_count.saturating_sub(max_source_files);
            let deduction = ((over as i32 / 10) + 8).min(20);
            score -= deduction;
            findings.push(finding(
                Severity::Warning,
                None,
                self.name(),
                format!(
                    "repository has many files ({} source-file limit {})",
                    file_count, max_source_files
                ),
                "consider grouping related logic and pruning dead files",
            ));
        } else if file_count > max_source_files / 2 {
            score -= 8;
            findings.push(finding(
                Severity::Info,
                None,
                self.name(),
                format!(
                    "repository size is growing ({} files, threshold {})",
                    file_count, max_source_files
                ),
                "keep modules focused and boundaries clear",
            ));
        }

        if let Some(file) = snapshot.files.iter().max_by_key(|file| file.depth)
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

    fn analyze(&self, snapshot: &RepositorySnapshot, config: &ReviewConfig) -> MetricResult {
        let mut score: i32 = 100;
        let mut findings = Vec::new();
        let max_unwrap_count = config.thresholds.max_unwrap_count as usize;
        let max_expect_count = config.thresholds.max_expect_count as usize;
        let max_panic_count = config.thresholds.max_panic_count as usize;

        for (needle, penalty, label, limit) in [
            ("unwrap(", 6, "unwrap", max_unwrap_count),
            ("expect(", 5, "expect", max_expect_count),
            ("panic!(", 10, "panic!", max_panic_count),
            ("todo!(", 8, "todo!", 0usize),
            ("unimplemented!(", 8, "unimplemented!", 0usize),
        ] {
            let count = count_pattern(snapshot, needle);
            if count == 0 {
                continue;
            }

            if limit > 0 && count <= limit {
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
                first_file_with_pattern(snapshot, needle),
                self.name(),
                format!("found {} occurrence(s) of {}", count, label),
                "replace panic-prone code with proper Result handling",
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

        let clone_count = count_pattern(snapshot, ".clone()");
        if clone_count > max_clone_count {
            let over = clone_count.saturating_sub(max_clone_count);
            let deduction = ((over as i32) / 2 + 1).min(15);
            score -= deduction;
            findings.push(finding(
                Severity::Info,
                first_file_with_pattern(snapshot, ".clone()"),
                self.name(),
                format!(
                    "found {} clone call(s) (limit {})",
                    clone_count, max_clone_count
                ),
                "check whether expensive cloning can be replaced with borrowing",
            ));
        }

        let file_count = snapshot.profile().source_file_count();
        if file_count > max_source_files {
            score -= 8;
            findings.push(finding(
                Severity::Info,
                None,
                self.name(),
                format!(
                    "analysis surface is large ({} source files, limit {})",
                    file_count, max_source_files
                ),
                "watch for repeated scans or duplicate reads in hot paths",
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

        let test_indicators = count_pattern(snapshot, "#[test]")
            + count_pattern(snapshot, "#[cfg(test)]")
            + snapshot.profile().test_file_count();

        if test_indicators < min_test_indicators {
            let missing = min_test_indicators.saturating_sub(test_indicators);
            score -= 35.min((missing as i32) * 10 + 5);
            findings.push(finding(
                Severity::Error,
                None,
                self.name(),
                format!(
                    "test indicators below configured minimum ({} < {})",
                    test_indicators, min_test_indicators
                ),
                "add unit tests or integration tests around core logic",
            ));
        } else if test_indicators < 3 {
            score -= 12;
            findings.push(finding(
                Severity::Warning,
                None,
                self.name(),
                format!("only {} test indicator(s) found", test_indicators),
                "add a few more focused tests around important flows",
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

impl Metric for ObservabilityMetric {
    fn name(&self) -> &'static str {
        "observability"
    }

    fn weight(&self) -> u8 {
        1
    }

    fn analyze(&self, snapshot: &RepositorySnapshot, config: &ReviewConfig) -> MetricResult {
        let mut score: i32 = 100;
        let mut findings = Vec::new();
        let enabled_targets = count_enabled_observability_targets(config);
        let total_targets = total_observability_targets();

        if enabled_targets == 0 {
            score -= 20;
            findings.push(finding(
                Severity::Info,
                None,
                self.name(),
                "all observability targets are disabled",
                "enable at least one target so the report can surface useful context",
            ));
        } else if enabled_targets < total_targets {
            let missing = total_targets - enabled_targets;
            let deduction = ((missing as i32) * 4).min(24);
            score -= deduction;
            findings.push(finding(
                Severity::Info,
                None,
                self.name(),
                format!(
                    "observability coverage enabled for {}/{} targets",
                    enabled_targets, total_targets
                ),
                "enable additional observability targets when the extra context is useful",
            ));
        }

        if config.observability.longest_file_ranking && snapshot.files.is_empty() {
            score -= 20;
            findings.push(finding(
                Severity::Warning,
                None,
                self.name(),
                "file ranking was enabled, but no files were collected",
                "verify the repository path and scanner exclusions",
            ));
        }

        if config.observability.longest_function_ranking && snapshot.functions.is_empty() {
            score -= 10;
            findings.push(finding(
                Severity::Warning,
                None,
                self.name(),
                "function ranking was enabled, but no functions were collected",
                "ensure the repository contains Rust sources that the scanner can parse",
            ));
        }

        let git_targets_enabled = git_observability_enabled(config);
        match (git_targets_enabled, snapshot.git.as_ref()) {
            (true, None) => {
                score -= 30;
                findings.push(finding(
                    Severity::Warning,
                    None,
                    self.name(),
                    "git observability was enabled, but git metadata is unavailable",
                    "run the review inside a git repository with readable history",
                ));
            }
            (true, Some(git)) if git.total_commits == 0 => {
                score -= 10;
                findings.push(finding(
                    Severity::Info,
                    None,
                    self.name(),
                    "git metadata was collected, but no commits were reported",
                    "confirm the repository has accessible commit history",
                ));
            }
            _ => {}
        }

        MetricResult {
            name: self.name(),
            weight: config.thresholds.observability_weight,
            score: clamp_score(score),
            findings,
        }
    }
}

fn finding(
    severity: Severity,
    file: Option<String>,
    metric: &'static str,
    message: impl Into<String>,
    suggestion: impl Into<String>,
) -> Finding {
    Finding {
        severity,
        file,
        metric,
        message: message.into(),
        suggestion: suggestion.into(),
    }
}

fn clamp_score(score: i32) -> u8 {
    score.clamp(0, 100) as u8
}

fn count_pattern(snapshot: &RepositorySnapshot, needle: &str) -> usize {
    snapshot
        .files
        .iter()
        .filter_map(|file| file.content.as_deref())
        .map(|content| content.matches(needle).count())
        .sum()
}

fn first_file_with_pattern(snapshot: &RepositorySnapshot, needle: &str) -> Option<String> {
    snapshot.files.iter().find_map(|file| {
        file.content.as_deref().and_then(|content| {
            if content.contains(needle) {
                Some(file.path.clone())
            } else {
                None
            }
        })
    })
}

fn max_line_length(snapshot: &RepositorySnapshot) -> Option<(String, usize)> {
    snapshot
        .files
        .iter()
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

fn count_enabled_observability_targets(config: &ReviewConfig) -> usize {
    [
        config.observability.file_names,
        config.observability.file_paths,
        config.observability.file_line_counts,
        config.observability.file_sizes,
        config.observability.longest_file_ranking,
        config.observability.longest_function_ranking,
        config.observability.contributor_count,
        config.observability.per_author_commit_counts,
        config.observability.total_commit_count,
        config.observability.commit_concentration,
        config.observability.most_recent_active_authors,
        config.observability.code_change_hotspots,
    ]
    .into_iter()
    .filter(|enabled| *enabled)
    .count()
}

fn total_observability_targets() -> usize {
    12
}

fn git_observability_enabled(config: &ReviewConfig) -> bool {
    config.observability.contributor_count
        || config.observability.per_author_commit_counts
        || config.observability.total_commit_count
        || config.observability.commit_concentration
        || config.observability.most_recent_active_authors
        || config.observability.code_change_hotspots
}
