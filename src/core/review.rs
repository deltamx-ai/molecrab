use std::cmp::Ordering;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt::Write;
use std::path::PathBuf;

use colored::{ColoredString, Colorize};
use serde::Serialize;

use super::classify::FileCategory;
use super::config::ReviewConfig;
use super::metrics;
use super::model::{
    AreaHealth, CategoryCount, FileRanking, Finding, FrontendKind, FrontendProfile,
    FunctionRanking, FunctionSnapshot, FunctionSummary, LanguageCount, MetricResult, Priority,
    RepositorySnapshot, ReviewReport, ReviewScope, Severity, StylesheetRanking, area_of,
    is_dead_code_candidate,
};
use super::scanner;

pub fn analyze(
    path: PathBuf,
    config_path: Option<PathBuf>,
    since: Option<String>,
    eslint: Option<PathBuf>,
) -> Result<ReviewReport, String> {
    let config = ReviewConfig::load_for_repository(&path, config_path.as_deref())?;
    let snapshot = scanner::scan_repository(&path, &config)?;
    let metric_results = metrics::evaluate(&snapshot, &config);

    let lint_findings = match eslint {
        Some(report_path) => {
            let json = std::fs::read_to_string(&report_path).map_err(|err| {
                format!(
                    "failed to read ESLint report {}: {err}",
                    report_path.display()
                )
            })?;
            super::lint::parse_eslint(&json, &path)?
        }
        None => Vec::new(),
    };

    let mut report = build_report(&snapshot, config, metric_results, lint_findings);

    if let Some(since) = since {
        let changed = scanner::changed_files(&path, &since).ok_or_else(|| {
            format!("cannot diff against '{since}' — not a git repository or unknown ref")
        })?;
        let changed: HashSet<String> = changed.into_iter().collect();
        scope_report_to_diff(&mut report, &snapshot, &since, &changed);
    }

    Ok(report)
}

fn build_report(
    snapshot: &RepositorySnapshot,
    config: ReviewConfig,
    metrics: Vec<MetricResult>,
    lint_findings: Vec<Finding>,
) -> ReviewReport {
    let mut findings = dedupe_findings(&metrics);
    // External lint findings (ESLint) are surfaced alongside our own, but they
    // never affect the metric scores — they ride in as extra issues only.
    findings.extend(lint_findings.iter().cloned());
    let issue_categories = summarize_categories(&findings);

    // Honest score: the real weighted average, never floored upward. The
    // configured `overall_score` is a pass/fail gate, not a minimum to display.
    let overall = weighted_score(&metrics);
    let grade = grade_for(overall).to_string();
    let passed = overall >= config.thresholds.overall_score;
    let verdict = verdict_label(&grade, &metrics, config.thresholds.failing_metric_score);
    let risk_level = risk_level_for(&findings);
    let worst_metric = metrics
        .iter()
        .min_by_key(|metric| metric.score)
        .map(|m| m.name);

    let priorities = build_priorities(snapshot, &metrics, &lint_findings, &config);
    let areas = build_areas(snapshot, &metrics);

    let categories = category_map(snapshot);
    let unreferenced: Vec<&FunctionSnapshot> = snapshot
        .functions
        .iter()
        .filter(|f| {
            is_dead_code_candidate(
                f,
                categories.get(f.file.as_str()) == Some(&FileCategory::Source),
            )
        })
        .collect();
    let dead_set: HashSet<(&str, usize)> = unreferenced
        .iter()
        .map(|f| (f.file.as_str(), f.start_line))
        .collect();
    let all_functions: Vec<&FunctionSnapshot> = snapshot.functions.iter().collect();

    let profile = snapshot.profile.clone();
    let file_rankings = rank_files(snapshot, &config);
    let function_summary = build_function_summary(&all_functions, &config, unreferenced.len());
    let function_rankings = rank_functions(snapshot, &config);
    let param_hygiene = rank_param_hygiene(snapshot, &config);
    let dead_code = rank_dead_code(&unreferenced, &config);
    let most_complex = rank_most_complex(snapshot, &config);
    let most_notable = rank_notable_functions(snapshot, &config, &dead_set);
    let stylesheet_rankings = rank_stylesheets(snapshot, &config);
    let git = trimmed_git(snapshot, &config);

    ReviewReport {
        profile,
        config,
        scope: None,
        metrics,
        findings,
        lint_findings,
        priorities,
        areas,
        overall,
        grade,
        verdict,
        risk_level,
        passed,
        worst_metric,
        issue_categories,
        file_rankings,
        function_summary,
        function_rankings,
        param_hygiene,
        dead_code,
        most_complex,
        most_notable,
        stylesheet_rankings,
        git,
        frontend: snapshot.frontend.clone(),
    }
}

/// Coarse correctness-risk level from the safety findings: an error-severity risk
/// (or several warnings) is "high", any warning-level risk is "moderate", and
/// info-only / none is "low".
fn risk_level_for(findings: &[Finding]) -> &'static str {
    let mut errors = 0usize;
    let mut warnings = 0usize;
    for finding in findings.iter().filter(|f| is_risk_category(f.category)) {
        match finding.severity {
            Severity::Error => errors += 1,
            Severity::Warning => warnings += 1,
            Severity::Info => {}
        }
    }
    if errors > 0 || warnings >= 5 {
        "high"
    } else if warnings > 0 {
        "moderate"
    } else {
        "low"
    }
}

/// Aggregates judgment-free statistics over the given functions. Thresholds
/// (long / over-limit) come from config; the summary only counts, it does not
/// judge — findings do that. Takes a function slice (not the whole snapshot) so
/// it can be reused for the changed-files subset in diff mode.
fn build_function_summary(
    functions: &[&FunctionSnapshot],
    config: &ReviewConfig,
    unreferenced_function_count: usize,
) -> FunctionSummary {
    let max_lines = config.thresholds.max_function_lines as usize;
    let max_params = config.thresholds.max_function_params as usize;
    let max_cyclomatic = config.thresholds.max_cyclomatic as usize;

    let function_count = functions.len();
    let total_lines: usize = functions.iter().map(|f| f.lines).sum();
    let total_param_count: usize = functions.iter().map(|f| f.param_count).sum();
    let unused_param_count: usize = functions.iter().map(|f| f.unused_params.len()).sum();
    let total_cyclomatic: usize = functions.iter().map(|f| f.cyclomatic).sum();

    let mut breakdown: BTreeMap<&'static str, usize> = BTreeMap::new();
    for function in functions {
        *breakdown.entry(function.language).or_insert(0) += 1;
    }
    let mut language_breakdown: Vec<LanguageCount> = breakdown
        .into_iter()
        .map(|(language, count)| LanguageCount { language, count })
        .collect();
    language_breakdown.sort_by(|a, b| {
        b.count
            .cmp(&a.count)
            .then_with(|| a.language.cmp(b.language))
    });

    FunctionSummary {
        function_count,
        average_function_lines: mean(total_lines, function_count),
        max_function_lines: functions.iter().map(|f| f.lines).max().unwrap_or(0),
        long_function_count: functions.iter().filter(|f| f.lines > max_lines).count(),
        total_param_count,
        average_param_count: mean(total_param_count, function_count),
        zero_param_function_count: functions.iter().filter(|f| f.param_count == 0).count(),
        four_plus_param_function_count: functions.iter().filter(|f| f.param_count >= 4).count(),
        over_param_limit_count: functions
            .iter()
            .filter(|f| f.param_count > max_params)
            .count(),
        unused_param_count,
        functions_with_unused_params: functions
            .iter()
            .filter(|f| !f.unused_params.is_empty())
            .count(),
        unreferenced_function_count,
        average_cyclomatic: mean(total_cyclomatic, function_count),
        max_cyclomatic: functions.iter().map(|f| f.cyclomatic).max().unwrap_or(0),
        complex_function_count: functions
            .iter()
            .filter(|f| f.cyclomatic > max_cyclomatic)
            .count(),
        language_breakdown,
    }
}

fn mean(total: usize, count: usize) -> f64 {
    if count == 0 {
        0.0
    } else {
        (total as f64) / (count as f64)
    }
}

/// Narrows a whole-repo report down to a diff: keeps only the findings and
/// evidence that touch changed files, recomputes the category and function
/// summaries over that subset, and records the scope. The metric scores stay
/// repo-wide (the header says so) — re-scoring to the change is a larger change
/// left for later.
fn scope_report_to_diff(
    report: &mut ReviewReport,
    snapshot: &RepositorySnapshot,
    since: &str,
    changed: &HashSet<String>,
) {
    let in_scope = |file: &str| changed.contains(file);
    report
        .findings
        .retain(|f| f.file.as_deref().is_some_and(in_scope));
    report
        .lint_findings
        .retain(|f| f.file.as_deref().is_some_and(in_scope));
    report
        .priorities
        .retain(|p| p.file.as_deref().is_some_and(in_scope));
    report.issue_categories = summarize_categories(&report.findings);
    report.function_rankings.retain(|r| in_scope(&r.file));
    report.param_hygiene.retain(|r| in_scope(&r.file));
    report.dead_code.retain(|r| in_scope(&r.file));
    report.most_complex.retain(|r| in_scope(&r.file));
    report.most_notable.retain(|r| in_scope(&r.file));
    report.file_rankings.retain(|r| in_scope(&r.path));
    // Areas are a whole-repo rollup; not meaningful for a handful of changed files.
    report.areas.clear();

    // Recompute the function summary over just the changed functions.
    let categories = category_map(snapshot);
    let changed_fns: Vec<&FunctionSnapshot> = snapshot
        .functions
        .iter()
        .filter(|f| in_scope(&f.file))
        .collect();
    let unreferenced = snapshot
        .functions
        .iter()
        .filter(|f| in_scope(&f.file))
        .filter(|f| {
            is_dead_code_candidate(
                f,
                categories.get(f.file.as_str()) == Some(&FileCategory::Source),
            )
        })
        .count();
    report.function_summary = build_function_summary(&changed_fns, &report.config, unreferenced);

    report.scope = Some(ReviewScope {
        since: since.to_string(),
        changed_file_count: changed.len(),
    });
}

/// Collapses the per-metric findings into one list, dropping exact duplicates
/// (same metric, file and message).
fn dedupe_findings(metrics: &[MetricResult]) -> Vec<Finding> {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for metric in metrics {
        for finding in &metric.findings {
            let key = (
                finding.metric,
                finding.file.clone(),
                finding.message.clone(),
            );
            if seen.insert(key) {
                out.push(finding.clone());
            }
        }
    }
    out
}

/// Groups findings into reviewer categories with counts — the "what kinds of
/// problems exist" overview. Ordered worst-severity first, then by count.
fn summarize_categories(findings: &[Finding]) -> Vec<CategoryCount> {
    let mut map: HashMap<&'static str, (usize, u8)> = HashMap::new();
    for finding in findings {
        let entry = map.entry(finding.category).or_insert((0, 0));
        entry.0 += 1;
        entry.1 = entry.1.max(severity_rank(finding.severity));
    }
    let mut ordered: Vec<(&'static str, usize, u8)> = map
        .into_iter()
        .map(|(category, (count, severity))| (category, count, severity))
        .collect();
    ordered.sort_by(|a, b| {
        b.2.cmp(&a.2)
            .then_with(|| b.1.cmp(&a.1))
            .then_with(|| a.0.cmp(b.0))
    });
    ordered
        .into_iter()
        .map(|(category, count, _)| CategoryCount { category, count })
        .collect()
}

fn severity_rank(severity: Severity) -> u8 {
    match severity {
        Severity::Error => 3,
        Severity::Warning => 2,
        Severity::Info => 1,
    }
}

/// Ranks every finding by impact and keeps the most important ones. Impact
/// blends severity, the metric's weight, the finding's score penalty, and
/// whether it points at first-party source (noise files never reach here).
fn build_priorities(
    snapshot: &RepositorySnapshot,
    metrics: &[MetricResult],
    lint_findings: &[Finding],
    config: &ReviewConfig,
) -> Vec<Priority> {
    let categories = category_map(snapshot);
    let mut priorities = Vec::new();
    let metric_weight = |finding: &Finding| {
        metrics
            .iter()
            .find(|metric| metric.name == finding.metric)
            .map(|metric| metric.weight)
            .unwrap_or(0)
    };
    let mut push = |finding: &Finding, weight: u8| {
        priorities.push(Priority {
            id: priority_id(finding),
            impact: impact_of(finding, weight, &categories),
            severity: finding.severity,
            metric: finding.metric,
            category: finding.category,
            file: finding.file.clone(),
            line: finding.line,
            message: finding.message.clone(),
            suggestion: finding.suggestion.clone(),
        });
    };
    for metric in metrics {
        for finding in &metric.findings {
            push(finding, metric.weight);
        }
    }
    // Ingested lint findings are unscored, but still ranked into the list so a
    // serious lint error can surface in "Fix first". Borrow the weight of the
    // metric they are tagged with (lint findings reuse `metric = "robustness"`
    // etc. is not guaranteed, so fall back to 0 when unknown).
    for finding in lint_findings {
        let weight = metric_weight(finding);
        push(finding, weight);
    }
    priorities.sort_by(|a, b| b.impact.cmp(&a.impact).then_with(|| a.id.cmp(&b.id)));
    priorities.truncate(config.thresholds.top_priorities as usize);
    priorities
}

fn impact_of(
    finding: &Finding,
    metric_weight: u8,
    categories: &HashMap<&str, FileCategory>,
) -> u32 {
    let severity = match finding.severity {
        Severity::Error => 3,
        Severity::Warning => 2,
        Severity::Info => 1,
    };
    let source_factor = match &finding.file {
        Some(path) => match categories.get(path.as_str()) {
            Some(FileCategory::Source) => 10,
            Some(FileCategory::Test) => 4,
            Some(FileCategory::Config) => 2,
            Some(FileCategory::Docs) => 1,
            _ => 3,
        },
        None => 6,
    };
    let magnitude = finding.score_penalty.max(1);
    severity * u32::from(metric_weight) * magnitude * source_factor
}

fn priority_id(finding: &Finding) -> String {
    format!(
        "{}:{}:{}",
        finding.metric,
        finding.file.as_deref().unwrap_or("repo"),
        slug(&finding.message)
    )
}

fn slug(text: &str) -> String {
    let words: Vec<String> = text
        .split_whitespace()
        .take(5)
        .map(|word| {
            word.chars()
                .filter(|c| c.is_alphanumeric())
                .collect::<String>()
                .to_lowercase()
        })
        .filter(|word| !word.is_empty())
        .collect();
    if words.is_empty() {
        "issue".to_string()
    } else {
        words.join("-")
    }
}

#[derive(Default)]
struct AreaAccumulator {
    file_count: usize,
    source_file_count: usize,
    errors: usize,
    warnings: usize,
    infos: usize,
    impact_by_metric: HashMap<&'static str, u32>,
}

/// Rolls up health per top-level area (package/directory) so you can see where
/// problems concentrate. Noise files are not counted.
fn build_areas(snapshot: &RepositorySnapshot, metrics: &[MetricResult]) -> Vec<AreaHealth> {
    let categories = category_map(snapshot);
    let mut areas: BTreeMap<String, AreaAccumulator> = BTreeMap::new();

    for file in &snapshot.files {
        if file.category.is_noise() {
            continue;
        }
        let acc = areas.entry(file.area().to_string()).or_default();
        acc.file_count += 1;
        if file.is_source() {
            acc.source_file_count += 1;
        }
    }

    for metric in metrics {
        for finding in &metric.findings {
            let Some(path) = &finding.file else {
                continue;
            };
            let acc = areas.entry(area_of(path).to_string()).or_default();
            match finding.severity {
                Severity::Error => acc.errors += 1,
                Severity::Warning => acc.warnings += 1,
                Severity::Info => acc.infos += 1,
            }
            *acc.impact_by_metric.entry(metric.name).or_insert(0) +=
                impact_of(finding, metric.weight, &categories);
        }
    }

    let mut areas: Vec<AreaHealth> = areas
        .into_iter()
        .map(|(area, acc)| AreaHealth {
            area,
            file_count: acc.file_count,
            source_file_count: acc.source_file_count,
            errors: acc.errors,
            warnings: acc.warnings,
            infos: acc.infos,
            worst_metric: acc
                .impact_by_metric
                .into_iter()
                .max_by_key(|(_, impact)| *impact)
                .map(|(metric, _)| metric),
        })
        .collect();

    areas.sort_by(|a, b| {
        b.errors
            .cmp(&a.errors)
            .then_with(|| b.warnings.cmp(&a.warnings))
            .then_with(|| b.infos.cmp(&a.infos))
            .then_with(|| a.area.cmp(&b.area))
    });
    // Drop areas that are neither source nor flagged (e.g. a lone dotfile dir).
    areas.retain(|area| area.source_file_count > 0 || area.errors + area.warnings + area.infos > 0);
    areas
}

fn category_map(snapshot: &RepositorySnapshot) -> HashMap<&str, FileCategory> {
    snapshot
        .files
        .iter()
        .map(|file| (file.path.as_str(), file.category))
        .collect()
}

/// Keeps only the top-N hotspots so the report does not dump the entire file
/// list (scanner already drops non-code paths).
fn trimmed_git(
    snapshot: &RepositorySnapshot,
    config: &ReviewConfig,
) -> Option<super::model::GitSnapshot> {
    let mut git = snapshot.git.clone()?;
    git.hotspots
        .truncate(config.thresholds.top_hotspots as usize);
    Some(git)
}

fn weighted_score(metrics: &[MetricResult]) -> u8 {
    let (weighted_sum, weight_sum) = metrics.iter().fold((0u32, 0u32), |(sum, weight), metric| {
        (
            sum + u32::from(metric.score) * u32::from(metric.weight),
            weight + u32::from(metric.weight),
        )
    });

    if weight_sum == 0 {
        0
    } else {
        (weighted_sum / weight_sum) as u8
    }
}

fn grade_for(score: u8) -> &'static str {
    match score {
        90..=100 => "A",
        80..=89 => "B",
        70..=79 => "C",
        60..=69 => "D",
        _ => "F",
    }
}

/// Sorts `items` by `cmp` and keeps the top `limit` (an empty result when
/// `limit == 0`). The single home for the "rank then cap" pattern every
/// `rank_*` evidence list shares.
fn top_n<T>(mut items: Vec<T>, limit: usize, cmp: impl FnMut(&T, &T) -> Ordering) -> Vec<T> {
    items.sort_by(cmp);
    if limit == 0 {
        items.clear();
    } else {
        items.truncate(limit);
    }
    items
}

fn rank_files(snapshot: &RepositorySnapshot, config: &ReviewConfig) -> Vec<FileRanking> {
    if !config.observability.longest_file_ranking {
        return Vec::new();
    }

    let files = snapshot
        .files
        .iter()
        .filter(|file| file.is_first_party_code())
        .filter(|file| file.lines >= config.thresholds.min_file_lines_for_rank as usize)
        .map(|file| FileRanking {
            path: file.path.clone(),
            name: file.name.clone(),
            lines: file.lines,
            bytes: file.bytes,
        })
        .collect::<Vec<_>>();

    top_n(
        files,
        config.thresholds.top_file_rankings as usize,
        |a, b| b.lines.cmp(&a.lines).then_with(|| b.bytes.cmp(&a.bytes)),
    )
}

/// Evidence: the longest functions. (The aggregate health lives in
/// `function_summary`; this is just the supporting sample.)
fn rank_functions(snapshot: &RepositorySnapshot, config: &ReviewConfig) -> Vec<FunctionRanking> {
    if !config.observability.longest_function_ranking {
        return Vec::new();
    }

    let functions = snapshot
        .functions
        .iter()
        .filter(|func| func.lines >= config.thresholds.min_function_lines_for_rank as usize)
        .map(|func| to_function_ranking(func, config))
        .collect::<Vec<_>>();

    top_n(
        functions,
        config.thresholds.top_function_rankings as usize,
        |a, b| {
            b.lines
                .cmp(&a.lines)
                .then_with(|| b.param_count.cmp(&a.param_count))
                .then_with(|| a.file.cmp(&b.file))
        },
    )
}

/// Ranks functions that have at least one unused parameter, surfacing them even
/// when they are short enough to miss the longest-function ranking.
fn rank_param_hygiene(
    snapshot: &RepositorySnapshot,
    config: &ReviewConfig,
) -> Vec<FunctionRanking> {
    if !config.observability.function_param_analysis {
        return Vec::new();
    }

    let functions = snapshot
        .functions
        .iter()
        .filter(|func| !func.unused_params.is_empty())
        .map(|func| to_function_ranking(func, config))
        .collect::<Vec<_>>();

    top_n(
        functions,
        config.thresholds.top_function_rankings as usize,
        |a, b| {
            b.unused_params
                .len()
                .cmp(&a.unused_params.len())
                .then_with(|| b.param_count.cmp(&a.param_count))
                .then_with(|| a.file.cmp(&b.file))
        },
    )
}

/// Evidence: functions that look like possible dead code (named, first-party
/// source, zero references), longest first.
fn rank_dead_code(
    unreferenced: &[&super::model::FunctionSnapshot],
    config: &ReviewConfig,
) -> Vec<FunctionRanking> {
    if !config.observability.longest_function_ranking {
        return Vec::new();
    }
    let functions: Vec<FunctionRanking> = unreferenced
        .iter()
        .map(|&func| to_function_ranking(func, config))
        .collect();
    top_n(
        functions,
        config.thresholds.top_function_rankings as usize,
        |a, b| b.lines.cmp(&a.lines).then_with(|| a.file.cmp(&b.file)),
    )
}

/// Evidence: the most complex functions, by cyclomatic complexity.
fn rank_most_complex(snapshot: &RepositorySnapshot, config: &ReviewConfig) -> Vec<FunctionRanking> {
    if !config.observability.longest_function_ranking {
        return Vec::new();
    }
    let functions: Vec<FunctionRanking> = snapshot
        .functions
        .iter()
        .filter(|func| func.cyclomatic > 1)
        .map(|func| to_function_ranking(func, config))
        .collect();
    top_n(
        functions,
        config.thresholds.top_function_rankings as usize,
        |a, b| {
            b.cyclomatic
                .cmp(&a.cyclomatic)
                .then_with(|| b.max_nesting.cmp(&a.max_nesting))
                .then_with(|| a.file.cmp(&b.file))
        },
    )
}

/// Evidence for the compact text report: the functions worth a look, each shown
/// once, ranked by an overall "concern" score (length + complexity + nesting +
/// unused params + dead). Functions in `dead` get a `dead?` flag. Only functions
/// with at least one flag are notable.
fn rank_notable_functions(
    snapshot: &RepositorySnapshot,
    config: &ReviewConfig,
    dead: &HashSet<(&str, usize)>,
) -> Vec<FunctionRanking> {
    if !config.observability.longest_function_ranking {
        return Vec::new();
    }
    let rows: Vec<FunctionRanking> = snapshot
        .functions
        .iter()
        .map(|func| {
            let mut ranking = to_function_ranking(func, config);
            if dead.contains(&(func.file.as_str(), func.start_line)) {
                ranking.flags.push("dead?");
            }
            ranking
        })
        .filter(|ranking| !ranking.flags.is_empty())
        .collect();
    top_n(
        rows,
        config.thresholds.top_function_rankings as usize,
        |a, b| {
            notable_concern(b)
                .cmp(&notable_concern(a))
                .then_with(|| a.file.cmp(&b.file))
        },
    )
}

fn notable_concern(ranking: &FunctionRanking) -> usize {
    ranking.lines
        + ranking.cyclomatic * 4
        + ranking.max_nesting * 8
        + ranking.unused_params.len() * 40
        + if ranking.flags.contains(&"dead?") {
            80
        } else {
            0
        }
}

fn to_function_ranking(func: &FunctionSnapshot, config: &ReviewConfig) -> FunctionRanking {
    let max_lines = config.thresholds.max_function_lines as usize;
    let max_params = config.thresholds.max_function_params as usize;
    let max_cyclomatic = config.thresholds.max_cyclomatic as usize;
    let max_nesting = config.thresholds.max_function_nesting as usize;
    let mut flags = Vec::new();
    if func.lines > max_lines {
        flags.push("long");
    }
    if func.cyclomatic > max_cyclomatic {
        flags.push("complex");
    }
    if func.max_nesting > max_nesting {
        flags.push("deeply-nested");
    }
    if func.param_count > max_params {
        flags.push("many-params");
    }
    if !func.unused_params.is_empty() {
        flags.push("unused-param");
    }
    if func.signals.unsafe_count > 0 {
        flags.push("unsafe");
    }
    if func.signals.empty_blocks > 0 {
        flags.push("empty-guard");
    }
    if func.signals.subscribe_calls > 0 && !func.signals.subscribe_cleanup {
        flags.push("leak?");
    }
    if func.signals.max_bool_chain > config.thresholds.max_bool_operands as usize
        || func.signals.max_ternary_depth > config.thresholds.max_ternary_depth as usize
    {
        flags.push("complex-expr");
    }
    if func.signals.any_types > 0 {
        flags.push("any");
    }
    if func.signals.unknown_casts > 0
        || func.signals.as_casts > config.thresholds.max_as_casts as usize
    {
        flags.push("cast!");
    }
    if func.signals.non_null_assertions > config.thresholds.max_non_null_assertions as usize {
        flags.push("non-null!");
    }
    if func.signals.then_calls > 0 && func.signals.catch_calls == 0 {
        flags.push("promise!");
    }
    if func.signals.use_effect_missing_deps > 0 {
        flags.push("effect-deps");
    }

    FunctionRanking {
        file: func.file.clone(),
        name: func.name.clone(),
        language: func.language,
        start_line: func.start_line,
        end_line: func.end_line,
        lines: func.lines,
        param_count: func.param_count,
        unused_params: func.unused_params.clone(),
        references: func.references,
        referenced_by: func.referenced_by.clone(),
        cyclomatic: func.cyclomatic,
        max_nesting: func.max_nesting,
        flags,
    }
}

fn rank_stylesheets(
    snapshot: &RepositorySnapshot,
    config: &ReviewConfig,
) -> Vec<StylesheetRanking> {
    if !config.observability.longest_stylesheet_ranking {
        return Vec::new();
    }

    let stylesheets = snapshot
        .stylesheets
        .iter()
        .map(|sheet| StylesheetRanking {
            file: sheet.file.clone(),
            name: sheet.name.clone(),
            lines: sheet.lines,
            bytes: sheet.bytes,
            rule_count: sheet.rule_count,
            selector_count: sheet.selector_count,
            declaration_count: sheet.declaration_count,
            variable_count: sheet.variable_count,
            import_count: sheet.import_count,
            max_nesting_depth: sheet.max_nesting_depth,
            largest_rule_lines: sheet.largest_rule_lines,
            duplicate_selector_count: sheet.duplicate_selector_count,
            important_count: sheet.important_count,
        })
        .collect::<Vec<_>>();

    // Longest stylesheets first, then the heaviest single rule, then nesting.
    top_n(
        stylesheets,
        config.thresholds.top_stylesheet_rankings as usize,
        |a, b| {
            b.lines
                .cmp(&a.lines)
                .then_with(|| b.largest_rule_lines.cmp(&a.largest_rule_lines))
                .then_with(|| b.max_nesting_depth.cmp(&a.max_nesting_depth))
                .then_with(|| a.file.cmp(&b.file))
        },
    )
}

// --------------------------------------------------------------------------
// Text rendering
//
// The report is built as a hierarchy: a strong, colored summary and a ranked
// "Top issues" list carry the signal; scores and areas give context; the
// observability detail is dimmed and compact so it never competes for
// attention. Each finding only appears once (in Top issues), so there is no
// duplicate "Findings" section.
// --------------------------------------------------------------------------

pub(crate) fn render_text_report(report: &ReviewReport) -> String {
    let mut out = String::new();
    render_summary(&mut out, report);
    render_fix_first(&mut out, report);
    render_issues_by_category(&mut out, report);
    render_scores(&mut out, report);
    render_areas(&mut out, report);
    render_functions(&mut out, report);
    render_frontend(&mut out, report);
    render_details(&mut out, report);
    out
}

pub(crate) fn render_json_report(report: &ReviewReport) -> Result<String, String> {
    let output = JsonReviewReport::from_report(report);
    serde_json::to_string_pretty(&output)
        .map_err(|err| format!("failed to render json report: {}", err))
}

fn render_summary(out: &mut String, report: &ReviewReport) {
    let _ = writeln!(
        out,
        "{} {}",
        "molecrab".bold().cyan(),
        report.profile.path().dimmed()
    );
    if let Some(scope) = &report.scope {
        let _ = writeln!(
            out,
            "{}",
            format!(
                "diff review: {} changed file(s) since {} (score is repo-wide)",
                scope.changed_file_count, scope.since
            )
            .bold()
            .magenta()
        );
    }
    let _ = writeln!(out);

    let verdict = report.verdict;
    let verdict_colored = match verdict {
        "healthy" => verdict.green().bold(),
        "serviceable" => verdict.yellow().bold(),
        _ => verdict.red().bold(),
    };
    let _ = writeln!(
        out,
        "  Score {}   Grade {}   {}",
        paint_score(report.overall, format!("{}/100", report.overall)),
        paint_grade(&report.grade),
        verdict_colored,
    );

    // Frontend project kind + correctness-risk level — only when there is a
    // frontend to talk about.
    if report.frontend.kind != FrontendKind::NonFrontend {
        let risk = match report.risk_level {
            "high" => report.risk_level.red().bold(),
            "moderate" => report.risk_level.yellow().bold(),
            _ => report.risk_level.green().bold(),
        };
        let _ = writeln!(
            out,
            "  Frontend {}   risk {}",
            report.frontend.kind.label().bold().cyan(),
            risk,
        );
    }

    let gate = if report.passed {
        format!("gate PASSED (>={})", report.config.thresholds.overall_score)
            .green()
            .bold()
    } else {
        format!("gate FAILED (<{})", report.config.thresholds.overall_score)
            .red()
            .bold()
    };
    let weakest = report
        .metrics
        .iter()
        .min_by_key(|metric| metric.score)
        .map(|metric| format!("weakest: {} {}", metric.name, metric.score))
        .unwrap_or_default();
    let _ = writeln!(out, "  {}   {}", gate, weakest.dimmed());

    let _ = writeln!(
        out,
        "  {}",
        format!(
            "{} files · {} source · {} test · {} lines",
            report.profile.file_count(),
            report.profile.source_file_count(),
            report.profile.test_file_count(),
            report.profile.total_lines()
        )
        .dimmed()
    );

    let total_problems: usize = report.issue_categories.iter().map(|c| c.count).sum();
    if total_problems > 0 {
        let breakdown = report
            .issue_categories
            .iter()
            .map(|c| format!("{} {}", c.category, c.count))
            .collect::<Vec<_>>()
            .join(" · ");
        let _ = writeln!(
            out,
            "  {} problems · {}",
            total_problems.to_string().bold(),
            breakdown
        );
    }
    let _ = writeln!(out);
}

/// The verdict is honest about failing sub-metrics: a repo with any metric below
/// the failing threshold is never reported as "healthy", even at grade A/B.
/// Computed in the analysis layer (`build_report`) and stored on the report, so
/// the text and JSON renderers display the same judgment rather than recomputing.
fn verdict_label(grade: &str, metrics: &[MetricResult], failing_metric_score: u8) -> &'static str {
    let failing = metrics
        .iter()
        .any(|metric| metric.score < failing_metric_score);
    match (grade, failing) {
        ("A" | "B", false) => "healthy",
        ("A" | "B", true) => "serviceable",
        ("C", _) => "serviceable",
        _ => "needs attention",
    }
}

/// The "start here" pointer: the three highest-impact problems, one line each.
/// A shortcut into the full categorized list below ("if you only fix 3 things").
fn render_fix_first(out: &mut String, report: &ReviewReport) {
    if report.priorities.is_empty() {
        return;
    }
    heading(out, "Fix first");
    for (idx, priority) in report.priorities.iter().take(3).enumerate() {
        let location = location_label(priority.file.as_deref(), priority.line);
        let _ = writeln!(
            out,
            "  {} {}  {}  {}",
            format!("{}.", idx + 1).bold(),
            severity_badge(priority.severity),
            priority.message,
            location,
        );
    }
    let _ = writeln!(out);
}

/// Renders a `file:line` (or just `file`, or a dim `repo-wide`) location label.
fn location_label(file: Option<&str>, line: Option<usize>) -> String {
    match (file, line) {
        (Some(file), Some(line)) => format!("{}:{}", file, line).cyan().to_string(),
        (Some(file), None) => file.cyan().to_string(),
        (None, _) => "repo-wide".dimmed().to_string(),
    }
}

/// The reviewer's main view: problems grouped by category ("what kind of
/// problem"), categories ordered worst-first, findings within ordered by
/// severity. This replaces a flat issue list so a reviewer can see, at a
/// glance, what kinds of problems exist and where.
fn render_issues_by_category(out: &mut String, report: &ReviewReport) {
    heading(out, "Issues");
    if report.findings.is_empty() {
        let _ = writeln!(out, "  {}", "no issues found".green());
        let _ = writeln!(out);
        return;
    }

    for category in &report.issue_categories {
        let mut items: Vec<&Finding> = report
            .findings
            .iter()
            .filter(|finding| finding.category == category.category)
            .collect();
        items.sort_by(|a, b| severity_rank(b.severity).cmp(&severity_rank(a.severity)));

        let _ = writeln!(
            out,
            "  {} {}",
            category.category.bold(),
            format!("({})", category.count).dimmed()
        );
        for finding in items {
            let location = location_label(finding.file.as_deref(), finding.line);
            let _ = writeln!(
                out,
                "    {}  {}",
                severity_badge(finding.severity),
                finding.message
            );
            let _ = writeln!(
                out,
                "        {}  {} {}",
                location,
                "->".dimmed(),
                finding.suggestion.dimmed()
            );
        }
    }
    let _ = writeln!(out);
}

fn render_scores(out: &mut String, report: &ReviewReport) {
    heading(out, "Scores");
    let weakest = report
        .metrics
        .iter()
        .min_by_key(|metric| metric.score)
        .map(|metric| metric.name);

    for metric in &report.metrics {
        let mark = if Some(metric.name) == weakest {
            "  <- weakest".dimmed().to_string()
        } else {
            String::new()
        };
        let _ = writeln!(
            out,
            "  {:<16} {} {}{}",
            metric.name,
            bar(metric.score),
            paint_score(metric.score, format!("{:>3}", metric.score)),
            mark,
        );
    }
    let _ = writeln!(out);
}

fn render_areas(out: &mut String, report: &ReviewReport) {
    // A breakdown only adds signal when the repo has more than one area.
    if report.areas.len() <= 1 {
        return;
    }

    heading(out, "Areas");
    for area in &report.areas {
        let errors = count_badge(area.errors, "E", |t| t.red().bold());
        let warnings = count_badge(area.warnings, "W", |t| t.yellow());
        let infos = count_badge(area.infos, "i", |t| t.normal());
        let worst = area
            .worst_metric
            .map(|metric| format!("worst: {}", metric))
            .unwrap_or_default();
        let _ = writeln!(
            out,
            "  {:<14} {:>3} src   {} {} {}   {}",
            area.area,
            area.source_file_count,
            errors,
            warnings,
            infos,
            worst.dimmed(),
        );
    }
    let _ = writeln!(out);
}

/// Function observability: a compact statistical summary, then a single
/// "Notable functions" table (size/complexity/usage outliers, each shown once).
/// The granular per-category rankings live in the JSON output.
fn render_functions(out: &mut String, report: &ReviewReport) {
    if !report.config.observability.longest_function_ranking {
        return;
    }
    let summary = &report.function_summary;
    heading(out, "Functions");
    if summary.function_count == 0 {
        let _ = writeln!(out, "  no functions analyzed");
        let _ = writeln!(out);
        return;
    }

    let max_lines = report.config.thresholds.max_function_lines as usize;
    let max_cyclomatic = report.config.thresholds.max_cyclomatic as usize;

    // ---- Summary: two compact fact lines ----
    let langs = summary
        .language_breakdown
        .iter()
        .map(|lang| format!("{} {}", lang.language, lang.count))
        .collect::<Vec<_>>()
        .join(" · ");
    let _ = writeln!(
        out,
        "  {} fns · avg {:.0} / max {} lines · {} · {}",
        summary.function_count,
        summary.average_function_lines,
        summary.max_function_lines,
        paint_count(
            summary.long_function_count,
            format!("{} long (>{})", summary.long_function_count, max_lines),
        ),
        langs.dimmed(),
    );
    let _ = writeln!(
        out,
        "  cc avg {:.1} / max {} · {} · params avg {:.1} · {} · {}",
        summary.average_cyclomatic,
        summary.max_cyclomatic,
        paint_count(
            summary.complex_function_count,
            format!(
                "{} complex (>{})",
                summary.complex_function_count, max_cyclomatic
            ),
        ),
        summary.average_param_count,
        paint_count(
            summary.unused_param_count,
            format!("{} unused-param", summary.unused_param_count),
        ),
        paint_count(
            summary.unreferenced_function_count,
            format!("{} unreferenced", summary.unreferenced_function_count),
        ),
    );
    let _ = writeln!(out);

    // ---- Notable functions: one deduplicated, concern-ranked table ----
    if report.most_notable.is_empty() {
        let _ = writeln!(out, "  {}", "no notable functions".green());
    } else {
        let _ = writeln!(out, "  {}", "Notable functions".bold());
        for func in &report.most_notable {
            render_notable_function(out, func);
        }
    }
    let _ = writeln!(out);
}

/// One notable function on a single line: name · stats (lines/cc/nesting/params/
/// refs) · quality flags · location. Quality flags come from the analysis layer.
fn render_notable_function(out: &mut String, func: &FunctionRanking) {
    let mut stats = vec![format!("{}L", func.lines), format!("cc{}", func.cyclomatic)];
    if func.max_nesting > 0 {
        stats.push(format!("n{}", func.max_nesting));
    }
    if func.unused_params.is_empty() {
        stats.push(format!("{}p", func.param_count));
    } else {
        stats.push(format!(
            "{}p({}u)",
            func.param_count,
            func.unused_params.len()
        ));
    }
    if super::model::referenceable_fn_name(&func.name).is_some() {
        stats.push(format!("~{}r", func.references));
    }
    let flags = func
        .flags
        .iter()
        .map(|flag| {
            if matches!(
                *flag,
                "dead?" | "unsafe" | "leak?" | "cast!" | "non-null!" | "promise!"
            ) {
                flag.red().bold().to_string()
            } else {
                flag.yellow().to_string()
            }
        })
        .collect::<Vec<_>>()
        .join(" ");
    let _ = writeln!(
        out,
        "    {}  {:<20} {}  {}",
        format!("{:<26}", clip(&func.name, 26)).bold(),
        stats.join(" "),
        flags,
        format!("{}:{}", func.file, func.start_line).dimmed(),
    );
}

/// A dedicated frontend block: project kind + the framework-specific evidence,
/// a one-line TS/JS function-health recap, and a CSS/SCSS recap. Skipped for
/// non-frontend repos so a pure backend project never sees it.
fn render_frontend(out: &mut String, report: &ReviewReport) {
    let fp = &report.frontend;
    if fp.kind == FrontendKind::NonFrontend {
        return;
    }
    heading(out, "Frontend");
    let _ = writeln!(
        out,
        "  {} · {} script file(s) · risk {}",
        fp.kind.label().bold(),
        fp.script_files,
        report.risk_level,
    );

    if fp.kind.is_react() {
        let _ = writeln!(
            out,
            "  {}  hooks {} · jsx/tsx files {} · react dep {}",
            "React".bold(),
            fp.react_hooks,
            fp.jsx_files,
            yes_no(fp.react_dependency),
        );
    }
    if fp.kind.is_angular() {
        let _ = writeln!(
            out,
            "  {}  decorators {} · templates {} · DI constructors {} · angular dep {}",
            "Angular".bold(),
            fp.angular_decorators,
            fp.html_templates,
            fp.di_constructors,
            yes_no(fp.angular_dependency),
        );
    }

    let summary = &report.function_summary;
    if summary.function_count > 0 {
        let _ = writeln!(
            out,
            "  {}  {} fns · {} long · {} complex · avg cc {:.1}",
            "Functions".bold(),
            summary.function_count,
            summary.long_function_count,
            summary.complex_function_count,
            summary.average_cyclomatic,
        );
    }

    if !report.stylesheet_rankings.is_empty() {
        let important: usize = report
            .stylesheet_rankings
            .iter()
            .map(|s| s.important_count)
            .sum();
        let max_nesting = report
            .stylesheet_rankings
            .iter()
            .map(|s| s.max_nesting_depth)
            .max()
            .unwrap_or(0);
        let _ = writeln!(
            out,
            "  {}  {} sheet(s) ranked · {} !important · max nesting {}",
            "CSS".bold(),
            report.stylesheet_rankings.len(),
            important,
            max_nesting,
        );
    }
    let _ = writeln!(out);
}

fn yes_no(value: bool) -> &'static str {
    if value { "yes" } else { "no" }
}

/// Each line respects its observability config toggle; the whole block is
/// skipped if nothing is enabled or available.
fn render_details(out: &mut String, report: &ReviewReport) {
    let obs = &report.config.observability;
    let mut lines: Vec<(String, String)> = Vec::new();

    if obs.longest_file_ranking && !report.file_rankings.is_empty() {
        lines.push((
            "Largest files".to_string(),
            join_compact(
                report
                    .file_rankings
                    .iter()
                    .map(|f| format!("{} {}L", f.name, f.lines)),
            ),
        ));
    }
    if obs.longest_stylesheet_ranking && !report.stylesheet_rankings.is_empty() {
        lines.push((
            "Stylesheets".to_string(),
            join_compact(
                report
                    .stylesheet_rankings
                    .iter()
                    .map(|s| format!("{} {}L/{}dup", s.name, s.lines, s.duplicate_selector_count)),
            ),
        ));
    }
    if let Some(git) = &report.git {
        if obs.total_commit_count || obs.contributor_count || obs.commit_concentration {
            let contributors = if git.contributor_count == 1 {
                "1 contributor".to_string()
            } else {
                format!("{} contributors", git.contributor_count)
            };
            // A "bus factor" hint: one author, or a few owning almost everything.
            let ownership = if git.contributor_count == 1 {
                " · bus factor 1".to_string()
            } else if git.commit_concentration >= 0.7 {
                format!(
                    " · top 3 own {:.0}% (concentrated)",
                    git.commit_concentration * 100.0
                )
            } else {
                format!(" · top 3 own {:.0}%", git.commit_concentration * 100.0)
            };
            lines.push((
                "Git".to_string(),
                format!(
                    "{} commits · {}{}",
                    git.total_commits, contributors, ownership
                ),
            ));
        }
        if obs.code_change_hotspots && !git.hotspots.is_empty() {
            lines.push((
                "Hotspots".to_string(),
                join_compact(
                    git.hotspots
                        .iter()
                        .map(|h| format!("{} ({})", base_name(&h.path), h.commits)),
                ),
            ));
        }
    }

    if lines.is_empty() {
        return;
    }

    heading(out, "Details");
    for (label, value) in lines {
        let _ = writeln!(out, "  {:<14} {}", label.dimmed(), value.dimmed());
    }
    let _ = writeln!(out);
}

// ---- presentation helpers ----

fn heading(out: &mut String, title: &str) {
    let _ = writeln!(out, "{}", title.bold().cyan());
}

fn paint_score(score: u8, text: String) -> ColoredString {
    if score >= 85 {
        text.green().bold()
    } else if score >= 70 {
        text.yellow().bold()
    } else {
        text.red().bold()
    }
}

fn paint_grade(grade: &str) -> ColoredString {
    match grade {
        "A" | "B" => grade.green().bold(),
        "C" => grade.yellow().bold(),
        _ => grade.red().bold(),
    }
}

/// Paints a summary count yellow when it is non-zero (something to look at) and
/// dim when it is zero — a quick at-a-glance read without making a judgment.
fn paint_count(count: usize, text: String) -> ColoredString {
    if count > 0 {
        text.yellow()
    } else {
        text.dimmed()
    }
}

fn severity_badge(severity: Severity) -> ColoredString {
    match severity {
        Severity::Error => " ERR ".bold().white().on_red(),
        Severity::Warning => " WRN ".bold().black().on_yellow(),
        Severity::Info => " INF ".bold().black().on_cyan(),
    }
}

/// A 10-cell bar, filled proportionally to the score and colored by band.
fn bar(score: u8) -> ColoredString {
    let filled = (score.min(100) / 10) as usize;
    let mut text = String::new();
    text.extend(std::iter::repeat_n('#', filled));
    text.extend(std::iter::repeat_n('-', 10 - filled));
    if score >= 85 {
        text.green()
    } else if score >= 70 {
        text.yellow()
    } else {
        text.red()
    }
}

fn count_badge<F>(count: usize, suffix: &str, paint: F) -> String
where
    F: Fn(String) -> ColoredString,
{
    if count == 0 {
        "·".dimmed().to_string()
    } else {
        paint(format!("{}{}", count, suffix)).to_string()
    }
}

/// Joins up to five items with `·`, noting how many more were dropped.
fn join_compact(items: impl Iterator<Item = String>) -> String {
    let all: Vec<String> = items.collect();
    let shown = all.iter().take(5).cloned().collect::<Vec<_>>().join(" · ");
    if all.len() > 5 {
        format!("{} (+{} more)", shown, all.len() - 5)
    } else {
        shown
    }
}

fn clip(text: &str, max: usize) -> String {
    if text.chars().count() <= max {
        return text.to_string();
    }
    let cut: String = text.chars().take(max.saturating_sub(1)).collect();
    format!("{cut}…")
}

fn base_name(path: &str) -> &str {
    path.rsplit(['/', '\\']).next().unwrap_or(path)
}

/// Version of the JSON report contract. Bump on any breaking shape change so
/// service consumers can branch on it.
const SCHEMA_VERSION: u32 = 3;

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
struct JsonReviewReport {
    schema_version: u32,
    summary: JsonSummary,
    repository: super::model::RepositoryProfile,
    areas: Vec<super::model::AreaHealth>,
    priorities: Vec<super::model::Priority>,
    metrics: Vec<super::model::MetricResult>,
    /// The "safety / bug risk" view: the subset of findings whose category is a
    /// correctness risk (Safety / Type safety / Error handling / Resource leak /
    /// React / Angular), pulled out so service consumers can branch on risk
    /// directly. These are the same findings already counted in the metrics.
    safety_risks: Vec<Finding>,
    /// Findings ingested from an external linter (ESLint). Kept separate from
    /// metric findings because they do not affect the scores.
    lint_findings: Vec<Finding>,
    /// Frontend classification + evidence (React / Angular / Mixed / …).
    frontend: FrontendProfile,
    observability: JsonObservability,
}

/// Reviewer categories that represent a correctness / safety risk (as opposed to
/// style or structure). Drives the JSON `safety_risks` view.
fn is_risk_category(category: &str) -> bool {
    matches!(
        category,
        "Safety" | "Type safety" | "Error handling" | "Resource leak" | "React" | "Angular"
    )
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
struct JsonSummary {
    score: u8,
    grade: String,
    verdict: String,
    risk_level: &'static str,
    passed: bool,
    gate_threshold: u8,
    weakest_metric: Option<&'static str>,
    problem_count: usize,
    issue_categories: Vec<CategoryCount>,
    scope: Option<super::model::ReviewScope>,
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
struct JsonObservability {
    function_summary: super::model::FunctionSummary,
    function_rankings: JsonFunctionRankings,
    file_rankings: Vec<FileRanking>,
    stylesheet_rankings: Vec<StylesheetRanking>,
    git: Option<super::model::GitSnapshot>,
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
struct JsonFunctionRankings {
    longest_functions: Vec<FunctionRanking>,
    most_complex_functions: Vec<FunctionRanking>,
    functions_with_unused_params: Vec<FunctionRanking>,
    possibly_unused_functions: Vec<FunctionRanking>,
}

impl JsonReviewReport {
    fn from_report(report: &ReviewReport) -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            summary: JsonSummary {
                score: report.overall,
                grade: report.grade.clone(),
                verdict: report.verdict.to_string(),
                risk_level: report.risk_level,
                passed: report.passed,
                gate_threshold: report.config.thresholds.overall_score,
                weakest_metric: report.worst_metric,
                problem_count: report.issue_categories.iter().map(|c| c.count).sum(),
                issue_categories: report.issue_categories.clone(),
                scope: report.scope.clone(),
            },
            repository: report.profile.clone(),
            areas: report.areas.clone(),
            priorities: report.priorities.clone(),
            metrics: report.metrics.clone(),
            safety_risks: report
                .findings
                .iter()
                .filter(|f| is_risk_category(f.category))
                .cloned()
                .collect(),
            lint_findings: report.lint_findings.clone(),
            frontend: report.frontend.clone(),
            observability: JsonObservability {
                function_summary: report.function_summary.clone(),
                function_rankings: JsonFunctionRankings {
                    longest_functions: report.function_rankings.clone(),
                    most_complex_functions: report.most_complex.clone(),
                    functions_with_unused_params: report.param_hygiene.clone(),
                    possibly_unused_functions: report.dead_code.clone(),
                },
                file_rankings: report.file_rankings.clone(),
                stylesheet_rankings: report.stylesheet_rankings.clone(),
                git: report.git.clone(),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::model::{
        FunctionSignals, FunctionSnapshot, RepositoryProfile, RepositorySnapshot,
    };

    fn func(
        name: &str,
        language: &'static str,
        lines: usize,
        params: usize,
        unused: &[&str],
    ) -> FunctionSnapshot {
        FunctionSnapshot {
            file: "x.rs".to_string(),
            name: name.to_string(),
            language,
            start_line: 1,
            end_line: lines,
            lines,
            param_count: params,
            params: Vec::new(),
            unused_params: unused.iter().map(|s| s.to_string()).collect(),
            cyclomatic: 1,
            max_nesting: 0,
            references: 0,
            referenced_by: Vec::new(),
            signals: FunctionSignals::default(),
        }
    }

    #[test]
    fn function_summary_aggregates_facts() {
        let functions = vec![
            func("a", "rust", 100, 6, &[]),         // long + over-limit + 4+
            func("b", "typescript", 10, 0, &[]),    // zero-arg
            func("c", "typescript", 20, 2, &["x"]), // one unused param
        ];
        let snapshot = RepositorySnapshot::new(
            RepositoryProfile::new("r", 0, 0, 0, 0),
            Vec::new(),
            functions,
            Vec::new(),
            None,
        );

        let functions_ref: Vec<&FunctionSnapshot> = snapshot.functions.iter().collect();
        let summary = build_function_summary(&functions_ref, &ReviewConfig::default(), 0);
        assert_eq!(summary.function_count, 3);
        assert_eq!(summary.max_function_lines, 100);
        assert_eq!(summary.long_function_count, 1);
        assert_eq!(summary.total_param_count, 8);
        assert_eq!(summary.zero_param_function_count, 1);
        assert_eq!(summary.four_plus_param_function_count, 1);
        assert_eq!(summary.over_param_limit_count, 1);
        assert_eq!(summary.unused_param_count, 1);
        assert_eq!(summary.functions_with_unused_params, 1);
        // Sorted by count desc: typescript (2) before rust (1).
        assert_eq!(summary.language_breakdown[0].language, "typescript");
        assert_eq!(summary.language_breakdown[0].count, 2);
    }
}
