use std::cmp::Ordering;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::PathBuf;

use super::classify::FileCategory;
use super::config::ReviewConfig;
use super::metrics;
use super::model::{
    AreaHealth, CategoryCount, FileRanking, Finding, FunctionRanking, FunctionSnapshot,
    FunctionSummary, LanguageCount, MetricResult, Priority, RepositorySnapshot, ReviewReport,
    ReviewScope, Severity, StylesheetRanking, area_of, is_dead_code_candidate,
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

mod render;
pub(crate) use render::{render_json_report, render_text_report};

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

/// Reviewer categories that represent a correctness / safety risk (as opposed to
/// style or structure). Drives the JSON `safety_risks` view.
fn is_risk_category(category: &str) -> bool {
    matches!(
        category,
        "Safety" | "Type safety" | "Error handling" | "Resource leak" | "React" | "Angular"
    )
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
