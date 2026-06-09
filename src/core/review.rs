use std::collections::{BTreeMap, HashMap};
use std::fmt::Write;
use std::path::PathBuf;

use colored::{ColoredString, Colorize};
use serde::Serialize;

use crate::cli::OutputFormat;

use super::classify::FileCategory;
use super::config::ReviewConfig;
use super::metrics;
use super::model::{
    AreaHealth, FileRanking, Finding, FunctionRanking, FunctionSnapshot, FunctionSummary,
    LanguageCount, MetricResult, Priority, RepositorySnapshot, ReviewReport, Severity,
    StylesheetRanking, area_of, is_dead_code_candidate,
};
use super::scanner;

pub fn run(path: PathBuf, config_path: Option<PathBuf>, format: OutputFormat) -> i32 {
    match analyze(path, config_path) {
        Ok(report) => {
            match format {
                OutputFormat::Text => println!("{}", render_text_report(&report)),
                OutputFormat::Json => match render_json_report(&report) {
                    Ok(json) => println!("{}", json),
                    Err(err) => {
                        eprintln!("review failed: {}", err.red());
                        return 1;
                    }
                },
            }
            0
        }
        Err(err) => {
            eprintln!("review failed: {}", err.red());
            1
        }
    }
}

pub fn analyze(path: PathBuf, config_path: Option<PathBuf>) -> Result<ReviewReport, String> {
    let config = ReviewConfig::load_for_repository(&path, config_path.as_deref())?;
    let snapshot = scanner::scan_repository(&path, &config)?;
    let metric_results = metrics::evaluate(&snapshot, &config);
    Ok(build_report(snapshot, config, metric_results))
}

fn build_report(
    snapshot: RepositorySnapshot,
    config: ReviewConfig,
    metrics: Vec<MetricResult>,
) -> ReviewReport {
    let findings = dedupe_findings(&metrics);

    // Honest score: the real weighted average, never floored upward. The
    // configured `overall_score` is a pass/fail gate, not a minimum to display.
    let overall = weighted_score(&metrics);
    let grade = grade_for(overall).to_string();
    let passed = overall >= config.thresholds.overall_score;
    let verdict = verdict_label(&grade, &metrics, config.thresholds.failing_metric_score);
    let worst_metric = metrics
        .iter()
        .min_by_key(|metric| metric.score)
        .map(|m| m.name);

    let priorities = build_priorities(&snapshot, &metrics, &config);
    let areas = build_areas(&snapshot, &metrics);

    let categories = category_map(&snapshot);
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

    let profile = snapshot.profile.clone();
    let file_rankings = rank_files(&snapshot, &config);
    let function_summary = build_function_summary(&snapshot, &config, unreferenced.len());
    let function_rankings = rank_functions(&snapshot, &config);
    let param_hygiene = rank_param_hygiene(&snapshot, &config);
    let dead_code = rank_dead_code(&unreferenced, &config);
    let stylesheet_rankings = rank_stylesheets(&snapshot, &config);
    let git = trimmed_git(&snapshot, &config);

    ReviewReport {
        profile,
        config,
        metrics,
        findings,
        priorities,
        areas,
        overall,
        grade,
        verdict,
        passed,
        worst_metric,
        file_rankings,
        function_summary,
        function_rankings,
        param_hygiene,
        dead_code,
        stylesheet_rankings,
        git,
    }
}

/// Aggregates judgment-free statistics over every analyzed function. Thresholds
/// (long / over-limit) come from config; the summary only counts, it does not
/// judge — findings do that. `unreferenced_function_count` is passed in since it
/// needs file categories the caller already computed.
fn build_function_summary(
    snapshot: &RepositorySnapshot,
    config: &ReviewConfig,
    unreferenced_function_count: usize,
) -> FunctionSummary {
    let functions = &snapshot.functions;
    let max_lines = config.thresholds.max_function_lines as usize;
    let max_params = config.thresholds.max_function_params as usize;

    let function_count = functions.len();
    let total_lines: usize = functions.iter().map(|f| f.lines).sum();
    let total_param_count: usize = functions.iter().map(|f| f.param_count).sum();
    let unused_param_count: usize = functions.iter().map(|f| f.unused_params.len()).sum();

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

/// Ranks every finding by impact and keeps the most important ones. Impact
/// blends severity, the metric's weight, the finding's score penalty, and
/// whether it points at first-party source (noise files never reach here).
fn build_priorities(
    snapshot: &RepositorySnapshot,
    metrics: &[MetricResult],
    config: &ReviewConfig,
) -> Vec<Priority> {
    let categories = category_map(snapshot);
    let mut priorities = Vec::new();
    for metric in metrics {
        for finding in &metric.findings {
            priorities.push(Priority {
                id: priority_id(finding),
                impact: impact_of(finding, metric.weight, &categories),
                severity: finding.severity,
                metric: finding.metric,
                file: finding.file.clone(),
                message: finding.message.clone(),
                suggestion: finding.suggestion.clone(),
            });
        }
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

fn rank_files(snapshot: &RepositorySnapshot, config: &ReviewConfig) -> Vec<FileRanking> {
    if !config.observability.longest_file_ranking {
        return Vec::new();
    }

    let mut files = snapshot
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

    files.sort_by(|a, b| b.lines.cmp(&a.lines).then_with(|| b.bytes.cmp(&a.bytes)));
    let limit = config.thresholds.top_file_rankings as usize;
    if limit == 0 {
        files.clear();
    } else {
        files.truncate(limit);
    }
    files
}

/// Evidence: the longest functions. (The aggregate health lives in
/// `function_summary`; this is just the supporting sample.)
fn rank_functions(snapshot: &RepositorySnapshot, config: &ReviewConfig) -> Vec<FunctionRanking> {
    if !config.observability.longest_function_ranking {
        return Vec::new();
    }

    let mut functions = snapshot
        .functions
        .iter()
        .filter(|func| func.lines >= config.thresholds.min_function_lines_for_rank as usize)
        .map(|func| to_function_ranking(func, config))
        .collect::<Vec<_>>();

    functions.sort_by(|a, b| {
        b.lines
            .cmp(&a.lines)
            .then_with(|| b.param_count.cmp(&a.param_count))
            .then_with(|| a.file.cmp(&b.file))
    });
    let limit = config.thresholds.top_function_rankings as usize;
    if limit == 0 {
        functions.clear();
    } else {
        functions.truncate(limit);
    }
    functions
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

    let mut functions = snapshot
        .functions
        .iter()
        .filter(|func| !func.unused_params.is_empty())
        .map(|func| to_function_ranking(func, config))
        .collect::<Vec<_>>();

    functions.sort_by(|a, b| {
        b.unused_params
            .len()
            .cmp(&a.unused_params.len())
            .then_with(|| b.param_count.cmp(&a.param_count))
            .then_with(|| a.file.cmp(&b.file))
    });
    let limit = config.thresholds.top_function_rankings as usize;
    if limit == 0 {
        functions.clear();
    } else {
        functions.truncate(limit);
    }
    functions
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
    let mut functions: Vec<FunctionRanking> = unreferenced
        .iter()
        .map(|&func| to_function_ranking(func, config))
        .collect();
    functions.sort_by(|a, b| b.lines.cmp(&a.lines).then_with(|| a.file.cmp(&b.file)));
    let limit = config.thresholds.top_function_rankings as usize;
    if limit == 0 {
        functions.clear();
    } else {
        functions.truncate(limit);
    }
    functions
}

fn to_function_ranking(func: &FunctionSnapshot, config: &ReviewConfig) -> FunctionRanking {
    let max_lines = config.thresholds.max_function_lines as usize;
    let max_params = config.thresholds.max_function_params as usize;
    let mut flags = Vec::new();
    if func.lines > max_lines {
        flags.push("long");
    }
    if func.param_count > max_params {
        flags.push("many-params");
    }
    if !func.unused_params.is_empty() {
        flags.push("unused-param");
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

    let mut stylesheets = snapshot
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
        })
        .collect::<Vec<_>>();

    // Longest stylesheets first, then the heaviest single rule, then nesting.
    stylesheets.sort_by(|a, b| {
        b.lines
            .cmp(&a.lines)
            .then_with(|| b.largest_rule_lines.cmp(&a.largest_rule_lines))
            .then_with(|| b.max_nesting_depth.cmp(&a.max_nesting_depth))
            .then_with(|| a.file.cmp(&b.file))
    });
    let limit = config.thresholds.top_stylesheet_rankings as usize;
    if limit == 0 {
        stylesheets.clear();
    } else {
        stylesheets.truncate(limit);
    }
    stylesheets
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

fn render_text_report(report: &ReviewReport) -> String {
    let mut out = String::new();
    render_summary(&mut out, report);
    render_priorities(&mut out, report);
    render_scores(&mut out, report);
    render_areas(&mut out, report);
    render_functions(&mut out, report);
    render_details(&mut out, report);
    out
}

fn render_json_report(report: &ReviewReport) -> Result<String, String> {
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

fn render_priorities(out: &mut String, report: &ReviewReport) {
    heading(out, "Top issues");
    if report.priorities.is_empty() {
        let _ = writeln!(out, "  {}", "no issues found".green());
        let _ = writeln!(out);
        return;
    }

    for (idx, priority) in report.priorities.iter().enumerate() {
        let _ = writeln!(
            out,
            "  {} {}  {}",
            format!("{}.", idx + 1).bold(),
            severity_badge(priority.severity),
            priority.message,
        );
        let location = priority
            .file
            .as_deref()
            .map(|file| file.cyan().to_string())
            .unwrap_or_else(|| "repo-wide".dimmed().to_string());
        let _ = writeln!(
            out,
            "      {}  {}",
            location,
            format!("[{}]", priority.metric).dimmed()
        );
        let _ = writeln!(
            out,
            "      {} {}",
            "->".dimmed(),
            priority.suggestion.dimmed()
        );
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

/// Function observability, two layers: a judgment-free statistical **summary**
/// first (overall health at a glance), then the **evidence** (longest functions
/// and unused-parameter samples).
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
    let max_params = report.config.thresholds.max_function_params as usize;

    // ---- Summary (facts only) ----
    let _ = writeln!(
        out,
        "  {} functions · avg {:.0} lines · max {} · {}",
        summary.function_count,
        summary.average_function_lines,
        summary.max_function_lines,
        paint_count(
            summary.long_function_count,
            format!("{} long (>{})", summary.long_function_count, max_lines),
        ),
    );
    let _ = writeln!(
        out,
        "  {} params · avg {:.1}/fn · {} zero-arg · {} with 4+ · {}",
        summary.total_param_count,
        summary.average_param_count,
        summary.zero_param_function_count,
        summary.four_plus_param_function_count,
        paint_count(
            summary.over_param_limit_count,
            format!(
                "{} over limit (>{})",
                summary.over_param_limit_count, max_params
            ),
        ),
    );
    if summary.unused_param_count > 0 {
        let _ = writeln!(
            out,
            "  {}",
            format!(
                "{} unused param(s) across {} function(s)",
                summary.unused_param_count, summary.functions_with_unused_params
            )
            .yellow(),
        );
    }
    if summary.unreferenced_function_count > 0 {
        let _ = writeln!(
            out,
            "  {}",
            format!(
                "{} unreferenced function(s) — possible dead code",
                summary.unreferenced_function_count
            )
            .yellow(),
        );
    }
    if !summary.language_breakdown.is_empty() {
        let langs = summary
            .language_breakdown
            .iter()
            .map(|lang| format!("{} {}", lang.language, lang.count))
            .collect::<Vec<_>>()
            .join(" · ");
        let _ = writeln!(out, "  {}", format!("languages: {}", langs).dimmed());
    }
    let _ = writeln!(out);

    // ---- Evidence ----
    if !report.function_rankings.is_empty() {
        let _ = writeln!(out, "  {}", "Longest functions".bold());
        for func in &report.function_rankings {
            render_function_entry(out, func, false);
        }
        let _ = writeln!(out);
    }
    if report.config.observability.function_param_analysis && !report.param_hygiene.is_empty() {
        let _ = writeln!(out, "  {}", "Unused parameters".bold());
        for func in &report.param_hygiene {
            render_function_entry(out, func, false);
        }
        let _ = writeln!(out);
    }
    if !report.dead_code.is_empty() {
        let _ = writeln!(out, "  {}", "Possibly unused (no references)".bold());
        for func in &report.dead_code {
            render_function_entry(out, func, true);
        }
        let _ = writeln!(out);
    }
}

/// One function rendered as evidence: a name + quality-flags line, then a dim
/// stats + location line. The quality flags come from the analysis layer
/// (`func.flags`); `unreferenced` adds the "dead?" flag for the dead-code list.
fn render_function_entry(out: &mut String, func: &FunctionRanking, unreferenced: bool) {
    let mut flags: Vec<String> = Vec::new();
    if unreferenced {
        flags.push("dead?".red().bold().to_string());
    }
    for flag in &func.flags {
        flags.push(flag.yellow().to_string());
    }
    let flags = if flags.is_empty() {
        "ok".green().to_string()
    } else {
        flags.join(" ")
    };

    let mut stats = vec![format!("{} lines", func.lines)];
    if func.unused_params.is_empty() {
        stats.push(format!(
            "{} param{}",
            func.param_count,
            plural(func.param_count)
        ));
    } else {
        stats.push(format!(
            "{} param{} ({} unused: {})",
            func.param_count,
            plural(func.param_count),
            func.unused_params.len(),
            func.unused_params.join(", ")
        ));
    }
    if super::model::referenceable_fn_name(&func.name).is_some() {
        stats.push(format!("~{} refs", func.references));
    }

    let _ = writeln!(out, "    {}  {}", clip(&func.name, 30).bold(), flags);
    let _ = writeln!(
        out,
        "        {}  {}",
        stats.join(" · "),
        format!("{}:{}", func.file, func.start_line).dimmed()
    );
    if !func.referenced_by.is_empty() {
        let shown = func
            .referenced_by
            .iter()
            .take(3)
            .map(|reference| format!("{} ({})", reference.file, reference.count))
            .collect::<Vec<_>>()
            .join(" · ");
        let more = func.referenced_by.len().saturating_sub(3);
        let suffix = if more > 0 {
            format!(" (+{} more)", more)
        } else {
            String::new()
        };
        let _ = writeln!(
            out,
            "        {}",
            format!("used by: {}{}", shown, suffix).dimmed()
        );
    }
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
            lines.push((
                "Git".to_string(),
                format!(
                    "{} commits · {} contributors · top-3 own {:.0}%",
                    git.total_commits,
                    git.contributor_count,
                    git.commit_concentration * 100.0
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

fn plural(count: usize) -> &'static str {
    if count == 1 { "" } else { "s" }
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
struct JsonReviewReport {
    summary: JsonSummary,
    repository: super::model::RepositoryProfile,
    areas: Vec<super::model::AreaHealth>,
    priorities: Vec<super::model::Priority>,
    metrics: Vec<super::model::MetricResult>,
    observability: JsonObservability,
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
struct JsonSummary {
    score: u8,
    grade: String,
    verdict: String,
    passed: bool,
    gate_threshold: u8,
    weakest_metric: Option<&'static str>,
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
    functions_with_unused_params: Vec<FunctionRanking>,
    possibly_unused_functions: Vec<FunctionRanking>,
}

impl JsonReviewReport {
    fn from_report(report: &ReviewReport) -> Self {
        Self {
            summary: JsonSummary {
                score: report.overall,
                grade: report.grade.clone(),
                verdict: report.verdict.to_string(),
                passed: report.passed,
                gate_threshold: report.config.thresholds.overall_score,
                weakest_metric: report.worst_metric,
            },
            repository: report.profile.clone(),
            areas: report.areas.clone(),
            priorities: report.priorities.clone(),
            metrics: report.metrics.clone(),
            observability: JsonObservability {
                function_summary: report.function_summary.clone(),
                function_rankings: JsonFunctionRankings {
                    longest_functions: report.function_rankings.clone(),
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
    use crate::core::model::{FunctionSnapshot, RepositoryProfile, RepositorySnapshot};

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
            references: 0,
            referenced_by: Vec::new(),
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

        let summary = build_function_summary(&snapshot, &ReviewConfig::default(), 0);
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
