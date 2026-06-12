//! Presentation layer for the review report: the terminal (text) renderer and
//! the JSON serializer. Pure formatting — it reads a finished `ReviewReport`
//! plus the few analysis helpers it needs (`severity_rank`, `is_risk_category`)
//! from the parent module, and never computes scores or rankings itself.

use std::fmt::Write;

use colored::{ColoredString, Colorize};
use serde::Serialize;

use super::{is_risk_category, severity_rank};
use crate::core::model::{
    CategoryCount, FileRanking, Finding, FrontendKind, FrontendProfile, FunctionRanking,
    ReviewReport, Severity, StylesheetRanking,
};

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
    if crate::core::model::referenceable_fn_name(&func.name).is_some() {
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
    repository: crate::core::model::RepositoryProfile,
    areas: Vec<crate::core::model::AreaHealth>,
    priorities: Vec<crate::core::model::Priority>,
    metrics: Vec<crate::core::model::MetricResult>,
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
    scope: Option<crate::core::model::ReviewScope>,
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
struct JsonObservability {
    function_summary: crate::core::model::FunctionSummary,
    function_rankings: JsonFunctionRankings,
    file_rankings: Vec<FileRanking>,
    stylesheet_rankings: Vec<StylesheetRanking>,
    git: Option<crate::core::model::GitSnapshot>,
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
