use std::fmt::Write;
use std::path::PathBuf;

use colored::Colorize;

use super::config::ReviewConfig;
use super::metrics;
use super::model::{
    FileRanking, Finding, FunctionRanking, MetricResult, RepositorySnapshot, ReviewReport, Severity,
};
use super::scanner;

pub fn run(path: PathBuf, config_path: Option<PathBuf>) -> i32 {
    match analyze(path, config_path) {
        Ok(report) => {
            println!("{}", render_report(&report));
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
    let snapshot = scanner::scan_repository(&path)?;
    let metric_results = metrics::evaluate(&snapshot, &config);
    Ok(build_report(snapshot, config, metric_results))
}

fn build_report(
    snapshot: RepositorySnapshot,
    config: ReviewConfig,
    metrics: Vec<MetricResult>,
) -> ReviewReport {
    let findings: Vec<Finding> = metrics
        .iter()
        .flat_map(|metric| metric.findings.clone())
        .collect();

    let overall = weighted_score(&metrics);
    let adjusted_overall = apply_config_floor(overall, config.thresholds.overall_score);
    let grade = grade_for(adjusted_overall).to_string();
    let profile = snapshot.profile.clone();
    let file_rankings = rank_files(&snapshot, &config);
    let function_rankings = rank_functions(&snapshot, &config);
    let git = snapshot.git.clone();

    ReviewReport {
        profile,
        config,
        metrics,
        findings,
        overall: adjusted_overall,
        grade,
        file_rankings,
        function_rankings,
        git,
    }
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

fn apply_config_floor(score: u8, floor: u8) -> u8 {
    score.max(floor)
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

fn rank_functions(snapshot: &RepositorySnapshot, config: &ReviewConfig) -> Vec<FunctionRanking> {
    if !config.observability.longest_function_ranking {
        return Vec::new();
    }

    let mut functions = snapshot
        .functions
        .iter()
        .filter(|func| func.lines >= config.thresholds.min_function_lines_for_rank as usize)
        .map(|func| FunctionRanking {
            file: func.file.clone(),
            name: func.name.clone(),
            start_line: func.start_line,
            end_line: func.end_line,
            lines: func.lines,
        })
        .collect::<Vec<_>>();

    functions.sort_by(|a, b| b.lines.cmp(&a.lines).then_with(|| a.file.cmp(&b.file)));
    let limit = config.thresholds.top_function_rankings as usize;
    if limit == 0 {
        functions.clear();
    } else {
        functions.truncate(limit);
    }
    functions
}

fn render_report(report: &ReviewReport) -> String {
    let mut out = String::new();

    render_header(&mut out, report);
    render_overview(&mut out, report);
    render_metrics(&mut out, report);
    render_observability(&mut out, report);
    render_findings(&mut out, report);

    out
}

fn render_header(out: &mut String, report: &ReviewReport) {
    let mut line = String::new();
    let status = match report.grade.as_str() {
        "A" | "B" => "healthy".green(),
        "C" => "okay".yellow(),
        _ => "needs work".red(),
    };

    let _ = writeln!(out, "{}", "molecrab review".bold().cyan());
    let _ = writeln!(out, "{}", "================".cyan());
    let _ = writeln!(out);
    let _ = writeln!(
        line,
        "Status: {}  Grade: {}  Score: {}/100",
        status,
        report.grade.bold(),
        report.overall
    );
    let _ = writeln!(out, "{}", line);
}

fn render_overview(out: &mut String, report: &ReviewReport) {
    section(out, "Overview");
    kv(out, "Path", report.profile.path());
    kv(out, "Files", report.profile.file_count().to_string());
    kv(
        out,
        "Source files",
        report.profile.source_file_count().to_string(),
    );
    kv(
        out,
        "Test files",
        report.profile.test_file_count().to_string(),
    );
    kv(out, "Total lines", report.profile.total_lines().to_string());
    kv(
        out,
        "Configured floor",
        format!("{} / 100", report.config.thresholds.overall_score),
    );
    kv(
        out,
        "Observability weight",
        report.config.thresholds.observability_weight.to_string(),
    );
    let enabled_targets = report.config.enabled_observability_targets();
    kv(
        out,
        "Observability enabled",
        if enabled_targets.is_empty() {
            "none".to_string()
        } else {
            enabled_targets.join(", ")
        },
    );
    out.push('\n');
}

fn render_metrics(out: &mut String, report: &ReviewReport) {
    section(out, "Metrics");
    for metric in &report.metrics {
        let label = metric_label(metric.score);
        let _ = writeln!(
            out,
            "{} {:<14} {:>3}/100 (weight {})",
            label, metric.name, metric.score, metric.weight
        );
    }
    out.push('\n');
}

fn render_observability(out: &mut String, report: &ReviewReport) {
    section(out, "Observability");
    render_file_observability(out, report);
    render_function_observability(out, report);
    render_git_observability(out, report);
    out.push('\n');
}

fn render_findings(out: &mut String, report: &ReviewReport) {
    section(out, "Top findings");
    if report.findings.is_empty() {
        let _ = writeln!(out, "- no major issues found");
        return;
    }

    let mut grouped = grouped_findings(&report.findings);

    for (title, items) in [
        ("Errors", &mut grouped.errors),
        ("Warnings", &mut grouped.warnings),
        ("Info", &mut grouped.info),
    ] {
        if items.is_empty() {
            continue;
        }
        let _ = writeln!(out, "{}", title.bold());
        for finding in items.iter().take(5) {
            let severity = finding.severity_label();
            let location = finding
                .file
                .as_deref()
                .map(|file| format!("{}: ", file))
                .unwrap_or_default();
            let _ = writeln!(out, "- [{}] {}{}", severity, location, finding.message);
            let _ = writeln!(out, "  -> {}", finding.suggestion);
        }
        out.push('\n');
    }
}

fn render_file_observability(out: &mut String, report: &ReviewReport) {
    let config = &report.config.observability;
    if !(config.file_names || config.file_paths || config.file_line_counts || config.file_sizes) {
        return;
    }

    section(out, "File observability");
    if report.file_rankings.is_empty() {
        let _ = writeln!(out, "- no file ranking available");
        return;
    }

    for file in &report.file_rankings {
        let mut parts = Vec::new();
        if config.file_names {
            parts.push(format!("name: {}", file.name));
        }
        if config.file_paths {
            parts.push(format!("path: {}", file.path));
        }
        if config.file_line_counts {
            parts.push(format!("lines: {}", file.lines));
        }
        if config.file_sizes {
            parts.push(format!("bytes: {}", file.bytes));
        }
        let _ = writeln!(out, "- {}", parts.join(" | "));
    }
}

fn render_function_observability(out: &mut String, report: &ReviewReport) {
    if !report.config.observability.longest_function_ranking {
        return;
    }

    section(out, "Function observability");
    if report.function_rankings.is_empty() {
        let _ = writeln!(out, "- no function snapshot available");
        return;
    }

    for func in &report.function_rankings {
        let _ = writeln!(
            out,
            "- {} :: {} ({} lines, {}-{})",
            func.file, func.name, func.lines, func.start_line, func.end_line
        );
    }
}

fn render_git_observability(out: &mut String, report: &ReviewReport) {
    let config = &report.config.observability;
    if !(config.contributor_count
        || config.per_author_commit_counts
        || config.total_commit_count
        || config.commit_concentration
        || config.most_recent_active_authors
        || config.code_change_hotspots)
    {
        return;
    }

    section(out, "Git observability");
    if let Some(git) = &report.git {
        if config.total_commit_count {
            kv(out, "Total commits", git.total_commits.to_string());
        }
        if config.contributor_count {
            kv(out, "Contributor count", git.contributor_count.to_string());
        }
        if config.commit_concentration {
            kv(
                out,
                "Commit concentration",
                format!("{:.2}", git.commit_concentration),
            );
        }
        if config.most_recent_active_authors {
            bullet_list(
                out,
                "Most recent active authors",
                &git.recent_active_authors,
                |a| format!("{} ({})", a.name, a.commits),
            );
        }
        if config.per_author_commit_counts {
            bullet_list(
                out,
                "Per-author commit counts",
                &git.author_commit_counts,
                |a| format!("{} ({})", a.name, a.commits),
            );
        }
        if config.code_change_hotspots {
            bullet_list(out, "Code change hotspots", &git.hotspots, |h| {
                format!("{} ({})", h.path, h.commits)
            });
        }
    } else {
        let _ = writeln!(out, "- git data unavailable");
    }
}

fn metric_label(score: u8) -> String {
    if score >= 85 {
        " OK ".black().on_green().to_string()
    } else if score >= 70 {
        "WARN".black().on_yellow().to_string()
    } else {
        "FAIL".white().on_red().to_string()
    }
}

fn section(out: &mut String, title: &str) {
    let _ = writeln!(out, "{}", title.bold().white());
    let _ = writeln!(out, "{}", "-".repeat(title.len()).dimmed());
}

fn kv(out: &mut String, key: &str, value: impl AsRef<str>) {
    let _ = writeln!(out, "- {:<24} {}", key, value.as_ref());
}

fn bullet_list<T, F>(out: &mut String, title: &str, items: &[T], mut render: F)
where
    F: FnMut(&T) -> String,
{
    if items.is_empty() {
        return;
    }
    let _ = writeln!(out, "- {}:", title);
    for item in items.iter().take(5) {
        let _ = writeln!(out, "  - {}", render(item));
    }
}

struct GroupedFindings<'a> {
    errors: Vec<&'a Finding>,
    warnings: Vec<&'a Finding>,
    info: Vec<&'a Finding>,
}

fn grouped_findings<'a>(findings: &'a [Finding]) -> GroupedFindings<'a> {
    let mut grouped = GroupedFindings {
        errors: Vec::new(),
        warnings: Vec::new(),
        info: Vec::new(),
    };

    for finding in findings {
        match finding.severity {
            Severity::Error => grouped.errors.push(finding),
            Severity::Warning => grouped.warnings.push(finding),
            Severity::Info => grouped.info.push(finding),
        }
    }

    grouped
}

trait FindingExt {
    fn severity_label(&self) -> String;
}

impl FindingExt for Finding {
    fn severity_label(&self) -> String {
        match self.severity {
            Severity::Info => "INFO".blue().to_string(),
            Severity::Warning => "WARN".yellow().to_string(),
            Severity::Error => "ERROR".red().to_string(),
        }
    }
}
