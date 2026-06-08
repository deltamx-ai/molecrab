use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::process::Command;

use super::model::{
    FileSnapshot, FunctionSnapshot, GitAuthorStat, GitHotspot, GitSnapshot, RepositoryProfile,
    RepositorySnapshot,
};

pub fn scan_repository(root: &Path) -> Result<RepositorySnapshot, String> {
    if !root.exists() {
        return Err(format!("path does not exist: {}", root.display()));
    }

    let mut files = Vec::new();
    visit_path(root, root, &mut files)?;

    let functions = collect_functions(&files);
    let git = collect_git_snapshot(root);

    let file_count = files.len();
    let source_file_count = files.iter().filter(|f| !f.is_test).count();
    let test_file_count = files.iter().filter(|f| f.is_test).count();
    let total_lines = files.iter().map(|f| f.lines).sum();
    let profile = RepositoryProfile::new(
        root.display().to_string(),
        file_count,
        source_file_count,
        test_file_count,
        total_lines,
    );

    Ok(RepositorySnapshot::new(profile, files, functions, git))
}

fn visit_path(root: &Path, current: &Path, files: &mut Vec<FileSnapshot>) -> Result<(), String> {
    let entries = fs::read_dir(current)
        .map_err(|err| format!("failed to read directory {}: {}", current.display(), err))?;

    for entry in entries {
        let entry = entry
            .map_err(|err| format!("failed to read entry in {}: {}", current.display(), err))?;
        let path = entry.path();
        let file_type = entry
            .file_type()
            .map_err(|err| format!("failed to inspect {}: {}", path.display(), err))?;

        if file_type.is_dir() {
            if should_skip_dir(&path) {
                continue;
            }
            visit_path(root, &path, files)?;
            continue;
        }

        if file_type.is_file() {
            let relative = path
                .strip_prefix(root)
                .unwrap_or(&path)
                .to_string_lossy()
                .to_string();
            let name = path
                .file_name()
                .and_then(|v| v.to_str())
                .unwrap_or_default()
                .to_string();
            let content = fs::read_to_string(&path).ok();
            let lines = content.as_deref().map(count_lines).unwrap_or(0);
            let bytes = fs::metadata(&path).map(|meta| meta.len()).unwrap_or(0);
            let depth = path
                .components()
                .count()
                .saturating_sub(root.components().count());
            let is_test = is_test_path(&path, content.as_deref());

            files.push(FileSnapshot {
                path: relative,
                name,
                lines,
                bytes,
                depth,
                is_test,
                content,
            });
        }
    }

    Ok(())
}

fn should_skip_dir(path: &Path) -> bool {
    matches!(
        path.file_name().and_then(|name| name.to_str()),
        Some(".git" | "target" | "node_modules" | "dist" | "build" | ".idea" | ".vscode")
    )
}

fn is_test_path(path: &Path, content: Option<&str>) -> bool {
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or_default();
    let lower = path.to_string_lossy().to_lowercase();
    if lower.contains("/tests/") || lower.contains("\\tests\\") || name.contains("test") {
        return true;
    }
    content.is_some_and(|c| c.contains("#[test]") || c.contains("#[cfg(test)]"))
}

fn count_lines(text: &str) -> usize {
    text.lines().count().max(1)
}

fn collect_functions(files: &[FileSnapshot]) -> Vec<FunctionSnapshot> {
    let mut functions = Vec::new();
    for file in files {
        if let Some(content) = &file.content {
            functions.extend(scan_rust_functions(file, content));
        }
    }
    functions
}

fn scan_rust_functions(file: &FileSnapshot, content: &str) -> Vec<FunctionSnapshot> {
    let mut functions = Vec::new();
    let lines: Vec<&str> = content.lines().collect();
    let mut i = 0;

    while i < lines.len() {
        let line = lines[i].trim_start();
        if let Some(name) = extract_rust_fn_name(line) {
            let start = i + 1;
            let end = find_function_end(&lines, i).unwrap_or(lines.len());
            let line_count = end.saturating_sub(start).max(1);
            functions.push(FunctionSnapshot {
                file: file.path.clone(),
                name,
                start_line: start,
                end_line: end,
                lines: line_count,
            });
            i = end;
            continue;
        }
        i += 1;
    }

    functions
}

fn extract_rust_fn_name(line: &str) -> Option<String> {
    let keywords = ["pub fn ", "fn ", "pub(crate) fn ", "pub(super) fn "];
    for keyword in keywords {
        if let Some(rest) = line.strip_prefix(keyword) {
            let name = rest
                .split(|c: char| c == '(' || c.is_whitespace())
                .next()
                .unwrap_or_default();
            if !name.is_empty() {
                return Some(name.to_string());
            }
        }
    }
    None
}

fn find_function_end(lines: &[&str], start: usize) -> Option<usize> {
    let mut brace_depth = 0usize;
    let mut seen_open = false;

    for (idx, line) in lines.iter().enumerate().skip(start) {
        for ch in line.chars() {
            match ch {
                '{' => {
                    brace_depth += 1;
                    seen_open = true;
                }
                '}' => {
                    brace_depth = brace_depth.saturating_sub(1);
                    if seen_open && brace_depth == 0 {
                        return Some(idx + 1);
                    }
                }
                _ => {}
            }
        }
    }

    None
}

fn collect_git_snapshot(root: &Path) -> Option<GitSnapshot> {
    if !is_git_repo(root) {
        return None;
    }

    let total_commits = run_git_count(root, &["rev-list", "--count", "HEAD"]);
    let authors = run_git_lines(root, &["shortlog", "-sne", "--all", "--no-merges", "HEAD"]);
    let recent_authors = run_git_lines(
        root,
        &[
            "shortlog",
            "-sne",
            "--all",
            "--no-merges",
            "--since=30.days",
            "HEAD",
        ],
    );
    let hotspots = run_git_lines(root, &["log", "--name-only", "--pretty=format:", "--all"]);

    let total_commits = total_commits?;
    let authors = authors.unwrap_or_default();
    let recent_authors = recent_authors.unwrap_or_default();
    let hotspots = hotspots.unwrap_or_default();

    let mut author_stats = parse_author_stats(authors);
    let recent_active_authors = parse_author_stats(recent_authors);
    let total_author_commits: u32 = author_stats.iter().map(|a| a.commits).sum();
    let top_commit_sum: u32 = author_stats.iter().take(3).map(|a| a.commits).sum();
    let contributor_count = author_stats.len();
    let commit_concentration = if total_author_commits == 0 {
        0.0
    } else {
        (top_commit_sum as f64) / (total_author_commits as f64)
    };

    let hotspot_stats = parse_hotspots(hotspots);
    author_stats.sort_by(|a, b| b.commits.cmp(&a.commits).then_with(|| a.name.cmp(&b.name)));

    Some(GitSnapshot {
        total_commits,
        contributor_count,
        commit_concentration,
        recent_active_authors,
        author_commit_counts: author_stats,
        hotspots: hotspot_stats,
    })
}

fn is_git_repo(root: &Path) -> bool {
    run_git_output(root, &["rev-parse", "--is-inside-work-tree"])
        .as_deref()
        .map(str::trim)
        == Some("true")
}

fn run_git_count(root: &Path, args: &[&str]) -> Option<u32> {
    run_git_output(root, args)?.trim().parse::<u32>().ok()
}

fn run_git_lines(root: &Path, args: &[&str]) -> Option<Vec<String>> {
    let output = run_git_output(root, args)?;
    Some(output.lines().map(|line| line.to_string()).collect())
}

fn run_git_output(root: &Path, args: &[&str]) -> Option<String> {
    let output = Command::new("git")
        .args(args)
        .current_dir(root)
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let text = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if text.is_empty() { None } else { Some(text) }
}

fn parse_author_stats(lines: Vec<String>) -> Vec<GitAuthorStat> {
    let mut stats = Vec::new();
    for line in lines {
        let trimmed = line.trim();
        let mut parts = trimmed.split_whitespace();
        let commits = parts
            .next()
            .unwrap_or_default()
            .trim()
            .parse::<u32>()
            .unwrap_or(0);
        let name = parts.collect::<Vec<_>>().join(" ").trim().to_string();
        if !name.is_empty() {
            stats.push(GitAuthorStat { name, commits });
        }
    }
    stats.sort_by(|a, b| b.commits.cmp(&a.commits).then_with(|| a.name.cmp(&b.name)));
    stats
}

fn parse_hotspots(lines: Vec<String>) -> Vec<GitHotspot> {
    let mut map = BTreeMap::<String, u32>::new();
    for line in lines {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        *map.entry(trimmed.to_string()).or_insert(0) += 1;
    }

    let mut items: Vec<GitHotspot> = map
        .into_iter()
        .map(|(path, commits)| GitHotspot { path, commits })
        .collect();
    items.sort_by(|a, b| b.commits.cmp(&a.commits).then_with(|| a.path.cmp(&b.path)));
    items
}
