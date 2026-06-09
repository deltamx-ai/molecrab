use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use std::path::Path;
use std::process::Command;

use super::classify;
use super::config::ReviewConfig;
use super::frontend;
use super::model::{
    FileReference, FileSnapshot, FunctionSnapshot, GitAuthorStat, GitHotspot, GitSnapshot,
    RepositoryProfile, RepositorySnapshot, referenceable_fn_name,
};

/// Languages the scanner dispatches on. Rust is analyzed here (line based);
/// frontend languages are delegated to the `frontend` module (AST based).
enum Language {
    Rust,
    Script,
}

pub fn scan_repository(root: &Path, config: &ReviewConfig) -> Result<RepositorySnapshot, String> {
    if !root.exists() {
        return Err(format!("path does not exist: {}", root.display()));
    }

    let mut files = Vec::new();
    visit_path(root, root, config, &mut files)?;

    let functions = annotate_references(collect_functions(&files), &files);
    let stylesheets = frontend::scan_stylesheets(&files);
    let git = collect_git_snapshot(root, config);

    let file_count = files.len();
    let source_file_count = files.iter().filter(|f| f.is_source()).count();
    let test_file_count = files.iter().filter(|f| f.is_test()).count();
    let total_lines = files.iter().map(|f| f.lines).sum();
    let profile = RepositoryProfile::new(
        root.display().to_string(),
        file_count,
        source_file_count,
        test_file_count,
        total_lines,
    );

    Ok(RepositorySnapshot::new(
        profile,
        files,
        functions,
        stylesheets,
        git,
    ))
}

fn visit_path(
    root: &Path,
    current: &Path,
    config: &ReviewConfig,
    files: &mut Vec<FileSnapshot>,
) -> Result<(), String> {
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
            visit_path(root, &path, config, files)?;
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
            let category =
                classify::classify(&relative, &name, content.as_deref(), &config.classification);

            files.push(FileSnapshot {
                path: relative,
                name,
                lines,
                bytes,
                depth,
                category,
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

fn count_lines(text: &str) -> usize {
    text.lines().count().max(1)
}

/// Routes each first-party code file to the analyzer for its language. Rust
/// stays here; frontend languages (TS/TSX/JS/JSX) are delegated to `frontend`.
/// Generated, vendored and non-code files are skipped.
fn collect_functions(files: &[FileSnapshot]) -> Vec<FunctionSnapshot> {
    let mut functions = Vec::new();
    for file in files {
        if !file.is_first_party_code() {
            continue;
        }
        let Some(content) = &file.content else {
            continue;
        };
        match language_of(&file.name) {
            Some(Language::Rust) => functions.extend(scan_rust_functions(file, content)),
            Some(Language::Script) => functions.extend(frontend::scan_functions(file, content)),
            None => {}
        }
    }
    functions
}

fn language_of(name: &str) -> Option<Language> {
    match ext_of(name)? {
        "rs" => Some(Language::Rust),
        "ts" | "tsx" | "js" | "jsx" | "mjs" | "cjs" => Some(Language::Script),
        _ => None,
    }
}

/// Fills in each function's call sites: which first-party files reference its
/// name and how many times (the definition's own occurrence excluded).
/// Name-based and approximate (it ignores scopes and same-named methods), but a
/// useful "who uses this / how widely" signal.
fn annotate_references(
    mut functions: Vec<FunctionSnapshot>,
    files: &[FileSnapshot],
) -> Vec<FunctionSnapshot> {
    let wanted: HashSet<String> = functions
        .iter()
        .filter_map(|f| referenceable_fn_name(&f.name).map(str::to_string))
        .collect();
    if wanted.is_empty() {
        return functions;
    }
    let occurrences = reference_occurrences(files, &wanted);

    for function in &mut functions {
        let Some(name) = referenceable_fn_name(&function.name) else {
            continue;
        };
        let Some(per_file) = occurrences.get(name) else {
            continue;
        };
        let mut referenced_by: Vec<FileReference> = per_file
            .iter()
            .map(|(file, count)| {
                // The definition itself is one occurrence in its own file.
                let count = if file == &function.file {
                    count.saturating_sub(1)
                } else {
                    *count
                };
                FileReference {
                    file: file.clone(),
                    count,
                }
            })
            .filter(|reference| reference.count > 0)
            .collect();
        referenced_by.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.file.cmp(&b.file)));
        function.references = referenced_by.iter().map(|r| r.count).sum();
        function.referenced_by = referenced_by;
    }
    functions
}

/// Builds `name -> (file -> count)` for the wanted function names in one pass.
/// Only tracks names we care about, so memory stays bounded to the functions.
fn reference_occurrences(
    files: &[FileSnapshot],
    wanted: &HashSet<String>,
) -> HashMap<String, HashMap<String, usize>> {
    let mut occurrences: HashMap<String, HashMap<String, usize>> = HashMap::new();
    for file in files {
        if !file.is_first_party_code() {
            continue;
        }
        let Some(content) = &file.content else {
            continue;
        };
        let mut token = String::new();
        for ch in content.chars() {
            if ch == '_' || ch.is_alphanumeric() {
                token.push(ch);
            } else if !token.is_empty() {
                record_reference(&mut occurrences, wanted, &token, &file.path);
                token.clear();
            }
        }
        record_reference(&mut occurrences, wanted, &token, &file.path);
    }
    occurrences
}

fn record_reference(
    occurrences: &mut HashMap<String, HashMap<String, usize>>,
    wanted: &HashSet<String>,
    token: &str,
    file: &str,
) {
    if wanted.contains(token) {
        *occurrences
            .entry(token.to_string())
            .or_default()
            .entry(file.to_string())
            .or_insert(0) += 1;
    }
}

fn ext_of(name: &str) -> Option<&str> {
    if name.ends_with(".d.ts") {
        return Some("d.ts");
    }
    Path::new(name).extension().and_then(|ext| ext.to_str())
}

// --------------------------------------------------------------------------
// Rust function analysis (line based)
// --------------------------------------------------------------------------

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
                language: "rust",
                start_line: start,
                end_line: end,
                lines: line_count,
                param_count: count_rust_params(&lines, i),
                // Usage analysis needs a real AST; the Rust scanner is line
                // based, so it reports the parameter count only.
                params: Vec::new(),
                unused_params: Vec::new(),
                references: 0,
                referenced_by: Vec::new(),
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
                .split(|c: char| c == '(' || c == '<' || c.is_whitespace())
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

/// Counts the formal parameters of a Rust function from its signature.
///
/// Walks from the `fn` line until the parameter parentheses balance, counting
/// commas that sit at the top level of the parameter list (commas inside
/// generics, tuples or nested types do not separate parameters). A leading
/// `self` receiver is not counted as a parameter.
fn count_rust_params(lines: &[&str], start: usize) -> usize {
    let mut paren = 0i32;
    let mut nested = 0i32;
    let mut started = false;
    let mut params: Vec<String> = Vec::new();
    let mut current = String::new();
    let mut prev = ' ';

    'outer: for line in lines.iter().skip(start) {
        for ch in line.chars() {
            match ch {
                '(' => {
                    paren += 1;
                    if paren == 1 && !started {
                        started = true;
                        prev = ch;
                        continue;
                    }
                    current.push(ch);
                }
                ')' => {
                    paren -= 1;
                    if paren == 0 && started {
                        push_param(&mut params, &current);
                        break 'outer;
                    }
                    current.push(ch);
                }
                '[' | '{' | '<' => {
                    nested += 1;
                    if started {
                        current.push(ch);
                    }
                }
                ']' | '}' => {
                    nested -= 1;
                    if started {
                        current.push(ch);
                    }
                }
                '>' => {
                    // Avoid treating the `>` of a `->` return arrow as a
                    // closing generic bracket.
                    if prev != '-' && nested > 0 {
                        nested -= 1;
                    }
                    if started {
                        current.push(ch);
                    }
                }
                ',' if started && paren == 1 && nested == 0 => {
                    push_param(&mut params, &current);
                    current.clear();
                }
                _ => {
                    if started {
                        current.push(ch);
                    }
                }
            }
            prev = ch;
        }
        if started {
            current.push(' ');
            prev = ' ';
        }
    }

    let mut count = params.len();
    if params.first().is_some_and(|first| is_self_receiver(first)) {
        count -= 1;
    }
    count
}

fn push_param(params: &mut Vec<String>, current: &str) {
    let trimmed = current.trim();
    if !trimmed.is_empty() {
        params.push(trimmed.to_string());
    }
}

fn is_self_receiver(param: &str) -> bool {
    let mut s = param.trim();
    if let Some(rest) = s.strip_prefix('&') {
        s = rest.trim_start();
    }
    if let Some(rest) = s.strip_prefix('\'') {
        s = rest
            .trim_start_matches(|c: char| c.is_alphanumeric() || c == '_')
            .trim_start();
    }
    if let Some(rest) = s.strip_prefix("mut ") {
        s = rest.trim_start();
    }
    s == "self" || s.starts_with("self:")
}

// --------------------------------------------------------------------------
// Git history snapshot
// --------------------------------------------------------------------------

fn collect_git_snapshot(root: &Path, config: &ReviewConfig) -> Option<GitSnapshot> {
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

    let mut hotspot_stats = parse_hotspots(hotspots);
    // Hotspots should point at code we maintain, not lock files or docs.
    hotspot_stats.retain(|hotspot| is_trackable_hotspot(&hotspot.path, config));
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

/// A hotspot is only useful if it points at first-party code; lock files,
/// build output and docs change for reasons unrelated to code quality.
fn is_trackable_hotspot(path: &str, config: &ReviewConfig) -> bool {
    let name = path.rsplit(['/', '\\']).next().unwrap_or(path);
    classify::classify(path, name, None, &config.classification).is_first_party_code()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rust_file(content: &str) -> FileSnapshot {
        FileSnapshot {
            path: "x.rs".to_string(),
            name: "x.rs".to_string(),
            lines: content.lines().count().max(1),
            bytes: content.len() as u64,
            depth: 1,
            category: classify::FileCategory::Source,
            content: Some(content.to_string()),
        }
    }

    #[test]
    fn counts_basic_rust_params() {
        let src = "fn add(a: i32, b: i32) -> i32 { a + b }\n";
        let functions = scan_rust_functions(&rust_file(src), src);
        assert_eq!(functions.len(), 1);
        assert_eq!(functions[0].name, "add");
        assert_eq!(functions[0].language, "rust");
        assert_eq!(functions[0].param_count, 2);
    }

    #[test]
    fn ignores_self_receiver() {
        let src = "fn method(&mut self, value: u8) {}\n";
        let functions = scan_rust_functions(&rust_file(src), src);
        assert_eq!(functions[0].param_count, 1);
    }

    #[test]
    fn ignores_commas_inside_generics() {
        let src = "fn build(map: HashMap<String, u8>, n: usize) -> bool { true }\n";
        let functions = scan_rust_functions(&rust_file(src), src);
        assert_eq!(functions[0].param_count, 2);
    }

    #[test]
    fn handles_no_params() {
        let src = "fn now() -> u64 { 0 }\n";
        let functions = scan_rust_functions(&rust_file(src), src);
        assert_eq!(functions[0].param_count, 0);
    }

    #[test]
    fn handles_closure_param_with_return_arrow() {
        let src = "fn run(cb: impl Fn(u8) -> bool, n: u8) {}\n";
        let functions = scan_rust_functions(&rust_file(src), src);
        assert_eq!(functions[0].param_count, 2);
    }

    #[test]
    fn counts_call_sites_as_references() {
        let definition = rust_file("pub fn helper(x: u8) -> u8 {\n    x\n}\n");
        let mut caller =
            rust_file("fn run() {\n    let _ = helper(1);\n    let _ = helper(2);\n}\n");
        caller.path = "caller.rs".to_string();
        caller.name = "caller.rs".to_string();

        let functions = scan_rust_functions(&definition, definition.content.as_deref().unwrap());
        let annotated = annotate_references(functions, &[definition.clone(), caller]);

        let helper = annotated.iter().find(|f| f.name == "helper").unwrap();
        // Two call sites in caller.rs; the definition occurrence is excluded,
        // so the definition file (x.rs) does not appear at all.
        assert_eq!(helper.references, 2);
        assert_eq!(helper.referenced_by.len(), 1);
        assert_eq!(helper.referenced_by[0].file, "caller.rs");
        assert_eq!(helper.referenced_by[0].count, 2);
    }
}
