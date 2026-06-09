use super::classify::FileCategory;
use super::config::ReviewConfig;

#[derive(Debug, Clone, serde::Serialize)]
pub struct FileSnapshot {
    pub path: String,
    pub name: String,
    pub lines: usize,
    pub bytes: u64,
    pub depth: usize,
    pub category: FileCategory,
    pub content: Option<String>,
}

impl FileSnapshot {
    pub fn is_test(&self) -> bool {
        self.category.is_test()
    }

    pub fn is_source(&self) -> bool {
        self.category.is_source()
    }

    /// First-party code (source or test) — what we wrote.
    pub fn is_first_party_code(&self) -> bool {
        self.category.is_first_party_code()
    }

    /// The top-level path segment, used to group files into areas/packages.
    pub fn area(&self) -> &str {
        area_of(&self.path)
    }
}

/// The top-level path segment of a repo-relative path (its "area"/package).
/// Files at the repo root are grouped under `(root)`.
pub fn area_of(path: &str) -> &str {
    match path.split(['/', '\\']).next() {
        Some(segment) if path.contains('/') || path.contains('\\') => segment,
        _ => "(root)",
    }
}

/// If `name` is a concrete, lookup-able function name, returns the bare name to
/// search for references (the last `::` segment). Anonymous or synthetic labels
/// (`arrow_function`, call-context labels like `describe("x")`, etc.) return
/// `None`, since a name-based reference count would be meaningless for them.
pub fn referenceable_fn_name(name: &str) -> Option<&str> {
    if name.contains('(') {
        return None;
    }
    let segment = name.rsplit("::").next().unwrap_or(name);
    let anonymous = matches!(
        segment,
        "arrow_function"
            | "function"
            | "method"
            | "property"
            | "constructor"
            | "default_function"
            | "default_class"
            | "class"
            | "private_method"
            | "private_property"
    ) || segment.starts_with("function_");
    if anonymous {
        return None;
    }
    let mut chars = segment.chars();
    let valid = chars.next().is_some_and(|c| c.is_alphabetic() || c == '_')
        && segment.chars().all(|c| c.is_alphanumeric() || c == '_');
    valid.then_some(segment)
}

/// Whether a function looks like possible dead code: a real named function in
/// first-party source with no first-party references, excluding the program
/// entry point. `is_source` is supplied by the caller (we exclude tests, since
/// test functions are invoked by the harness, not called by name).
///
/// This is a heuristic, not proof — a 0-reference function may still be public
/// API consumed elsewhere, or invoked by a framework. Callers should present it
/// as "possible", not certain.
pub fn is_dead_code_candidate(func: &FunctionSnapshot, is_source: bool) -> bool {
    is_source
        && func.references == 0
        && matches!(referenceable_fn_name(&func.name), Some(name) if name != "main")
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct FunctionSnapshot {
    pub file: String,
    pub name: String,
    pub language: &'static str,
    pub start_line: usize,
    pub end_line: usize,
    pub lines: usize,
    pub param_count: usize,
    pub params: Vec<ParamUsage>,
    pub unused_params: Vec<String>,
    /// Approximate number of call sites: how many times the function's name is
    /// referenced across first-party code, minus its own definition. `0` for
    /// anonymous functions (where a name-based count is meaningless).
    pub references: usize,
    /// The files that reference this function, with per-file counts (the
    /// definition's own occurrence excluded). Sorted by count descending.
    pub referenced_by: Vec<FileReference>,
}

/// A single file that references a function, and how many times.
#[derive(Debug, Clone, serde::Serialize)]
pub struct FileReference {
    pub file: String,
    pub count: usize,
}

/// Usage of a single function parameter binding.
///
/// `references` counts how many times the binding name is read inside the
/// function body (an approximate, name-based count). `used` is simply
/// `references > 0`. Only languages with AST-level analysis populate this.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ParamUsage {
    pub name: String,
    pub references: usize,
    pub used: bool,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct StylesheetSnapshot {
    pub file: String,
    pub name: String,
    pub lines: usize,
    pub bytes: u64,
    pub rule_count: usize,
    pub selector_count: usize,
    pub declaration_count: usize,
    pub variable_count: usize,
    pub import_count: usize,
    pub max_nesting_depth: usize,
    pub largest_rule_lines: usize,
    pub duplicate_selector_count: usize,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct RepositoryProfile {
    pub path: String,
    pub file_count: usize,
    pub source_file_count: usize,
    pub test_file_count: usize,
    pub total_lines: usize,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct GitAuthorStat {
    pub name: String,
    pub commits: u32,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct GitHotspot {
    pub path: String,
    pub commits: u32,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct GitSnapshot {
    pub total_commits: u32,
    pub contributor_count: usize,
    pub commit_concentration: f64,
    pub recent_active_authors: Vec<GitAuthorStat>,
    pub author_commit_counts: Vec<GitAuthorStat>,
    pub hotspots: Vec<GitHotspot>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct RepositorySnapshot {
    pub profile: RepositoryProfile,
    pub files: Vec<FileSnapshot>,
    pub functions: Vec<FunctionSnapshot>,
    pub stylesheets: Vec<StylesheetSnapshot>,
    pub git: Option<GitSnapshot>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum Severity {
    Info,
    Warning,
    Error,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct Finding {
    pub severity: Severity,
    pub file: Option<String>,
    pub metric: &'static str,
    pub message: String,
    pub suggestion: String,
    /// Points this finding deducted from its metric. Used as a magnitude signal
    /// when ranking findings by impact. `0` for purely informational notes.
    pub score_penalty: u32,
}

/// A finding promoted to the prioritized "top issues" list, carrying the
/// computed impact used to rank it. See `review::build_priorities`.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Priority {
    pub id: String,
    pub impact: u32,
    pub severity: Severity,
    pub metric: &'static str,
    pub file: Option<String>,
    pub message: String,
    pub suggestion: String,
}

/// Health rollup for one top-level area (package / directory) of the repo.
#[derive(Debug, Clone, serde::Serialize)]
pub struct AreaHealth {
    pub area: String,
    pub file_count: usize,
    pub source_file_count: usize,
    pub errors: usize,
    pub warnings: usize,
    pub infos: usize,
    pub worst_metric: Option<&'static str>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct MetricResult {
    pub name: &'static str,
    pub weight: u8,
    pub score: u8,
    pub findings: Vec<Finding>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ReviewReport {
    pub profile: RepositoryProfile,
    pub config: ReviewConfig,
    pub metrics: Vec<MetricResult>,
    pub findings: Vec<Finding>,
    pub priorities: Vec<Priority>,
    pub areas: Vec<AreaHealth>,
    pub overall: u8,
    pub grade: String,
    pub verdict: &'static str,
    pub passed: bool,
    pub worst_metric: Option<&'static str>,
    pub file_rankings: Vec<FileRanking>,
    pub function_summary: FunctionSummary,
    pub function_rankings: Vec<FunctionRanking>,
    pub param_hygiene: Vec<FunctionRanking>,
    pub dead_code: Vec<FunctionRanking>,
    pub stylesheet_rankings: Vec<StylesheetRanking>,
    pub git: Option<GitSnapshot>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct FileRanking {
    pub path: String,
    pub name: String,
    pub lines: usize,
    pub bytes: u64,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct FunctionRanking {
    pub file: String,
    pub name: String,
    pub language: &'static str,
    pub start_line: usize,
    pub end_line: usize,
    pub lines: usize,
    pub param_count: usize,
    pub unused_params: Vec<String>,
    pub references: usize,
    pub referenced_by: Vec<FileReference>,
    /// Quality flags derived in the analysis layer from the configured
    /// thresholds (e.g. "long", "many-params", "unused-param"). The renderer
    /// only displays these; it does not recompute the judgment.
    pub flags: Vec<&'static str>,
}

/// Aggregate, judgment-free statistics over every analyzed function. This is the
/// "summary" layer of function observability: it answers "what is the overall
/// state of the functions" at a glance, while the rankings provide the evidence.
#[derive(Debug, Clone, serde::Serialize)]
pub struct FunctionSummary {
    pub function_count: usize,
    pub average_function_lines: f64,
    pub max_function_lines: usize,
    pub long_function_count: usize,
    pub total_param_count: usize,
    pub average_param_count: f64,
    pub zero_param_function_count: usize,
    pub four_plus_param_function_count: usize,
    pub over_param_limit_count: usize,
    pub unused_param_count: usize,
    pub functions_with_unused_params: usize,
    pub unreferenced_function_count: usize,
    pub language_breakdown: Vec<LanguageCount>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct LanguageCount {
    pub language: &'static str,
    pub count: usize,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct StylesheetRanking {
    pub file: String,
    pub name: String,
    pub lines: usize,
    pub bytes: u64,
    pub rule_count: usize,
    pub selector_count: usize,
    pub declaration_count: usize,
    pub variable_count: usize,
    pub import_count: usize,
    pub max_nesting_depth: usize,
    pub largest_rule_lines: usize,
    pub duplicate_selector_count: usize,
}

impl RepositoryProfile {
    pub fn new(
        path: impl Into<String>,
        file_count: usize,
        source_file_count: usize,
        test_file_count: usize,
        total_lines: usize,
    ) -> Self {
        Self {
            path: path.into(),
            file_count,
            source_file_count,
            test_file_count,
            total_lines,
        }
    }

    pub fn path(&self) -> &str {
        &self.path
    }

    pub fn file_count(&self) -> usize {
        self.file_count
    }

    pub fn source_file_count(&self) -> usize {
        self.source_file_count
    }

    pub fn test_file_count(&self) -> usize {
        self.test_file_count
    }

    pub fn total_lines(&self) -> usize {
        self.total_lines
    }
}

impl RepositorySnapshot {
    pub fn new(
        profile: RepositoryProfile,
        files: Vec<FileSnapshot>,
        functions: Vec<FunctionSnapshot>,
        stylesheets: Vec<StylesheetSnapshot>,
        git: Option<GitSnapshot>,
    ) -> Self {
        Self {
            profile,
            files,
            functions,
            stylesheets,
            git,
        }
    }

    pub fn profile(&self) -> &RepositoryProfile {
        &self.profile
    }
}
