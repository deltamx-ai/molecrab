use super::config::ReviewConfig;

#[derive(Debug, Clone)]
pub struct FileSnapshot {
    pub path: String,
    pub name: String,
    pub lines: usize,
    pub bytes: u64,
    pub depth: usize,
    pub is_test: bool,
    pub content: Option<String>,
}

#[derive(Debug, Clone)]
pub struct FunctionSnapshot {
    pub file: String,
    pub name: String,
    pub start_line: usize,
    pub end_line: usize,
    pub lines: usize,
}

#[derive(Debug, Clone)]
pub struct RepositoryProfile {
    path: String,
    file_count: usize,
    source_file_count: usize,
    test_file_count: usize,
    total_lines: usize,
}

#[derive(Debug, Clone)]
pub struct GitAuthorStat {
    pub name: String,
    pub commits: u32,
}

#[derive(Debug, Clone)]
pub struct GitHotspot {
    pub path: String,
    pub commits: u32,
}

#[derive(Debug, Clone)]
pub struct GitSnapshot {
    pub total_commits: u32,
    pub contributor_count: usize,
    pub commit_concentration: f64,
    pub recent_active_authors: Vec<GitAuthorStat>,
    pub author_commit_counts: Vec<GitAuthorStat>,
    pub hotspots: Vec<GitHotspot>,
}

#[derive(Debug, Clone)]
pub struct RepositorySnapshot {
    pub profile: RepositoryProfile,
    pub files: Vec<FileSnapshot>,
    pub functions: Vec<FunctionSnapshot>,
    pub git: Option<GitSnapshot>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Info,
    Warning,
    Error,
}

#[derive(Debug, Clone)]
pub struct Finding {
    pub severity: Severity,
    pub file: Option<String>,
    pub metric: &'static str,
    pub message: String,
    pub suggestion: String,
}

#[derive(Debug, Clone)]
pub struct MetricResult {
    pub name: &'static str,
    pub weight: u8,
    pub score: u8,
    pub findings: Vec<Finding>,
}

#[derive(Debug, Clone)]
pub struct ReviewReport {
    pub profile: RepositoryProfile,
    pub config: ReviewConfig,
    pub metrics: Vec<MetricResult>,
    pub findings: Vec<Finding>,
    pub overall: u8,
    pub grade: String,
    pub file_rankings: Vec<FileRanking>,
    pub function_rankings: Vec<FunctionRanking>,
    pub git: Option<GitSnapshot>,
}

#[derive(Debug, Clone)]
pub struct FileRanking {
    pub path: String,
    pub name: String,
    pub lines: usize,
    pub bytes: u64,
}

#[derive(Debug, Clone)]
pub struct FunctionRanking {
    pub file: String,
    pub name: String,
    pub start_line: usize,
    pub end_line: usize,
    pub lines: usize,
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
        git: Option<GitSnapshot>,
    ) -> Self {
        Self {
            profile,
            files,
            functions,
            git,
        }
    }

    pub fn profile(&self) -> &RepositoryProfile {
        &self.profile
    }
}
