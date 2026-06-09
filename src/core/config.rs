use serde::Deserialize;
use std::fs;
use std::path::{Path, PathBuf};

/// Review configuration defaults.
///
/// Built-in defaults keep the review command usable even when no repository-local
/// configuration file is present.
///
/// Example `molecrab.toml`:
///
/// ```toml
/// [thresholds]
/// overall_score = 80
/// observability_weight = 3
/// max_file_lines = 400
/// max_long_lines = 160
/// max_path_depth = 6
/// max_function_lines = 60
/// max_function_params = 5
/// max_unwrap_count = 2
/// max_expect_count = 2
/// max_panic_count = 0
/// max_clone_count = 4
/// max_source_file_count = 80
/// min_test_indicators = 2
/// min_file_lines_for_rank = 60
/// min_function_lines_for_rank = 20
/// top_file_rankings = 5
/// top_function_rankings = 5
/// top_stylesheet_rankings = 5
/// top_priorities = 8
/// top_hotspots = 10
/// failing_metric_score = 60
///
/// [observability]
/// file_names = true
/// file_paths = true
/// file_line_counts = true
/// file_sizes = true
/// longest_file_ranking = true
/// longest_function_ranking = true
/// function_param_analysis = true
/// longest_stylesheet_ranking = true
/// contributor_count = true
/// per_author_commit_counts = true
/// total_commit_count = true
/// commit_concentration = true
/// most_recent_active_authors = true
/// code_change_hotspots = true
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, serde::Serialize, Default)]
#[serde(default)]
pub struct ReviewConfig {
    pub thresholds: ReviewThresholds,
    pub observability: ObservabilityTargets,
    pub classification: ClassificationConfig,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, serde::Serialize)]
#[serde(default)]
pub struct ReviewThresholds {
    pub overall_score: u8,
    pub observability_weight: u8,
    pub max_file_lines: u32,
    pub max_long_lines: u32,
    pub max_path_depth: u32,
    pub max_function_lines: u32,
    pub max_function_params: u32,
    pub max_unwrap_count: u32,
    pub max_expect_count: u32,
    pub max_panic_count: u32,
    pub max_clone_count: u32,
    pub max_source_file_count: u32,
    pub min_test_indicators: u32,
    pub min_file_lines_for_rank: u32,
    pub min_function_lines_for_rank: u32,
    pub top_file_rankings: u32,
    pub top_function_rankings: u32,
    pub top_stylesheet_rankings: u32,
    pub top_priorities: u32,
    pub top_hotspots: u32,
    pub failing_metric_score: u8,
}

/// Rules that decide how files are categorized (source / test / generated /
/// vendor / docs / config). Built-in defaults cover the common cases; these
/// lists only *add* to them. Paths are matched case-insensitively.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, serde::Serialize, Default)]
#[serde(default)]
pub struct ClassificationConfig {
    /// Extra path substrings that mark a file as generated (e.g. "codegen/").
    pub extra_generated: Vec<String>,
    /// Extra directory names treated as vendored / ignored.
    pub extra_ignored_dirs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, serde::Serialize)]
#[serde(default)]
pub struct ObservabilityTargets {
    pub file_names: bool,
    pub file_paths: bool,
    pub file_line_counts: bool,
    pub file_sizes: bool,
    pub longest_file_ranking: bool,
    pub longest_function_ranking: bool,
    pub function_param_analysis: bool,
    pub longest_stylesheet_ranking: bool,
    pub contributor_count: bool,
    pub per_author_commit_counts: bool,
    pub total_commit_count: bool,
    pub commit_concentration: bool,
    pub most_recent_active_authors: bool,
    pub code_change_hotspots: bool,
}

pub const REPOSITORY_LOCAL_CONFIG_CANDIDATES: &[&str] = &["molecrab.toml", ".molecrab.toml"];

impl Default for ReviewThresholds {
    fn default() -> Self {
        Self {
            overall_score: 80,
            observability_weight: 3,
            max_file_lines: 400,
            max_long_lines: 160,
            max_path_depth: 6,
            max_function_lines: 60,
            max_function_params: 5,
            max_unwrap_count: 2,
            max_expect_count: 2,
            max_panic_count: 0,
            max_clone_count: 4,
            max_source_file_count: 80,
            min_test_indicators: 2,
            min_file_lines_for_rank: 60,
            min_function_lines_for_rank: 20,
            top_file_rankings: 5,
            top_function_rankings: 5,
            top_stylesheet_rankings: 5,
            top_priorities: 8,
            top_hotspots: 10,
            failing_metric_score: 60,
        }
    }
}

impl Default for ObservabilityTargets {
    fn default() -> Self {
        Self {
            file_names: true,
            file_paths: true,
            file_line_counts: true,
            file_sizes: true,
            longest_file_ranking: true,
            longest_function_ranking: true,
            function_param_analysis: true,
            longest_stylesheet_ranking: true,
            contributor_count: true,
            per_author_commit_counts: true,
            total_commit_count: true,
            commit_concentration: true,
            most_recent_active_authors: true,
            code_change_hotspots: true,
        }
    }
}

impl ReviewConfig {
    pub fn load_for_repository(
        repository_root: &Path,
        explicit_config_path: Option<&Path>,
    ) -> Result<Self, String> {
        if let Some(config_path) = explicit_config_path {
            return Self::load_from_file_or_default(config_path);
        }

        for candidate in repository_local_candidates(repository_root) {
            if candidate.exists() {
                return Self::load_from_file(&candidate);
            }
        }

        Ok(Self::default())
    }

    pub fn load_from_file_or_default(path: &Path) -> Result<Self, String> {
        if path.exists() {
            Self::load_from_file(path)
        } else {
            Ok(Self::default())
        }
    }

    pub fn load_from_file(path: &Path) -> Result<Self, String> {
        let raw = fs::read_to_string(path)
            .map_err(|err| format!("failed to read config {}: {}", path.display(), err))?;

        toml::from_str::<ReviewConfig>(&raw)
            .map_err(|err| format!("failed to parse review config {}: {}", path.display(), err))
    }

    pub fn enabled_observability_targets(&self) -> Vec<&'static str> {
        let mut targets = Vec::new();

        if self.observability.file_names {
            targets.push("file_names");
        }
        if self.observability.file_paths {
            targets.push("file_paths");
        }
        if self.observability.file_line_counts {
            targets.push("file_line_counts");
        }
        if self.observability.file_sizes {
            targets.push("file_sizes");
        }
        if self.observability.longest_file_ranking {
            targets.push("longest_file_ranking");
        }
        if self.observability.longest_function_ranking {
            targets.push("longest_function_ranking");
        }
        if self.observability.function_param_analysis {
            targets.push("function_param_analysis");
        }
        if self.observability.longest_stylesheet_ranking {
            targets.push("longest_stylesheet_ranking");
        }
        if self.observability.contributor_count {
            targets.push("contributor_count");
        }
        if self.observability.per_author_commit_counts {
            targets.push("per_author_commit_counts");
        }
        if self.observability.total_commit_count {
            targets.push("total_commit_count");
        }
        if self.observability.commit_concentration {
            targets.push("commit_concentration");
        }
        if self.observability.most_recent_active_authors {
            targets.push("most_recent_active_authors");
        }
        if self.observability.code_change_hotspots {
            targets.push("code_change_hotspots");
        }

        targets
    }
}

fn repository_local_candidates(repository_root: &Path) -> Vec<PathBuf> {
    REPOSITORY_LOCAL_CONFIG_CANDIDATES
        .iter()
        .map(|candidate| repository_root.join(candidate))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn defaults_are_sensible() {
        let config = ReviewConfig::default();

        assert_eq!(config.thresholds.overall_score, 80);
        assert_eq!(config.thresholds.observability_weight, 3);
        assert!(config.observability.file_names);
        assert!(config.observability.code_change_hotspots);
    }

    #[test]
    fn loads_from_repository_local_file() {
        let repo = temp_dir("molecrab-config-repo");
        fs::create_dir_all(&repo).unwrap();
        let config_path = repo.join("molecrab.toml");
        fs::write(
            &config_path,
            r#"
[thresholds]
overall_score = 91
observability_weight = 7
max_file_lines = 250
max_long_lines = 120
max_path_depth = 4
max_unwrap_count = 1
max_expect_count = 1
max_panic_count = 0
max_clone_count = 2
max_source_file_count = 10
min_test_indicators = 3
min_file_lines_for_rank = 80
top_file_rankings = 10
top_function_rankings = 7

[observability]
file_names = true
file_paths = false
file_line_counts = true
file_sizes = false
longest_file_ranking = true
longest_function_ranking = false
contributor_count = true
per_author_commit_counts = false
total_commit_count = true
commit_concentration = false
most_recent_active_authors = true
code_change_hotspots = false
"#,
        )
        .unwrap();

        let loaded = ReviewConfig::load_for_repository(&repo, None).unwrap();
        assert_eq!(loaded.thresholds.overall_score, 91);
        assert_eq!(loaded.thresholds.observability_weight, 7);
        assert_eq!(loaded.thresholds.max_file_lines, 250);
        assert!(loaded.observability.file_names);
        assert!(!loaded.observability.file_paths);
        assert!(loaded.observability.longest_file_ranking);
        assert!(!loaded.observability.longest_function_ranking);
    }

    #[test]
    fn falls_back_to_defaults_when_config_is_missing() {
        let repo = temp_dir("molecrab-missing-config-repo");
        fs::create_dir_all(&repo).unwrap();

        let loaded = ReviewConfig::load_for_repository(&repo, None).unwrap();
        assert_eq!(loaded, ReviewConfig::default());
    }

    #[test]
    fn explicit_missing_config_uses_defaults() {
        let repo = temp_dir("molecrab-explicit-missing-config-repo");
        fs::create_dir_all(&repo).unwrap();
        let missing = repo.join("does-not-exist.toml");

        let loaded = ReviewConfig::load_for_repository(&repo, Some(&missing)).unwrap();
        assert_eq!(loaded, ReviewConfig::default());
    }

    fn temp_dir(prefix: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("{}-{}", prefix, unique))
    }
}
