//! File classification.
//!
//! A review tool is only as good as the files it looks at. Lock files, build
//! output and vendored code are not "the code under review" — counting their
//! lines, grepping them for patterns, or ranking them as the largest files all
//! produce noise. This module assigns every file a single category so the rest
//! of the pipeline can scope its work to what actually matters.
//!
//! Classification is built-in by default (the common lock/build/doc patterns
//! are well known) and can be extended via `[classification]` in molecrab.toml.

use super::config::ClassificationConfig;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FileCategory {
    /// First-party source code that the metrics should judge.
    Source,
    /// First-party test code (judged differently from source).
    Test,
    /// Machine-generated files (lock files, build output, minified bundles).
    Generated,
    /// Third-party / vendored code.
    Vendor,
    /// Documentation (markdown, plain text, ...).
    Docs,
    /// Configuration / data files.
    Config,
    /// Anything else (images, binaries, unknown extensions).
    Other,
}

impl FileCategory {
    pub fn label(self) -> &'static str {
        match self {
            FileCategory::Source => "source",
            FileCategory::Test => "test",
            FileCategory::Generated => "generated",
            FileCategory::Vendor => "vendor",
            FileCategory::Docs => "docs",
            FileCategory::Config => "config",
            FileCategory::Other => "other",
        }
    }

    /// First-party source — the primary surface the quality metrics judge.
    pub fn is_source(self) -> bool {
        matches!(self, FileCategory::Source)
    }

    pub fn is_test(self) -> bool {
        matches!(self, FileCategory::Test)
    }

    /// First-party code (source or test) — what we wrote, worth analyzing.
    pub fn is_first_party_code(self) -> bool {
        matches!(self, FileCategory::Source | FileCategory::Test)
    }

    /// Files that must never feed scoring, rankings or hotspots.
    pub fn is_noise(self) -> bool {
        matches!(
            self,
            FileCategory::Generated | FileCategory::Vendor | FileCategory::Other
        )
    }
}

const VENDOR_SEGMENTS: &[&str] = &["node_modules", "vendor", "third_party", ".venv", "venv"];

const GENERATED_SEGMENTS: &[&str] = &[
    "dist",
    "build",
    "out",
    "target",
    "coverage",
    ".next",
    ".nuxt",
    ".svelte-kit",
    "__snapshots__",
    "__pycache__",
];

const GENERATED_NAMES: &[&str] = &[
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "cargo.lock",
    "composer.lock",
    "poetry.lock",
    "gemfile.lock",
    "go.sum",
    "bun.lockb",
];

const GENERATED_SUFFIXES: &[&str] = &[".min.js", ".min.css", ".map", ".lock", ".generated.ts"];

const DOC_EXTS: &[&str] = &["md", "mdx", "rst", "adoc", "txt"];

const CONFIG_EXTS: &[&str] = &[
    "json", "toml", "yaml", "yml", "ini", "cfg", "conf", "env", "lock",
];

const CODE_EXTS: &[&str] = &[
    "rs", "ts", "tsx", "js", "jsx", "mjs", "cjs", "py", "go", "java", "rb", "c", "h", "cc", "cpp",
    "hpp", "cs", "swift", "kt", "scala", "php", "css", "scss", "sass", "less", "vue", "svelte",
];

/// Assigns a category to a file from its repo-relative path, file name and
/// (optional) content. `path` uses `/` separators.
pub fn classify(
    path: &str,
    name: &str,
    content: Option<&str>,
    cfg: &ClassificationConfig,
) -> FileCategory {
    let path_lower = path.to_lowercase();
    let name_lower = name.to_lowercase();

    if has_segment(&path_lower, VENDOR_SEGMENTS)
        || cfg
            .extra_ignored_dirs
            .iter()
            .any(|d| has_segment(&path_lower, &[d.as_str()]))
    {
        return FileCategory::Vendor;
    }

    if is_generated(&path_lower, &name_lower)
        || cfg
            .extra_generated
            .iter()
            .any(|p| path_lower.contains(&p.to_lowercase()))
    {
        return FileCategory::Generated;
    }

    let ext = extension(&name_lower);

    if matches!(ext, Some(e) if DOC_EXTS.contains(&e)) || is_doc_name(&name_lower) {
        return FileCategory::Docs;
    }

    let is_code = matches!(ext, Some(e) if CODE_EXTS.contains(&e));

    // Config files (json/toml/...) that are not code. Checked before treating a
    // bare extension as config so that, e.g., a `.ts` config still reads as code.
    if !is_code && (matches!(ext, Some(e) if CONFIG_EXTS.contains(&e)) || is_dotfile(&name_lower)) {
        return FileCategory::Config;
    }

    if is_code {
        if looks_like_test(&path_lower, &name_lower, content) {
            return FileCategory::Test;
        }
        return FileCategory::Source;
    }

    FileCategory::Other
}

fn is_generated(path_lower: &str, name_lower: &str) -> bool {
    GENERATED_NAMES.contains(&name_lower)
        || GENERATED_SUFFIXES.iter().any(|s| name_lower.ends_with(s))
        || has_segment(path_lower, GENERATED_SEGMENTS)
}

fn looks_like_test(path_lower: &str, name_lower: &str, content: Option<&str>) -> bool {
    const TEST_SEGMENTS: &[&str] = &["tests", "test", "__tests__", "spec", "__mocks__"];
    if has_segment(path_lower, TEST_SEGMENTS) {
        return true;
    }
    if name_lower.contains(".test.")
        || name_lower.contains(".spec.")
        || name_lower.contains("_test.")
        || name_lower.starts_with("test_")
    {
        return true;
    }
    content.is_some_and(|c| c.contains("#[test]") || c.contains("#[cfg(test)]"))
}

fn is_doc_name(name_lower: &str) -> bool {
    let stem = name_lower.split('.').next().unwrap_or(name_lower);
    matches!(
        stem,
        "readme" | "changelog" | "license" | "licence" | "contributing" | "authors"
    )
}

fn is_dotfile(name_lower: &str) -> bool {
    // Leading-dot config such as .gitignore, .editorconfig, .eslintrc.
    name_lower.starts_with('.')
}

fn extension(name_lower: &str) -> Option<&str> {
    if name_lower.ends_with(".d.ts") {
        return Some("ts");
    }
    name_lower.rsplit_once('.').map(|(_, ext)| ext)
}

fn has_segment(path_lower: &str, segments: &[&str]) -> bool {
    path_lower
        .split(['/', '\\'])
        .any(|part| segments.contains(&part))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn classify_default(path: &str) -> FileCategory {
        let name = path.rsplit('/').next().unwrap_or(path);
        classify(path, name, None, &ClassificationConfig::default())
    }

    #[test]
    fn lock_and_build_files_are_generated() {
        assert_eq!(
            classify_default("tt/package-lock.json"),
            FileCategory::Generated
        );
        assert_eq!(classify_default("rust/Cargo.lock"), FileCategory::Generated);
        assert_eq!(classify_default("dist/app.js"), FileCategory::Generated);
        assert_eq!(
            classify_default("src/bundle.min.js"),
            FileCategory::Generated
        );
    }

    #[test]
    fn markdown_and_config_are_not_source() {
        assert_eq!(classify_default("design.md"), FileCategory::Docs);
        assert_eq!(classify_default("tsconfig.json"), FileCategory::Config);
        assert_eq!(classify_default("package.json"), FileCategory::Config);
        assert_eq!(classify_default(".gitignore"), FileCategory::Config);
    }

    #[test]
    fn code_and_tests_split() {
        assert_eq!(classify_default("rust/src/main.rs"), FileCategory::Source);
        assert_eq!(classify_default("src/app.tsx"), FileCategory::Source);
        assert_eq!(
            classify_default("src/stages/history-analyzer.test.ts"),
            FileCategory::Test
        );
        assert_eq!(
            classify_default("tt/src/__tests__/pipeline.test.ts"),
            FileCategory::Test
        );
    }

    #[test]
    fn rust_test_module_detected_by_content() {
        let cat = classify(
            "src/lib.rs",
            "lib.rs",
            Some("#[cfg(test)]\nmod tests {}"),
            &ClassificationConfig::default(),
        );
        assert_eq!(cat, FileCategory::Test);
    }

    #[test]
    fn vendored_code_is_vendor() {
        assert_eq!(
            classify_default("node_modules/react/index.js"),
            FileCategory::Vendor
        );
    }
}
