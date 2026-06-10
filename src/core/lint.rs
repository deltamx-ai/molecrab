//! Ingest external linter reports as findings.
//!
//! molecrab does not re-implement lint rules; it folds an existing linter's
//! output into the same `Finding` pipeline (Issues / Fix first / JSON). v1
//! supports ESLint's JSON formatter (`eslint -f json`), which also covers
//! TypeScript via typescript-eslint. Ingested findings are surfaced but do not
//! change molecrab's own metric scores.

use std::path::Path;

use serde::Deserialize;

use super::model::{Finding, Severity};

#[derive(Deserialize)]
struct EslintFile {
    #[serde(rename = "filePath")]
    file_path: String,
    #[serde(default)]
    messages: Vec<EslintMessage>,
}

#[derive(Deserialize)]
struct EslintMessage {
    #[serde(rename = "ruleId")]
    rule_id: Option<String>,
    severity: u8,
    message: String,
    #[serde(default)]
    line: u32,
}

/// Parses an ESLint JSON report (`eslint -f json`) into findings, with file
/// paths made relative to `root` so they line up with molecrab's own paths.
pub fn parse_eslint(json: &str, root: &Path) -> Result<Vec<Finding>, String> {
    let files: Vec<EslintFile> =
        serde_json::from_str(json).map_err(|err| format!("failed to parse ESLint JSON: {err}"))?;

    let mut findings = Vec::new();
    for file in files {
        let relative = relativize(&file.file_path, root);
        for message in file.messages {
            let severity = match message.severity {
                2 => Severity::Error,
                _ => Severity::Warning,
            };
            let rule = message.rule_id.unwrap_or_else(|| "eslint".to_string());
            let text = if message.line > 0 {
                format!("{}: {} (L{})", rule, message.message, message.line)
            } else {
                format!("{}: {}", rule, message.message)
            };
            // Penalty is only an impact-ranking magnitude here; lint is not scored.
            let score_penalty = if matches!(severity, Severity::Error) {
                4
            } else {
                2
            };
            findings.push(Finding {
                severity,
                file: Some(relative.clone()),
                metric: "lint",
                category: "Lint",
                rule: None,
                line: (message.line > 0).then_some(message.line as usize),
                message: text,
                suggestion: format!("eslint rule: {rule}"),
                score_penalty,
            });
        }
    }
    Ok(findings)
}

/// ESLint emits absolute paths; strip the repo root so they match snapshot paths.
fn relativize(path: &str, root: &Path) -> String {
    let root = root.to_string_lossy();
    match path.strip_prefix(root.as_ref()) {
        Some(rest) => rest.trim_start_matches(['/', '\\']).to_string(),
        None => path.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn parses_eslint_report_into_findings() {
        let json = r#"[
            {"filePath": "/repo/src/a.ts", "messages": [
                {"ruleId": "no-unused-vars", "severity": 1, "message": "'x' is unused", "line": 3},
                {"ruleId": "no-undef", "severity": 2, "message": "'y' is not defined", "line": 7}
            ]},
            {"filePath": "/repo/src/b.ts", "messages": []}
        ]"#;
        let findings = parse_eslint(json, Path::new("/repo")).unwrap();
        assert_eq!(findings.len(), 2);

        let undef = findings
            .iter()
            .find(|f| f.message.contains("no-undef"))
            .unwrap();
        assert_eq!(undef.severity, Severity::Error);
        assert_eq!(undef.category, "Lint");
        assert_eq!(undef.metric, "lint");
        assert_eq!(undef.file.as_deref(), Some("src/a.ts"));
        assert!(undef.message.contains("(L7)"));
    }

    #[test]
    fn empty_report_yields_nothing() {
        assert!(parse_eslint("[]", Path::new("/repo")).unwrap().is_empty());
    }
}
