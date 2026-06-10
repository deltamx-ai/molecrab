//! Frontend project classification + lightweight Angular template analysis.
//!
//! Two jobs, both repo-level (the per-function AST work lives in `frontend.rs`):
//!
//! 1. [`classify`] decides whether the repo is React / Angular / Mixed / Generic
//!    TS-JS / Non-frontend, from dependency manifests, file extensions, and cheap
//!    token scans (hooks, decorators) plus the DI-constructor count from the AST
//!    pass. The result gates which framework rules run (`core::rules`).
//! 2. The template helpers ([`template_event_handlers`], [`ts_has_identifier`],
//!    [`sibling_component_path`]) back the Angular "template ↔ component" rule:
//!    an `(event)="handler()"` binding whose handler the component never defines
//!    is almost always a typo or a rename left behind.
//!
//! The template scan is deliberately heuristic (Angular templates are not XML);
//! it only flags handlers that appear *nowhere* in the sibling component, which
//! keeps false positives low.

use super::model::{FileSnapshot, FrontendKind, FrontendProfile, FunctionSnapshot};

/// Dependency markers (matched as quoted JSON keys) that imply a React project.
const REACT_DEPS: [&str; 4] = ["\"react\"", "\"react-dom\"", "\"next\"", "\"@types/react\""];
const REACT_HOOKS: [&str; 5] = ["useState", "useEffect", "useMemo", "useCallback", "useRef"];
const ANGULAR_DECORATORS: [&str; 5] = [
    "@Component",
    "@Injectable",
    "@NgModule",
    "@Directive",
    "@Pipe",
];

/// Classifies the repository's frontend flavour and records the evidence.
pub fn classify(files: &[FileSnapshot], functions: &[FunctionSnapshot]) -> FrontendProfile {
    let mut profile = FrontendProfile::default();

    for file in files {
        if file.category.is_noise() {
            continue;
        }
        let name = file.name.as_str();
        let content = file.content.as_deref().unwrap_or("");

        if name == "package.json" {
            if REACT_DEPS.iter().any(|dep| content.contains(dep)) {
                profile.react_dependency = true;
            }
            if content.contains("\"@angular/core\"") {
                profile.angular_dependency = true;
            }
        }
        if name == "angular.json" {
            profile.angular_dependency = true;
        }

        match ext(name) {
            Some("tsx" | "jsx") => {
                profile.jsx_files += 1;
                profile.script_files += 1;
            }
            Some("ts" | "js" | "mjs" | "cjs") => profile.script_files += 1,
            Some("html") => profile.html_templates += 1,
            _ => {}
        }

        if is_script(name) {
            for hook in REACT_HOOKS {
                profile.react_hooks += content.matches(hook).count();
            }
            for decorator in ANGULAR_DECORATORS {
                profile.angular_decorators += content.matches(decorator).count();
            }
        }
    }

    profile.di_constructors = functions
        .iter()
        .filter(|f| f.name.ends_with("::constructor") && f.param_count > 0)
        .count();

    let has_react = profile.react_dependency || profile.react_hooks > 0 || profile.jsx_files > 0;
    let has_angular = profile.angular_dependency || profile.angular_decorators > 0;
    profile.kind = match (has_react, has_angular) {
        (true, true) => FrontendKind::Mixed,
        (false, true) => FrontendKind::Angular,
        (true, false) => FrontendKind::React,
        (false, false) if profile.script_files > 0 => FrontendKind::Generic,
        (false, false) => FrontendKind::NonFrontend,
    };
    profile
}

/// The `.ts` component path a `.html` template is expected to pair with
/// (`foo.component.html` → `foo.component.ts`). `None` if `path` is not `.html`.
pub fn sibling_component_path(path: &str) -> Option<String> {
    path.strip_suffix(".html").map(|stem| format!("{stem}.ts"))
}

/// Handler names bound to events in an Angular template, with 1-based line
/// numbers. Catches `(click)="onClick()"`-style bindings; the handler is the
/// leading identifier of the bound statement.
pub fn template_event_handlers(html: &str) -> Vec<(String, usize)> {
    let mut handlers = Vec::new();
    for (idx, line) in html.lines().enumerate() {
        // `)="` is the tail of an event binding `(event)="expr"`. Two-way
        // bindings (`[(x)]="…"`) read as `)]="` and never match here.
        let mut search_from = 0;
        while let Some(rel) = line[search_from..].find(")=\"") {
            let expr_start = search_from + rel + 3;
            let Some(end_rel) = line[expr_start..].find('"') else {
                break;
            };
            let expr = &line[expr_start..expr_start + end_rel];
            if let Some(name) = leading_identifier(expr) {
                handlers.push((name.to_string(), idx + 1));
            }
            search_from = expr_start + end_rel + 1;
        }
    }
    handlers
}

/// Whether `name` appears as an identifier token anywhere in the TS source. Used
/// as a low-false-positive "does the component know this name at all" check.
pub fn ts_has_identifier(ts: &str, name: &str) -> bool {
    let mut token = String::new();
    for ch in ts.chars() {
        if ch == '_' || ch == '$' || ch.is_alphanumeric() {
            token.push(ch);
        } else {
            if token == name {
                return true;
            }
            token.clear();
        }
    }
    token == name
}

/// The leading `[A-Za-z_$][A-Za-z0-9_$]*` identifier of a bound expression.
fn leading_identifier(expr: &str) -> Option<&str> {
    let expr = expr.trim_start();
    let mut end = 0;
    for (i, ch) in expr.char_indices() {
        let ok = if i == 0 {
            ch.is_alphabetic() || ch == '_' || ch == '$'
        } else {
            ch.is_alphanumeric() || ch == '_' || ch == '$'
        };
        if ok {
            end = i + ch.len_utf8();
        } else {
            break;
        }
    }
    (end > 0).then(|| &expr[..end])
}

fn ext(name: &str) -> Option<&str> {
    name.rsplit_once('.').map(|(_, ext)| ext)
}

fn is_script(name: &str) -> bool {
    matches!(ext(name), Some("ts" | "tsx" | "js" | "jsx" | "mjs" | "cjs"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::classify::FileCategory;

    fn file(name: &str, content: &str) -> FileSnapshot {
        FileSnapshot {
            path: name.to_string(),
            name: name.rsplit('/').next().unwrap().to_string(),
            lines: content.lines().count().max(1),
            bytes: content.len() as u64,
            depth: 1,
            category: FileCategory::Source,
            content: Some(content.to_string()),
        }
    }

    #[test]
    fn classifies_react_from_jsx_and_hooks() {
        let files = vec![file(
            "src/App.tsx",
            "export function App() { const [n] = useState(0); return null; }",
        )];
        let profile = classify(&files, &[]);
        assert_eq!(profile.kind, FrontendKind::React);
        assert!(profile.jsx_files >= 1);
        assert!(profile.react_hooks >= 1);
    }

    #[test]
    fn classifies_angular_from_decorator() {
        let files = vec![file(
            "src/app.component.ts",
            "@Component({}) export class AppComponent {}",
        )];
        let profile = classify(&files, &[]);
        assert_eq!(profile.kind, FrontendKind::Angular);
        assert!(profile.angular_decorators >= 1);
    }

    #[test]
    fn classifies_mixed_when_both_present() {
        let files = vec![
            file("src/App.tsx", "const x = useEffect;"),
            file("src/a.component.ts", "@Component({}) class A {}"),
        ];
        assert_eq!(classify(&files, &[]).kind, FrontendKind::Mixed);
    }

    #[test]
    fn classifies_generic_and_non_frontend() {
        let generic = vec![file("src/util.ts", "export const add = (a, b) => a + b;")];
        assert_eq!(classify(&generic, &[]).kind, FrontendKind::Generic);
        assert_eq!(classify(&[], &[]).kind, FrontendKind::NonFrontend);
    }

    #[test]
    fn extracts_event_handlers_and_checks_membership() {
        let html =
            "<button (click)=\"onSave()\">x</button>\n<i (mouseenter)=\"hover($event)\"></i>";
        let handlers = template_event_handlers(html);
        let names: Vec<&str> = handlers.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(names, ["onSave", "hover"]);
        assert_eq!(handlers[0].1, 1);

        let ts = "export class C { onSave() {} }";
        assert!(ts_has_identifier(ts, "onSave"));
        assert!(!ts_has_identifier(ts, "hover"));
    }

    #[test]
    fn sibling_path_maps_html_to_ts() {
        assert_eq!(
            sibling_component_path("a/foo.component.html").as_deref(),
            Some("a/foo.component.ts")
        );
        assert_eq!(sibling_component_path("a/foo.ts"), None);
    }
}
