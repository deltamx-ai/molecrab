//! End-to-end tests over the public `analyze()` boundary: build a tiny repo on
//! disk, run the real pipeline (scan → classify → metrics → rules), and assert
//! on the resulting `ReviewReport`. These guard the analysis layer as a whole,
//! independent of how it is rendered.

use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use molecrab::core::model::FrontendKind;
use molecrab::core::review;

/// A unique temp directory with a `src/` subdir, so concurrent test runs don't
/// collide. Caller is responsible for writing fixture files into it.
fn temp_repo(tag: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("molecrab-it-{tag}-{nanos}"));
    fs::create_dir_all(dir.join("src")).unwrap();
    dir
}

#[test]
fn classifies_react_project_and_flags_effect_deps() {
    let dir = temp_repo("react");
    fs::write(
        dir.join("package.json"),
        r#"{ "dependencies": { "react": "^18.0.0" } }"#,
    )
    .unwrap();
    fs::write(
        dir.join("src/App.tsx"),
        "export function App() { useEffect(() => { load(); }); return null; }",
    )
    .unwrap();

    let report = review::analyze(dir.clone(), None, None, None).expect("analyze succeeds");

    assert_eq!(report.frontend.kind, FrontendKind::React);
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.rule == Some("react-effect-deps")),
        "expected a react-effect-deps finding, got: {:?}",
        report
            .findings
            .iter()
            .filter_map(|f| f.rule)
            .collect::<Vec<_>>()
    );

    fs::remove_dir_all(&dir).ok();
}

#[test]
fn classifies_angular_project_and_matches_template_handler() {
    let dir = temp_repo("angular");
    fs::write(
        dir.join("package.json"),
        r#"{ "dependencies": { "@angular/core": "^17.0.0" } }"#,
    )
    .unwrap();
    fs::write(
        dir.join("src/app.component.ts"),
        "import { Component } from '@angular/core';\n\
         @Component({ templateUrl: './app.component.html' })\n\
         export class AppComponent { realHandler() {} }",
    )
    .unwrap();
    fs::write(
        dir.join("src/app.component.html"),
        "<button (click)=\"missingHandler()\">x</button>",
    )
    .unwrap();

    let report = review::analyze(dir.clone(), None, None, None).expect("analyze succeeds");

    assert!(report.frontend.kind.is_angular());
    let template = report
        .findings
        .iter()
        .find(|f| f.rule == Some("angular-template-binding"))
        .expect("expected an angular-template-binding finding");
    assert!(template.message.contains("missingHandler"));

    fs::remove_dir_all(&dir).ok();
}

#[test]
fn react_rules_do_not_fire_on_a_generic_ts_project() {
    let dir = temp_repo("generic");
    fs::write(
        dir.join("src/util.ts"),
        "export function add(a: number, b: number) { return a + b; }",
    )
    .unwrap();

    let report = review::analyze(dir.clone(), None, None, None).expect("analyze succeeds");

    assert_eq!(report.frontend.kind, FrontendKind::Generic);
    assert!(
        !report
            .findings
            .iter()
            .any(|f| f.rule.is_some_and(|r| r.starts_with("react-")))
    );

    fs::remove_dir_all(&dir).ok();
}
