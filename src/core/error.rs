//! The error type returned at the review boundary.
//!
//! Internally the analysis modules use `Result<_, String>` for brevity; this
//! enum is the typed surface `core::review::analyze` exposes, so a service
//! consumer can branch on *what kind* of thing failed (bad config vs. IO vs.
//! git vs. lint ingest vs. rendering) instead of string-matching.

use std::fmt;

#[derive(Debug)]
pub enum ReviewError {
    /// Loading or parsing the review configuration failed.
    Config(String),
    /// A filesystem operation failed (reading the repo, a report file, …).
    Io(String),
    /// A git operation failed or the requested ref could not be diffed.
    Git(String),
    /// Ingesting an external linter report failed.
    Lint(String),
    /// Rendering the report (e.g. JSON serialization) failed.
    Render(String),
}

impl fmt::Display for ReviewError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (kind, detail) = match self {
            ReviewError::Config(d) => ("config", d),
            ReviewError::Io(d) => ("io", d),
            ReviewError::Git(d) => ("git", d),
            ReviewError::Lint(d) => ("lint", d),
            ReviewError::Render(d) => ("render", d),
        };
        write!(f, "{kind}: {detail}")
    }
}

impl std::error::Error for ReviewError {}
