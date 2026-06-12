use colored::Colorize;

use crate::cli::{Commands, OutputFormat};
use crate::core;

pub fn run(command: Commands) -> i32 {
    match command {
        Commands::Review {
            path,
            config,
            format,
            since,
            eslint,
        } => review(path, config, format, since, eslint),
        Commands::Doctor => {
            core::doctor::run();
            0
        }
    }
}

/// Runs the review analysis and renders it in the requested format. The choice
/// of output format lives here (the CLI layer), so `core` stays free of any
/// presentation/CLI coupling: it only produces a report and offers renderers.
fn review(
    path: std::path::PathBuf,
    config: Option<std::path::PathBuf>,
    format: OutputFormat,
    since: Option<String>,
    eslint: Option<std::path::PathBuf>,
) -> i32 {
    let report = match core::review::analyze(path, config, since, eslint) {
        Ok(report) => report,
        Err(err) => {
            eprintln!("review failed: {}", err.red());
            return 1;
        }
    };
    match format {
        OutputFormat::Text => {
            println!("{}", core::review::render_text_report(&report));
            0
        }
        OutputFormat::Json => match core::review::render_json_report(&report) {
            Ok(json) => {
                println!("{}", json);
                0
            }
            Err(err) => {
                eprintln!("review failed: {}", err.red());
                1
            }
        },
    }
}
