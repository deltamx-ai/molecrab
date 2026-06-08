use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "molecrab", version, about = "A repository quality review tool")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
pub enum OutputFormat {
    Text,
    Json,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Review a repository's code quality.
    Review {
        /// Path to the repository.
        path: PathBuf,

        /// Optional path to a review configuration file.
        #[arg(long)]
        config: Option<PathBuf>,

        /// Output format for the review report.
        #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
        format: OutputFormat,
    },

    /// Check whether common developer tools are installed and usable.
    Doctor,
}
