use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "molecrab", version, about = "A repository quality review tool")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Review a repository's code quality.
    Review {
        /// Path to the repository.
        path: PathBuf,
    },

    /// Check whether common developer tools are installed and usable.
    Doctor,
}
