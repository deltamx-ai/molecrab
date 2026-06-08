use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "molecrab", version, about = "A tiny CLI toolkit")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Check whether common developer tools are installed and usable.
    Doctor,
}
