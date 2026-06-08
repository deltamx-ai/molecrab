pub mod app;
pub mod cli;
pub mod core;

use clap::Parser;

pub fn run() {
    let cli = cli::Cli::parse();
    app::run(cli.command);
}
