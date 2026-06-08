mod app;
mod cli;

use clap::Parser;

fn main() {
    let cli = cli::Cli::parse();
    app::run(cli.command);
}
