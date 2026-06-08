use crate::{cli::Commands, core};

pub fn run(command: Commands) {
    match command {
        Commands::Review { path } => core::review::run(path),
        Commands::Doctor => core::doctor::run(),
    }
}
