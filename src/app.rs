use crate::{cli::Commands, core};

pub fn run(command: Commands) -> i32 {
    match command {
        Commands::Review { path, config } => core::review::run(path, config),
        Commands::Doctor => {
            core::doctor::run();
            0
        }
    }
}
