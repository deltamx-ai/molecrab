use crate::{cli::Commands, core};

pub fn run(command: Commands) -> i32 {
    match command {
        Commands::Review {
            path,
            config,
            format,
            since,
        } => core::review::run(path, config, format, since),
        Commands::Doctor => {
            core::doctor::run();
            0
        }
    }
}
