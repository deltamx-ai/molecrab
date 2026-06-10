use crate::{cli::Commands, core};

pub fn run(command: Commands) -> i32 {
    match command {
        Commands::Review {
            path,
            config,
            format,
            since,
            eslint,
        } => core::review::run(path, config, format, since, eslint),
        Commands::Doctor => {
            core::doctor::run();
            0
        }
    }
}
