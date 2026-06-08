pub mod doctor;

use crate::cli::Commands;

pub fn run(command: Commands) {
    match command {
        Commands::Doctor => doctor::run(),
    }
}
