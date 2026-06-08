use std::path::PathBuf;

use super::model::{RepositoryProfile, ReviewScore};

pub fn analyze(path: PathBuf) -> (RepositoryProfile, ReviewScore) {
    let profile = RepositoryProfile {
        path: path.display().to_string(),
    };
    let score = ReviewScore { overall: 0 };
    (profile, score)
}

pub fn run(path: PathBuf) {
    let (profile, score) = analyze(path);
    println!("review: {} | score: {}", profile.path, score.overall);
}
