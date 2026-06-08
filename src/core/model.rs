#[derive(Debug, Clone)]
pub struct RepositoryProfile {
    path: String,
}

#[derive(Debug, Clone)]
pub struct ReviewScore {
    overall: u8,
}

impl RepositoryProfile {
    pub fn new(path: impl Into<String>) -> Self {
        Self { path: path.into() }
    }

    pub fn path(&self) -> &str {
        &self.path
    }
}

impl ReviewScore {
    pub fn new(overall: u8) -> Self {
        Self { overall }
    }

    pub fn overall(&self) -> u8 {
        self.overall
    }
}
