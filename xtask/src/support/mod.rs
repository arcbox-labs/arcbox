use std::{error::Error, fmt, path::PathBuf};

pub mod fs;

#[derive(Debug)]
pub struct ExitCode(i32);

impl ExitCode {
    pub fn new(code: i32) -> Self {
        Self(code)
    }

    pub fn code(&self) -> i32 {
        self.0
    }
}

impl fmt::Display for ExitCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "exit with status {}", self.0)
    }
}

impl Error for ExitCode {}

pub fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask crate lives directly under the repository root")
        .to_owned()
}
