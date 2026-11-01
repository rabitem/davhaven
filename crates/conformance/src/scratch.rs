//! A directory of its own below the temporary directory, for the tests of the commands: removed again when it is dropped.

use std::path::PathBuf;

/// A scratch directory.
pub(crate) struct Scratch(pub(crate) PathBuf);

impl Scratch {
    /// A new, empty directory whose name says what the test is (and which process made it).
    pub(crate) fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("davhaven-conformance-{name}-{}", std::process::id()));
        drop(std::fs::remove_dir_all(&dir));
        std::fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }

    /// Writes a file into the directory and returns its path.
    pub(crate) fn file(&self, name: &str, content: &str) -> PathBuf {
        let path = self.0.join(name);
        std::fs::write(&path, content).unwrap();
        path
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        drop(std::fs::remove_dir_all(&self.0));
    }
}
