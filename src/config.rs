use std::path::PathBuf;

use anyhow::{Context, Result};

/// All paths claudectl uses. Testable: construct with a custom root.
#[derive(Clone)]
pub struct Paths {
    pub home: PathBuf,
}

impl Paths {
    pub fn from_home(home: PathBuf) -> Self {
        Self { home }
    }

    pub fn claudectl_dir(&self) -> PathBuf {
        self.home.join(".claudectl")
    }

    pub fn profiles_dir(&self) -> PathBuf {
        self.claudectl_dir().join("profiles")
    }

    pub fn active_file(&self) -> PathBuf {
        self.claudectl_dir().join("active")
    }

    pub fn claude_credentials_file(&self) -> PathBuf {
        self.home.join(".claude").join(".credentials.json")
    }

    pub fn claude_json(&self) -> PathBuf {
        self.home.join(".claude.json")
    }

    pub fn ensure_dirs(&self) -> Result<()> {
        let profiles = self.profiles_dir();
        std::fs::create_dir_all(&profiles)
            .with_context(|| format!("failed to create {}", profiles.display()))?;
        Ok(())
    }
}

/// Default paths using real home directory.
pub fn default_paths() -> Result<Paths> {
    let home = dirs::home_dir().context("could not determine home directory")?;
    Ok(Paths::from_home(home))
}

pub fn ensure_dirs() -> Result<()> {
    default_paths()?.ensure_dirs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_layout() {
        let p = Paths::from_home(PathBuf::from("/h"));
        assert_eq!(p.claudectl_dir(), PathBuf::from("/h/.claudectl"));
        assert_eq!(p.profiles_dir(), PathBuf::from("/h/.claudectl/profiles"));
        assert_eq!(p.active_file(), PathBuf::from("/h/.claudectl/active"));
        assert_eq!(
            p.claude_credentials_file(),
            PathBuf::from("/h/.claude/.credentials.json")
        );
        assert_eq!(p.claude_json(), PathBuf::from("/h/.claude.json"));
    }

    #[test]
    fn ensure_dirs_creates_profiles_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let p = Paths::from_home(tmp.path().to_path_buf());
        p.ensure_dirs().unwrap();
        assert!(p.profiles_dir().is_dir());
    }
}
