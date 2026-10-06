//! Private, durable file primitives for server state.
use anyhow::{Context, Result, bail};
use std::{
    fs::File,
    io::Write,
    path::{Component, Path},
};

pub fn validate_alias(alias: &str) -> Result<&str> {
    let alias = alias.trim();
    if alias.is_empty()
        || alias.len() > 64
        || !alias.is_ascii()
        || alias.starts_with('.')
        || alias.chars().any(|c| c.is_control() || c == '/' || c == '\\')
    {
        bail!("alias must be 1 to 64 ASCII characters without path separators");
    }
    let mut components = Path::new(alias).components();
    if !matches!(components.next(), Some(Component::Normal(_))) || components.next().is_some() {
        bail!("alias must be one path component");
    }
    Ok(alias)
}

pub fn ensure_private_dir(path: &Path) -> Result<()> {
    if std::fs::symlink_metadata(path).is_ok_and(|m| !m.is_dir() || m.file_type().is_symlink()) {
        bail!("server directory must be a real directory");
    }
    std::fs::create_dir_all(path).with_context(|| format!("failed to create {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

pub fn sync_directory(path: &Path) -> Result<()> {
    File::open(path)?.sync_all()?;
    Ok(())
}

pub fn atomic_write(destination: &Path, contents: &[u8]) -> Result<()> {
    let parent = destination.parent().context("file has no parent")?;
    ensure_private_dir(parent)?;
    if std::fs::symlink_metadata(destination)
        .is_ok_and(|m| !m.is_file() || m.file_type().is_symlink())
    {
        bail!("server state must be a regular file");
    }
    // NamedTempFile creates the file with mode 0600.
    let mut tmp = tempfile::NamedTempFile::new_in(parent)?;
    tmp.write_all(contents)?;
    tmp.as_file().sync_all()?;
    tmp.persist(destination)
        .map_err(|_| anyhow::anyhow!("server state publication failed"))?;
    sync_directory(parent)
}

pub fn remove_if_present(path: &Path) -> Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
    }
}
