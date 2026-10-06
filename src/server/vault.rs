//! Authenticated encryption, private reads, process locks, and the machine registry.
use super::fs;
use aes_gcm::{
    Aes256Gcm,
    aead::{Aead, AeadCore, KeyInit, OsRng, rand_core::RngCore},
};
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{File, OpenOptions},
    io::Write,
    path::Path,
};

pub fn random_bytes() -> [u8; 32] {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

pub fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

pub fn secret() -> String {
    digest(&random_bytes())
}

pub fn private_read(path: &Path) -> Result<Vec<u8>> {
    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.is_file() {
        bail!("secret must be a regular file");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            bail!("secret file must have mode 0600 or stricter");
        }
    }
    std::fs::read(path).context("could not read private file")
}

pub fn create_secret(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .context("could not create secret file; destination must be new")?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

pub struct Lock(File);
impl Drop for Lock {
    fn drop(&mut self) {
        // A fork can inherit the open description. Release explicitly before closing.
        let _ = self.0.unlock();
    }
}

/// Fails at once when another process owns the lock.
pub fn lock(state: &Path, name: &str) -> Result<Lock> {
    let file = open_lock(state, name)?;
    file.try_lock().context("another process owns this state")?;
    Ok(Lock(file))
}

/// Waits up to five seconds for a short registry update by another request.
pub fn registry_lock(state: &Path, name: &str) -> Result<Lock> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        match lock(state, name) {
            Ok(guard) => return Ok(guard),
            Err(e)
                if e.downcast_ref::<std::fs::TryLockError>()
                    .is_some_and(|e| matches!(e, std::fs::TryLockError::WouldBlock))
                    && std::time::Instant::now() < deadline =>
            {
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            Err(e) => return Err(e),
        }
    }
}

fn open_lock(state: &Path, name: &str) -> Result<File> {
    fs::ensure_private_dir(state)?;
    let path = state.join(name);
    if std::fs::symlink_metadata(&path).is_ok_and(|m| m.file_type().is_symlink()) {
        bail!("lock file must not be a symlink");
    }
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    Ok(options.open(path)?)
}

fn cipher(key: &Path) -> Result<Aes256Gcm> {
    let bytes = private_read(key)?;
    Aes256Gcm::new_from_slice(&bytes)
        .map_err(|_| anyhow::anyhow!("vault key must contain exactly 32 bytes"))
}

pub fn encrypt(key: &Path, plaintext: &[u8]) -> Result<Vec<u8>> {
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let encrypted = cipher(key)?
        .encrypt(&nonce, plaintext)
        .map_err(|_| anyhow::anyhow!("vault encryption failed"))?;
    let mut bytes = nonce.to_vec();
    bytes.extend(encrypted);
    Ok(bytes)
}

pub fn decrypt(key: &Path, bytes: &[u8]) -> Result<Vec<u8>> {
    if bytes.len() < 28 {
        bail!("vault is truncated");
    }
    cipher(key)?
        .decrypt(bytes[..12].into(), &bytes[12..])
        .map_err(|_| anyhow::anyhow!("vault authentication failed"))
}

pub fn seal<T: Serialize>(path: &Path, key: &Path, value: &T) -> Result<()> {
    fs::atomic_write(path, &encrypt(key, &serde_json::to_vec(value)?)?)
}

pub fn unseal<T: serde::de::DeserializeOwned>(path: &Path, key: &Path) -> Result<T> {
    let plaintext = decrypt(key, &private_read(path)?)?;
    serde_json::from_slice(&plaintext).map_err(|_| anyhow::anyhow!("invalid vault record"))
}

#[derive(Clone, Serialize, Deserialize)]
pub struct User {
    pub id: String,
    pub email: String,
    pub enabled: bool,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Machine {
    pub id: String,
    pub user: String,
    pub token_hash: String,
    pub revoked: bool,
}

pub fn users(state: &Path) -> Result<Vec<User>> {
    serde_json::from_slice(&private_read(&state.join("users.json"))?)
        .context("invalid user registry")
}

pub fn save_users(state: &Path, users: &[User]) -> Result<()> {
    fs::atomic_write(&state.join("users.json"), &serde_json::to_vec(users)?)
}

pub fn machines(state: &Path) -> Result<Vec<Machine>> {
    serde_json::from_slice(&private_read(&state.join("machines.json"))?)
        .context("invalid machine registry")
}

pub fn save_machines(state: &Path, machines: &[Machine]) -> Result<()> {
    fs::atomic_write(&state.join("machines.json"), &serde_json::to_vec(machines)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_changed_ciphertext_or_wrong_key_is_rejected() {
        let root = tempfile::tempdir().unwrap();
        let key = root.path().join("key");
        let other = root.path().join("other");
        create_secret(&key, &[7; 32]).unwrap();
        create_secret(&other, &[8; 32]).unwrap();
        let path = root.path().join("record.enc");
        seal(&path, &key, &"synthetic").unwrap();
        assert!(unseal::<String>(&path, &other).is_err());
        let mut bytes = private_read(&path).unwrap();
        bytes[12] ^= 1;
        fs::atomic_write(&path, &bytes).unwrap();
        assert!(unseal::<String>(&path, &key).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn a_duplicate_descriptor_does_not_keep_a_released_lock_owned() {
        use std::os::fd::{AsRawFd, FromRawFd};
        let root = tempfile::tempdir().unwrap();
        let guard = lock(root.path(), "owner.lock").unwrap();
        let fd = unsafe { libc::dup(guard.0.as_raw_fd()) };
        assert!(fd >= 0);
        let inherited = unsafe { File::from_raw_fd(fd) };
        assert!(lock(root.path(), "owner.lock").is_err());
        drop(guard);
        let _next = lock(root.path(), "owner.lock").unwrap();
        drop(inherited);
    }
}
