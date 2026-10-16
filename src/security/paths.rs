//! Trust paths are absolute, symlink-free, and not writable by Agents.
use std::fs::{Metadata, OpenOptions};
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt};
use std::path::{Component, Path, PathBuf};

use crate::error::{KeydError, Result};

fn denied(path: &Path) -> KeydError {
    KeydError::Permission(format!("untrusted protected path: {}", path.display()))
}

pub fn validate_absolute(path: &Path) -> Result<()> {
    let spelling = path.to_string_lossy();
    if !path.is_absolute()
        || spelling.contains("//")
        || spelling
            .split('/')
            .skip(1)
            .any(|part| part.is_empty() || part == "." || part == "..")
        || path
            .components()
            .any(|c| matches!(c, Component::ParentDir | Component::CurDir))
    {
        return Err(denied(path));
    }
    Ok(())
}

pub fn validate_file_metadata(meta: &Metadata, owners: &[u32], directory: bool) -> Result<()> {
    if !owners.contains(&meta.uid())
        || meta.mode() & 0o022 != 0
        || (directory && !meta.is_dir())
        || (!directory && !meta.is_file())
    {
        return Err(KeydError::Permission(
            "untrusted owner, mode or file type".into(),
        ));
    }
    Ok(())
}

pub fn validate_chain(path: &Path, owners: &[u32], directory: bool) -> Result<()> {
    validate_absolute(path)?;
    let mut current = PathBuf::from("/");
    validate_file_metadata(&std::fs::symlink_metadata(&current)?, owners, true)?;
    for component in path.components().skip(1) {
        current.push(component);
        let meta = std::fs::symlink_metadata(&current)?;
        validate_file_metadata(&meta, owners, current != path || directory)?;
    }
    Ok(())
}

pub fn state_directory(path: &Path, service_uid: u32) -> Result<()> {
    validate_chain(path, &[0, service_uid], true)?;
    let meta = std::fs::symlink_metadata(path)?;
    if meta.uid() != service_uid || meta.mode() & 0o777 != 0o700 {
        return Err(denied(path));
    }
    Ok(())
}

pub fn socket_parent(path: &Path, uid: u32, gid: u32) -> Result<()> {
    let parent = path.parent().ok_or_else(|| denied(path))?;
    validate_chain(parent, &[0, uid], true)?;
    let meta = std::fs::symlink_metadata(parent)?;
    if meta.uid() != uid || meta.gid() != gid || meta.mode() & 0o777 != 0o750 {
        return Err(denied(parent));
    }
    Ok(())
}

pub fn socket(path: &Path, uid: u32, gid: u32) -> Result<Metadata> {
    socket_parent(path, uid, gid)?;
    let meta = std::fs::symlink_metadata(path)?;
    if !meta.file_type().is_socket()
        || meta.uid() != uid
        || meta.gid() != gid
        || meta.mode() & 0o777 != 0o660
    {
        return Err(denied(path));
    }
    Ok(meta)
}

pub fn instance_lock(state: &Path, service_uid: u32) -> Result<nix::fcntl::Flock<std::fs::File>> {
    state_directory(state, service_uid)?;
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(nix::libc::O_NOFOLLOW)
        .open(state.join("service.lock"))?;
    let meta = file.metadata()?;
    validate_file_metadata(&meta, &[service_uid], false)?;
    if meta.mode() & 0o777 != 0o600 || meta.nlink() != 1 {
        return Err(denied(state));
    }
    nix::fcntl::Flock::lock(file, nix::fcntl::FlockArg::LockExclusiveNonblock)
        .map_err(|_| KeydError::Misuse("another service holds the state lock".into()))
}

/// Legacy local commands must never act as a maintenance backdoor into a
/// managed vault, including when --root uses a symlink or a relative spelling.
pub fn deny_managed_directory(path: &Path) -> Result<()> {
    let mut existing = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    while !existing.exists() {
        if !existing.pop() {
            return Ok(());
        }
    }
    let existing = existing.canonicalize()?;
    for ancestor in existing.ancestors() {
        if ancestor.join(".anp-keyd-managed").try_exists()?
            || ancestor.join("state.sqlite").try_exists()?
        {
            return Err(KeydError::Permission(
                "managed vault requires authenticated admin client".into(),
            ));
        }
    }
    Ok(())
}
