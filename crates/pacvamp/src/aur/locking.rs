//! Locks live outside recipe-writable trees and are never unlinked.
use eyre::{Context as _, Result};
use nix::fcntl::{Flock, FlockArg};
use std::path::Path;

pub(super) fn acquire(cache: &Path, pkgbase: &str) -> Result<Flock<std::fs::File>> {
    if !super::git::valid_pkgbase(pkgbase) {
        eyre::bail!("invalid AUR package base {pkgbase:?}");
    }
    let dir = cache.join(".locks");
    std::fs::create_dir_all(&dir)?;
    let path = dir.join(format!("{pkgbase}.lock"));
    let file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&path)?;
    Flock::lock(file, FlockArg::LockExclusiveNonblock)
        .map_err(|(_, err)| eyre::eyre!(err))
        .wrap_err_with(|| {
            format!("{pkgbase} is busy; retry after the other AUR operation finishes")
        })
}
