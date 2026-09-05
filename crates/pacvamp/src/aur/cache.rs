//! Retention for build runs, separate from recipe checkouts and lock files.
use eyre::{Context as _, Result};
use nix::fcntl::{Flock, FlockArg};
use serde::Serialize;
use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
};

pub fn lease(cache: &Path, prune: bool) -> Result<Flock<fs::File>> {
    fs::create_dir_all(cache.join(".locks"))?;
    let file = fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(cache.join(".locks/retention.lock"))?;
    Flock::lock(
        file,
        if prune {
            FlockArg::LockExclusiveNonblock
        } else {
            FlockArg::LockSharedNonblock
        },
    )
    .map_err(|(_, err)| eyre::eyre!(err))
    .wrap_err("cache is busy; retry after builds or pruning finish")
}

#[derive(Debug, Serialize)]
pub struct Run {
    pub path: PathBuf,
    pub bytes: u64,
    pub age_seconds: u64,
    pub protected: bool,
    pub prune: bool,
}

fn size(path: &Path) -> Result<u64> {
    use std::os::unix::fs::MetadataExt as _;
    let meta = match fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(err) => return Err(err.into()),
    };
    if meta.is_symlink() {
        return Ok(0);
    }
    let mut bytes = meta.len().max(meta.blocks().saturating_mul(512));
    if meta.is_dir() {
        for entry in fs::read_dir(path)? {
            bytes = bytes.saturating_add(size(&entry?.path())?);
        }
    }
    Ok(bytes)
}

pub fn inventory(
    cache: &Path,
    protected: &BTreeSet<PathBuf>,
    days: u64,
    max_bytes: Option<u64>,
) -> Result<Vec<Run>> {
    let root = cache.join(".pacvamp-build/runs");
    if !root.exists() {
        return Ok(Vec::new());
    }
    let root = root.canonicalize()?;
    let mut runs = Vec::new();
    for entry in fs::read_dir(&root)? {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let path = entry.path();
        let age_seconds = entry
            .metadata()?
            .modified()?
            .elapsed()
            .unwrap_or_default()
            .as_secs();
        let referenced = protected.iter().any(|p| p.starts_with(&path));
        runs.push(Run {
            bytes: size(&path)?,
            path,
            age_seconds,
            protected: referenced || age_seconds < 3600,
            prune: false,
        });
    }
    runs.sort_by_key(|run| std::cmp::Reverse(run.age_seconds));
    let mut retained = runs.iter().fold(0u64, |n, r| n.saturating_add(r.bytes));
    for run in &mut runs {
        run.prune = !run.protected
            && (run.age_seconds >= days.saturating_mul(86400)
                || max_bytes.is_some_and(|max| retained > max));
        if run.prune {
            retained = retained.saturating_sub(run.bytes);
        }
    }
    Ok(runs)
}
