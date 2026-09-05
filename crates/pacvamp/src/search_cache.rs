//! A disposable index for search display only. Resolution and trust verification
//! always read the authoritative sync databases, never these cached records.
use std::io::{Read, Write};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use eyre::{Context as _, Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::host::Source;

const SCHEMA: u32 = 1;
const MAX_BYTES: u64 = 32 * 1024 * 1024;

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct Package {
    pub name: String,
    pub version: String,
    pub desc: Option<String>,
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
struct Identity {
    device: u64,
    inode: u64,
    size: u64,
    modified: (i64, i64),
    changed: (i64, i64),
}

impl Identity {
    /// Sample the Linux file identity used to detect replacement and in-place edits.
    fn read(path: &Path) -> std::io::Result<Self> {
        let meta = path.metadata()?;
        Ok(Self {
            device: meta.dev(),
            inode: meta.ino(),
            size: meta.len(),
            modified: (meta.mtime(), meta.mtime_nsec()),
            changed: (meta.ctime(), meta.ctime_nsec()),
        })
    }
}

#[derive(Serialize, Deserialize)]
struct Index {
    schema: u32,
    identity: Identity,
    packages: Vec<Package>,
}

/// Namespace indexes by canonical database path within the invoking user's cache.
fn cache_path(database: &Path) -> Option<PathBuf> {
    let home = std::env::var_os("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .or_else(|| std::env::var_os("HOME").map(|p| PathBuf::from(p).join(".cache")))?;
    let path = database.canonicalize().ok()?;
    let key = Sha256::digest(path.as_os_str().as_encoded_bytes());
    Some(home.join("pacvamp/search-v1").join(format!("{key:x}.json")))
}

/// Read a bounded index only when its schema and sampled database identity match.
fn read(path: &Path, identity: &Identity) -> Option<Vec<Package>> {
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .ok()?
        .take(MAX_BYTES + 1)
        .read_to_end(&mut bytes)
        .ok()?;
    if bytes.len() as u64 > MAX_BYTES {
        return None;
    }
    let index: Index = serde_json::from_slice(&bytes).ok()?;
    (index.schema == SCHEMA && index.identity == *identity).then_some(index.packages)
}

/// Publish a complete disposable index by atomic rename, retaining size limits.
fn write(path: &Path, index: &Index) -> Result<()> {
    let parent = path.parent().expect("cache file has a parent");
    std::fs::create_dir_all(parent)?;
    let mut file = tempfile::NamedTempFile::new_in(parent)?;
    let bytes = serde_json::to_vec(index)?;
    if bytes.len() as u64 > MAX_BYTES {
        return Ok(());
    }
    file.write_all(&bytes)?;
    file.persist(path)?;
    Ok(())
}

/// Return search records from a revalidated cache or a stable database parse.
pub(crate) fn packages(source: &Source) -> Result<Vec<Package>> {
    let database = source.database_path();
    // A continuously refreshing database must not keep a menu query spinning.
    for _ in 0..3 {
        let identity = match Identity::read(database) {
            Ok(identity) => identity,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => {
                return Err(error).wrap_err_with(|| format!("reading {}", database.display()));
            }
        };
        let cache = cache_path(database);
        let cached = cache.as_deref().and_then(|path| read(path, &identity));
        // Cache I/O can overlap a pacman refresh. Restart from a fresh identity
        // on both hits and misses rather than returning or parsing against the old one.
        if Identity::read(database).ok().as_ref() != Some(&identity) {
            continue;
        }
        if let Some(packages) = cached {
            return Ok(packages);
        }
        // Parse anew rather than using Source's in-process cell: a refresh may have
        // replaced a database since another command populated that cell.
        let db = alpm_db::SyncDb::read(database, &source.name)
            .wrap_err_with(|| format!("reading {}", database.display()))?;
        if Identity::read(database)? != identity {
            bail!(
                "{} changed during search; retry after the repository refresh",
                database.display()
            );
        }
        let index = Index {
            schema: SCHEMA,
            identity,
            packages: db
                .packages
                .into_iter()
                .map(|p| Package {
                    name: p.name,
                    version: p.version,
                    desc: p.desc,
                })
                .collect(),
        };
        if let Some(path) = cache {
            // An unwritable/full cache must not make package search unavailable.
            let _ = write(&path, &index);
        }
        return Ok(index.packages);
    }
    bail!(
        "{} changed during search; retry after the repository refresh",
        database.display()
    )
}
