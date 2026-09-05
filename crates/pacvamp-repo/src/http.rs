//! Downloading upstream artifacts: streamed to disk while every digest a
//! PKGBUILD might carry is computed, so a multi-hundred-megabyte `.deb`
//! never sits in memory.

use std::io::{Read as _, Write as _};
use std::path::Path;

use eyre::{Context as _, Result, bail};
use sha2::Digest as _;

/// Larger than any desktop app we repackage; a guard, not a budget.
const MAX_BYTES: u64 = 4 * 1024 * 1024 * 1024;

/// What a download produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fetched {
    /// Lowercase hex.
    pub sha256: String,
    /// Lowercase hex.
    pub sha512: String,
    /// Lowercase hex, BLAKE2b-512 as makepkg's `b2sums` uses.
    pub blake2b: String,
    pub size: u64,
}

/// Download `url` to `dest`, replacing it, and return its digests.
pub fn fetch_to_file(url: &str, dest: &Path) -> Result<Fetched> {
    let mut response = ureq::get(url)
        .call()
        .wrap_err_with(|| format!("fetching {url}"))?;
    let mut reader = response.body_mut().with_config().limit(MAX_BYTES).reader();
    let parent = dest
        .parent()
        .ok_or_else(|| eyre::eyre!("download destination has no parent"))?;
    let mut file = tempfile::NamedTempFile::new_in(parent)
        .wrap_err_with(|| format!("staging {}", dest.display()))?;
    let mut sha256 = sha2::Sha256::new();
    let mut sha512 = sha2::Sha512::new();
    let mut blake2b = blake2::Blake2b512::new();
    let mut size = 0u64;
    let mut buf = vec![0u8; 1 << 16];
    loop {
        let n = reader
            .read(&mut buf)
            .wrap_err_with(|| format!("reading {url}"))?;
        if n == 0 {
            break;
        }
        file.write_all(&buf[..n])
            .wrap_err_with(|| format!("writing {}", dest.display()))?;
        sha256.update(&buf[..n]);
        sha512.update(&buf[..n]);
        blake2b.update(&buf[..n]);
        size += n as u64;
    }
    file.flush()?;
    if size == 0 {
        bail!("{url} is empty");
    }
    file.persist(dest)
        .wrap_err_with(|| format!("publishing {}", dest.display()))?;
    Ok(Fetched {
        sha256: format!("{:x}", sha256.finalize()),
        sha512: format!("{:x}", sha512.finalize()),
        blake2b: format!("{:x}", blake2b.finalize()),
        size,
    })
}
