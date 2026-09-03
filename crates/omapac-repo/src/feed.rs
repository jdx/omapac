//! Signed feeds: load the current document, bump its sequence, write it
//! atomically with a minisign signature beside it.

use std::path::{Path, PathBuf};

use eyre::{Context as _, Result};
use packslip::minisign::SecretKey;
use serde::Serialize;
use serde::de::DeserializeOwned;

/// The feed at `path`, if it exists.
pub fn load<T: DeserializeOwned>(path: &Path) -> Result<Option<T>> {
    match std::fs::read(path) {
        Ok(bytes) => Ok(Some(
            serde_json::from_slice(&bytes)
                .wrap_err_with(|| format!("parsing {}", path.display()))?,
        )),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err).wrap_err_with(|| format!("reading {}", path.display())),
    }
}

/// Write `value` and its signature atomically.
pub fn write_signed<T: Serialize>(
    path: &Path,
    value: &T,
    key: &SecretKey,
    comment: &str,
) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(value)?;
    let signature = key.sign(&bytes, comment).to_file();
    write_atomic(path, &bytes)?;
    write_atomic(&sig_path(path), signature.as_bytes())?;
    Ok(())
}

pub fn sig_path(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(".minisig");
    PathBuf::from(name)
}

pub fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let temp = path.with_extension("tmp");
    std::fs::write(&temp, bytes).wrap_err_with(|| format!("writing {}", temp.display()))?;
    std::fs::rename(&temp, path).wrap_err_with(|| format!("renaming to {}", path.display()))?;
    Ok(())
}

/// Read a secret key file.
pub fn secret_key(path: &Path) -> Result<SecretKey> {
    let text =
        std::fs::read_to_string(path).wrap_err_with(|| format!("reading {}", path.display()))?;
    Ok(SecretKey::parse(&text)?)
}

pub fn now() -> String {
    match std::env::var("OMAPAC_REPO_NOW") {
        Ok(fixed) => fixed,
        Err(_) => jiff::Timestamp::now().to_string(),
    }
}
