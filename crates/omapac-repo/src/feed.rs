//! Signed feeds: load the current document, bump its sequence, write it
//! atomically with a minisign signature beside it.

use std::path::{Path, PathBuf};

use eyre::{Context as _, Result};
use packslip::minisign::{PublicKey, SecretKey, Sig};
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

/// The signed feed at `path`, if it exists. Existing producer state must
/// authenticate before it can be extended and signed again.
pub fn load_signed<T: DeserializeOwned>(path: &Path, key: &PublicKey) -> Result<Option<T>> {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(err).wrap_err_with(|| format!("reading {}", path.display())),
    };
    let signature_path = sig_path(path);
    let signature = std::fs::read_to_string(&signature_path)
        .wrap_err_with(|| format!("reading {}", signature_path.display()))?;
    let signature =
        Sig::parse(&signature).wrap_err_with(|| format!("parsing {}", signature_path.display()))?;
    key.verify(&bytes, &signature)
        .wrap_err_with(|| format!("verifying {}", path.display()))?;
    Ok(Some(
        serde_json::from_slice(&bytes).wrap_err_with(|| format!("parsing {}", path.display()))?,
    ))
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
    write_signed_pair(path, &bytes, signature.as_bytes())
}

fn write_signed_pair(path: &Path, bytes: &[u8], signature: &[u8]) -> Result<()> {
    let signature_path = sig_path(path);
    let document_temp = path.with_extension("json.pair-tmp");
    let signature_temp = signature_path.with_extension("minisig.pair-tmp");
    std::fs::write(&document_temp, bytes)
        .wrap_err_with(|| format!("writing {}", document_temp.display()))?;
    if let Err(err) = std::fs::write(&signature_temp, signature) {
        let _ = std::fs::remove_file(&document_temp);
        return Err(err).wrap_err_with(|| format!("writing {}", signature_temp.display()));
    }
    let previous = std::fs::read(path).ok();
    std::fs::rename(&document_temp, path)
        .wrap_err_with(|| format!("publishing {}", path.display()))?;
    if let Err(err) = std::fs::rename(&signature_temp, &signature_path) {
        match previous {
            Some(previous) => write_atomic(path, &previous)?,
            None => {
                let _ = std::fs::remove_file(path);
            }
        }
        return Err(err).wrap_err_with(|| format!("publishing {}", signature_path.display()));
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failed_signature_publish_restores_document() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("feed.json");
        std::fs::write(&path, b"old").unwrap();
        std::fs::create_dir(sig_path(&path)).unwrap();
        let key = SecretKey::from_seed([4u8; 32]);
        assert!(write_signed(&path, &serde_json::json!({"new": true}), &key, "test").is_err());
        assert_eq!(std::fs::read(path).unwrap(), b"old");
    }

    #[test]
    fn signed_load_refuses_tampered_producer_state() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("feed.json");
        let key = SecretKey::from_seed([4u8; 32]);
        write_signed(&path, &serde_json::json!({"sequence": 1}), &key, "test").unwrap();
        let value: serde_json::Value = load_signed(&path, &key.public_key()).unwrap().unwrap();
        assert_eq!(value["sequence"], 1);

        std::fs::write(&path, br#"{"sequence":999}"#).unwrap();
        let err = load_signed::<serde_json::Value>(&path, &key.public_key()).unwrap_err();
        assert!(format!("{err:#}").contains("signature does not verify"));
    }
}
