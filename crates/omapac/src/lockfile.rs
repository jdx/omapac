//! `omapac.lock`: approved AUR commits and the evidence that was approved
//! with them, next to the user manifest and meant to be committed with
//! it. See `PLAN.md`, "Lockfile".

use std::collections::BTreeMap;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use eyre::{Context as _, Result};
use serde::{Deserialize, Serialize};

pub const VERSION: u32 = 1;

/// One approved AUR package.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AurEntry {
    /// The exact commit that was reviewed and may be built.
    pub commit: String,
    /// The version that commit builds, for display and drift checks.
    pub pkgver: String,
    /// Unix seconds.
    pub approved_at: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maintainer: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub source_hosts: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub install_files: Vec<String>,
    /// A digest of the findings that were acknowledged at approval.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub findings: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct Lockfile {
    #[serde(default = "version")]
    pub version: u32,
    #[serde(default)]
    pub aur: BTreeMap<String, AurEntry>,
}

fn version() -> u32 {
    VERSION
}

impl Lockfile {
    /// The lockfile beside a manifest.
    pub fn path_beside(manifest: &Path) -> PathBuf {
        manifest.with_file_name("omapac.lock")
    }

    pub fn load(path: &Path) -> Result<Lockfile> {
        match std::fs::read_to_string(path) {
            Ok(text) => {
                let lock: Lockfile = toml::from_str(&text)
                    .wrap_err_with(|| format!("parsing {}", path.display()))?;
                if lock.version > VERSION {
                    eyre::bail!(
                        "{} is version {}, newer than this omapac understands ({VERSION})",
                        path.display(),
                        lock.version
                    );
                }
                Ok(lock)
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(Lockfile {
                version: VERSION,
                aur: BTreeMap::new(),
            }),
            Err(err) => Err(err).wrap_err_with(|| format!("reading {}", path.display())),
        }
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .wrap_err_with(|| format!("creating {}", parent.display()))?;
        }
        let mut lock = self.clone();
        lock.version = VERSION;
        let text = toml::to_string_pretty(&lock).wrap_err("serialising the lockfile")?;
        let parent = path.parent().unwrap_or_else(|| Path::new("."));
        static NEXT_TEMP: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let temp_path = parent.join(format!(
            ".omapac.lock.tmp-{}-{}",
            std::process::id(),
            NEXT_TEMP.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        let result = (|| -> std::io::Result<()> {
            let mut temp = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&temp_path)?;
            temp.write_all(text.as_bytes())?;
            temp.sync_all()?;
            std::fs::rename(&temp_path, path)
        })();
        if let Err(err) = result {
            let _ = std::fs::remove_file(&temp_path);
            return Err(err).wrap_err_with(|| format!("publishing {}", path.display()));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_and_defaults() {
        let dir = tempfile::tempdir().unwrap();
        let manifest = dir.path().join("omapac.toml");
        let path = Lockfile::path_beside(&manifest);
        assert_eq!(path, dir.path().join("omapac.lock"));
        let lock = Lockfile::load(&path).unwrap();
        assert!(lock.aur.is_empty());

        let mut lock = lock;
        lock.aur.insert(
            "google-chrome".into(),
            AurEntry {
                commit: "a".repeat(40),
                pkgver: "152.0.7977.75-1".into(),
                approved_at: 1_756_800_000,
                maintainer: Some("gromit".into()),
                source_hosts: vec!["dl.google.com".into()],
                install_files: vec!["google-chrome.install".into()],
                findings: None,
            },
        );
        lock.save(&path).unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.starts_with("version = 1\n"), "{text}");
        assert!(text.contains("[aur.google-chrome]"), "{text}");
        assert!(!text.contains("findings"), "{text}");
        assert_eq!(Lockfile::load(&path).unwrap(), lock);

        std::fs::write(&path, "version = 9\n").unwrap();
        assert!(Lockfile::load(&path).is_err());
    }
}
