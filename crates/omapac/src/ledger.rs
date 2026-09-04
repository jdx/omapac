//! The ledger: what omapac did, as opposed to what the manifest says.
//! `/var/lib/omapac/state.json`, root-owned, schema-versioned, written
//! atomically. See `PLAN.md`, "Ledger".
//!
//! Writes happen after a transaction. omapac runs as the invoking user, so
//! a write is attempted directly and, when the directory refuses it,
//! repeated through an elevated re-invocation of omapac's hidden
//! `__ledger` command with the patch on stdin. Reads never elevate.

use std::collections::BTreeMap;
use std::io::{self, Write as _};
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};

use eyre::{Context as _, Result, bail};
use serde::{Deserialize, Serialize};

use crate::engine::sudo::{Context, Elevation, Invocation};
use crate::resolve::Tier;

pub const SCHEMA: u32 = 1;
pub const DEFAULT_PATH: &str = "/var/lib/omapac/state.json";

/// One package omapac installed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    pub version: String,
    pub tier: Tier,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repo: Option<String>,
    /// The AUR commit that was built, for AUR packages.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aur_commit: Option<String>,
    /// Whether the user asked for it, as opposed to a dependency pulled in.
    pub explicit: bool,
    /// Which command recorded it: install, add, apply, update.
    pub by: String,
    /// Unix seconds.
    pub at: i64,
}

/// The ledger file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ledger {
    #[serde(default = "schema")]
    pub schema: u32,
    #[serde(default)]
    pub packages: BTreeMap<String, Entry>,
    /// The newest signed index sequence seen, for rollback detection.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub index_sequence: Option<u64>,
    /// The snapshot id the machine last converged to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snapshot: Option<String>,
}

fn schema() -> u32 {
    SCHEMA
}

impl Default for Ledger {
    fn default() -> Self {
        Self {
            schema: SCHEMA,
            packages: BTreeMap::new(),
            index_sequence: None,
            snapshot: None,
        }
    }
}

/// A change to merge into the ledger.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct Patch {
    #[serde(default)]
    pub upsert: BTreeMap<String, Entry>,
    #[serde(default)]
    pub remove: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub index_sequence: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snapshot: Option<String>,
}

impl Patch {
    pub fn is_empty(&self) -> bool {
        self.upsert.is_empty()
            && self.remove.is_empty()
            && self.index_sequence.is_none()
            && self.snapshot.is_none()
    }
}

impl Ledger {
    /// The ledger path, under `sysroot` when given.
    pub fn path(sysroot: Option<&Path>) -> PathBuf {
        match sysroot {
            Some(root) => root.join(DEFAULT_PATH.trim_start_matches('/')),
            None => PathBuf::from(DEFAULT_PATH),
        }
    }

    /// Read the ledger; a missing file is an empty ledger.
    pub fn load(path: &Path) -> Result<Ledger> {
        match std::fs::read_to_string(path) {
            Ok(text) => {
                let ledger: Ledger = serde_json::from_str(&text)
                    .wrap_err_with(|| format!("parsing {}", path.display()))?;
                if ledger.schema > SCHEMA {
                    bail!(
                        "{} is schema {}, newer than this omapac understands ({SCHEMA})",
                        path.display(),
                        ledger.schema
                    );
                }
                Ok(ledger)
            }
            Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(Ledger {
                schema: SCHEMA,
                ..Default::default()
            }),
            Err(err) => Err(err).wrap_err_with(|| format!("reading {}", path.display())),
        }
    }

    /// Apply a patch in memory.
    pub fn merge(&mut self, patch: &Patch) {
        for name in &patch.remove {
            self.packages.remove(name);
        }
        for (name, entry) in &patch.upsert {
            let mut entry = entry.clone();
            if let Some(existing) = self.packages.get(name)
                && existing.explicit
                && !entry.explicit
            {
                entry.explicit = true;
                entry.by = existing.by.clone();
                entry.at = existing.at;
            }
            self.packages.insert(name.clone(), entry);
        }
        if let Some(sequence) = patch.index_sequence {
            self.index_sequence = Some(self.index_sequence.unwrap_or(0).max(sequence));
        }
        if let Some(snapshot) = &patch.snapshot {
            self.snapshot = Some(snapshot.clone());
        }
        self.schema = SCHEMA;
    }

    /// Write atomically: a sibling temp file, then rename.
    pub fn save(&self, path: &Path) -> io::Result<()> {
        let dir = path.parent().unwrap_or(Path::new("."));
        std::fs::create_dir_all(dir)?;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o755))?;
        let temp = dir.join(format!(
            ".{}.tmp-{}",
            path.file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("state.json"),
            std::process::id()
        ));
        let mut json = serde_json::to_vec_pretty(self).map_err(io::Error::other)?;
        json.push(b'\n');
        {
            let mut file = std::fs::File::create(&temp)?;
            file.write_all(&json)?;
            file.sync_all()?;
        }
        std::fs::set_permissions(&temp, std::fs::Permissions::from_mode(0o644))?;
        if let Err(err) = std::fs::rename(&temp, path) {
            let _ = std::fs::remove_file(&temp);
            return Err(err);
        }
        Ok(())
    }
}

/// Load, merge, save. Fails with the I/O error when the path is not
/// writable by this process.
pub fn merge_into(path: &Path, patch: &Patch) -> Result<Ledger> {
    let _lock =
        LedgerLock::acquire(path).wrap_err_with(|| format!("locking {}", path.display()))?;
    let mut ledger = Ledger::load(path)?;
    ledger.merge(patch);
    ledger
        .save(path)
        .wrap_err_with(|| format!("writing {}", path.display()))?;
    Ok(ledger)
}

struct LedgerLock {
    _file: std::fs::File,
}

impl LedgerLock {
    fn acquire(ledger: &Path) -> io::Result<LedgerLock> {
        let mut name = ledger.as_os_str().to_owned();
        name.push(".lock");
        let path = PathBuf::from(name);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)?;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        loop {
            match file.try_lock() {
                Ok(()) => return Ok(LedgerLock { _file: file }),
                Err(std::fs::TryLockError::WouldBlock) => {
                    if std::time::Instant::now() >= deadline {
                        return Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            format!("timed out waiting for {}", path.display()),
                        ));
                    }
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
                Err(std::fs::TryLockError::Error(err)) => return Err(err),
            }
        }
    }
}

/// Record `patch`, elevating through omapac's `__ledger` command when the
/// ledger directory refuses a direct write.
pub fn record(path: &Path, sysroot: Option<&Path>, patch: &Patch) -> Result<()> {
    if patch.is_empty() {
        return Ok(());
    }
    let denied = match merge_into(path, patch) {
        Ok(_) => return Ok(()),
        Err(err) => {
            let permission = err
                .chain()
                .filter_map(|e| e.downcast_ref::<io::Error>())
                .any(|e| e.kind() == io::ErrorKind::PermissionDenied);
            if !permission {
                return Err(err);
            }
            err
        }
    };
    let exe = std::env::current_exe().wrap_err("locating omapac")?;
    let mut args = Vec::new();
    if let Some(root) = sysroot {
        args.push("--sysroot".to_string());
        args.push(root.to_string_lossy().into_owned());
    }
    args.push("__ledger".to_string());
    let ctx = Context::detect(Elevation::Auto);
    if ctx.is_root {
        return Err(denied);
    }
    let invocation = Invocation::new(exe, args).elevated(&ctx)?;
    let command = invocation.display();
    let mut child = invocation
        .command()
        .stdin(std::process::Stdio::piped())
        .spawn()
        .wrap_err_with(|| format!("running `{command}`"))?;
    if let Some(mut stdin) = child.stdin.take() {
        serde_json::to_writer(&mut stdin, patch)?;
    }
    let status = child.wait()?;
    if !status.success() {
        bail!(
            "`{command}` exited with status {}",
            status.code().unwrap_or(-1)
        );
    }
    Ok(())
}

/// Unix seconds now.
pub fn now() -> i64 {
    jiff::Timestamp::now().as_second()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(version: &str) -> Entry {
        Entry {
            version: version.to_string(),
            tier: Tier::Arch,
            repo: Some("core".into()),
            aur_commit: None,
            explicit: true,
            by: "install".into(),
            at: 1_756_800_000,
        }
    }

    #[test]
    fn load_merge_save_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("var/lib/omapac/state.json");
        assert_eq!(Ledger::default().schema, SCHEMA);
        let ledger = Ledger::load(&path).unwrap();
        assert_eq!(ledger.schema, SCHEMA);
        assert!(ledger.packages.is_empty());

        let mut patch = Patch::default();
        patch.upsert.insert("curl".into(), entry("8.0-1"));
        patch.index_sequence = Some(7);
        merge_into(&path, &patch).unwrap();

        let mut patch = Patch::default();
        patch.upsert.insert("curl".into(), entry("8.1-1"));
        patch.upsert.insert("helix".into(), entry("26.03-1"));
        patch.remove.push("helix".into());
        patch.index_sequence = Some(5);
        patch.snapshot = Some("2026-09-03T06".into());
        let ledger = merge_into(&path, &patch).unwrap();
        assert_eq!(ledger.packages.len(), 2, "removes apply before upserts");
        assert_eq!(ledger.packages["curl"].version, "8.1-1");
        assert_eq!(
            ledger.index_sequence,
            Some(7),
            "sequence never goes backwards"
        );
        assert_eq!(ledger.snapshot.as_deref(), Some("2026-09-03T06"));

        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.ends_with("}\n"));
        assert!(!text.contains("aur_commit"), "absent fields are omitted");
        assert_eq!(
            std::fs::metadata(path.parent().unwrap())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o755
        );
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o644
        );
        assert!(
            std::fs::read_dir(path.parent().unwrap())
                .unwrap()
                .all(|e| matches!(
                    e.unwrap().file_name().to_str(),
                    Some("state.json" | "state.json.lock")
                )),
            "no temp files left"
        );
    }

    #[test]
    fn dependency_updates_preserve_explicit_provenance() {
        let mut ledger = Ledger::default();
        ledger.packages.insert("curl".into(), entry("8.0-1"));
        let mut dependency = entry("8.1-1");
        dependency.explicit = false;
        dependency.by = "install dependency".into();
        dependency.at += 10;
        let mut patch = Patch::default();
        patch.upsert.insert("curl".into(), dependency);

        ledger.merge(&patch);

        let curl = &ledger.packages["curl"];
        assert_eq!(curl.version, "8.1-1");
        assert!(curl.explicit);
        assert_eq!(curl.by, "install");
        assert_eq!(curl.at, 1_756_800_000);
    }

    #[test]
    fn concurrent_merges_do_not_drop_entries() {
        let dir = tempfile::tempdir().unwrap();
        let path = std::sync::Arc::new(dir.path().join("state.json"));
        let start = std::sync::Arc::new(std::sync::Barrier::new(12));
        let threads: Vec<_> = (0..12)
            .map(|i| {
                let path = path.clone();
                let start = start.clone();
                std::thread::spawn(move || {
                    let mut patch = Patch::default();
                    patch.upsert.insert(format!("package-{i}"), entry("1-1"));
                    patch.index_sequence = Some(i);
                    start.wait();
                    merge_into(&path, &patch).unwrap();
                })
            })
            .collect();
        for thread in threads {
            thread.join().unwrap();
        }
        let ledger = Ledger::load(&path).unwrap();
        assert_eq!(ledger.packages.len(), 12);
        assert_eq!(ledger.index_sequence, Some(11));
    }

    #[test]
    fn an_empty_lock_file_left_by_a_crash_does_not_block() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        std::fs::write(dir.path().join("state.json.lock"), []).unwrap();
        let mut patch = Patch::default();
        patch.upsert.insert("curl".into(), entry("8.0-1"));
        merge_into(&path, &patch).unwrap();
        assert!(Ledger::load(&path).unwrap().packages.contains_key("curl"));
    }

    #[test]
    fn newer_schema_is_refused_and_junk_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        std::fs::write(&path, r#"{"schema": 99}"#).unwrap();
        let err = Ledger::load(&path).unwrap_err().to_string();
        assert!(err.contains("schema 99"), "{err}");
        std::fs::write(&path, "nope").unwrap();
        assert!(Ledger::load(&path).is_err());
    }

    #[test]
    fn record_writes_directly_when_it_can() {
        let dir = tempfile::tempdir().unwrap();
        let path = Ledger::path(Some(dir.path()));
        let mut patch = Patch::default();
        patch.upsert.insert("curl".into(), entry("8.0-1"));
        record(&path, Some(dir.path()), &patch).unwrap();
        assert_eq!(Ledger::load(&path).unwrap().packages.len(), 1);
        record(&path, Some(dir.path()), &Patch::default()).unwrap();
    }
}
