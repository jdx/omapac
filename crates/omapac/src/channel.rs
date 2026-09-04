//! The release train from the client's side: the signed `release.json`
//! that says which snapshot a channel points at and what was tested, and
//! pinning a machine's mirror to an immutable snapshot. See
//! `docs/spec/release-train.md` and `PLAN.md`, "Release train".

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use eyre::{Context as _, Result, bail};
use serde::{Deserialize, Serialize};

/// `release.json`: one snapshot's manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Release {
    pub version: u32,
    /// The snapshot id, `YYYY-MM-DDTHH`.
    pub id: String,
    pub channel: String,
    /// The Arch mirror snapshot this release was built from.
    pub arch_snapshot: String,
    /// The OPR index sequence that goes with it.
    pub opr_index_sequence: u64,
    pub created_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tests: Option<Tests>,
    /// The pkgbases the suite exercised; everything else is consistent but
    /// not tested.
    #[serde(default)]
    pub tested_pkgbases: Vec<String>,
    #[serde(default)]
    pub promoted: Promoted,
    #[serde(default)]
    pub expedited: bool,
    #[serde(default)]
    pub held: bool,
    /// Digests of the Arch database files at this snapshot, by repository.
    #[serde(default)]
    pub db_digests: std::collections::BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tests {
    pub suite: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commit: Option<String>,
    pub result: TestResult,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub log_url: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TestResult {
    Pass,
    Fail,
    Pending,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct Promoted {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rc: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stable: Option<String>,
}

impl Release {
    /// Whether a package is in the tested set.
    pub fn is_tested(&self, pkgbase: &str) -> bool {
        self.tested_pkgbases.iter().any(|p| p == pkgbase)
    }

    /// Whether this snapshot ever reached `rc` or `stable`, which is what
    /// rollback requires without `--force`.
    pub fn was_promoted(&self) -> bool {
        self.promoted.rc.is_some() || self.promoted.stable.is_some()
    }
}

/// The channel a repository server URL names: the path segment before
/// `$arch` in `.../stable/x86_64`.
pub fn channel_of_url(url: &str) -> Option<String> {
    let path = url.split("://").nth(1)?.split('/').skip(1);
    let parts: Vec<&str> = path.collect();
    for name in ["stable", "rc", "edge", "dev"] {
        if parts.contains(&name) {
            return Some(name.to_string());
        }
    }
    None
}

/// The mirrorlist pacman reads for the official repositories.
pub const MIRRORLIST: &str = "/etc/pacman.d/mirrorlist";
const BACKUP_SUFFIX: &str = ".omapac-unpinned";

/// The `Server` line that pins to a snapshot.
pub fn pinned_server(snapshot_base: &str, id: &str) -> String {
    format!(
        "Server = {}/{id}/$repo/os/$arch",
        snapshot_base.trim_end_matches('/')
    )
}

/// The pin currently written to the mirrorlist, if any.
pub fn current_pin(mirrorlist: &Path) -> Option<String> {
    let text = std::fs::read_to_string(mirrorlist).ok()?;
    text.lines().find_map(|line| {
        line.strip_prefix("# omapac-pin: ")
            .map(|id| id.trim().to_string())
    })
}

/// The mirrorlist text that pins to `id`, and the backup path.
pub fn pin_text(snapshot_base: &str, id: &str) -> String {
    format!(
        "# Written by omapac channel pin; `omapac channel unpin` restores the previous list.\n# omapac-pin: {id}\n{}\n",
        pinned_server(snapshot_base, id)
    )
}

pub fn backup_path(mirrorlist: &Path) -> PathBuf {
    let mut name = mirrorlist.as_os_str().to_owned();
    name.push(BACKUP_SUFFIX);
    PathBuf::from(name)
}

/// Write `contents` to `path`, keeping a one-time backup of the original
/// when `backup` is set and none exists yet. Elevates through omapac's
/// hidden `__write` command when the directory refuses a direct write.
pub fn write_privileged(
    path: &Path,
    contents: &str,
    backup: bool,
    sysroot: Option<&Path>,
) -> Result<()> {
    let request = WriteRequest {
        path: path.to_path_buf(),
        contents: contents.to_string(),
        backup,
        remove_backup: false,
    };
    apply_privileged(request, sysroot)
}

/// Restore `path` and remove the one-time backup in the same privileged
/// request, so a later pin captures the newly current mirrorlist.
pub fn restore_privileged(path: &Path, contents: &str, sysroot: Option<&Path>) -> Result<()> {
    apply_privileged(
        WriteRequest {
            path: path.to_path_buf(),
            contents: contents.to_string(),
            backup: false,
            remove_backup: true,
        },
        sysroot,
    )
}

fn apply_privileged(request: WriteRequest, sysroot: Option<&Path>) -> Result<()> {
    match request.apply(sysroot) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => {
            let ctx = crate::engine::sudo::Context::detect(crate::engine::sudo::Elevation::Auto);
            if ctx.is_root {
                return Err(err).wrap_err_with(|| format!("writing {}", request.path.display()));
            }
            let exe = std::env::current_exe().wrap_err("locating omapac")?;
            let mut args = Vec::new();
            if let Some(root) = sysroot {
                args.push("--sysroot".to_string());
                args.push(root.to_string_lossy().into_owned());
            }
            args.push("__write".to_string());
            let invocation = crate::engine::sudo::Invocation::new(exe, args).elevated(&ctx)?;
            let command = invocation.display();
            let mut child = invocation
                .command()
                .stdin(std::process::Stdio::piped())
                .spawn()
                .wrap_err_with(|| format!("running `{command}`"))?;
            if let Some(mut stdin) = child.stdin.take() {
                serde_json::to_writer(&mut stdin, &request)?;
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
        Err(err) => Err(err).wrap_err_with(|| format!("writing {}", request.path.display())),
    }
}

/// A privileged file write, restricted to pacman's configuration directory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WriteRequest {
    pub path: PathBuf,
    pub contents: String,
    pub backup: bool,
    #[serde(default)]
    pub remove_backup: bool,
}

impl WriteRequest {
    /// Perform the write. Only paths under `/etc/pacman.d` (under any
    /// sysroot) are accepted, so the elevated helper cannot be turned into
    /// a general root file writer.
    pub fn apply(&self, sysroot: Option<&Path>) -> std::io::Result<()> {
        let allowed = sysroot
            .map(|root| root.join("etc/pacman.d"))
            .unwrap_or_else(|| PathBuf::from("/etc/pacman.d"));
        if std::fs::symlink_metadata(&allowed)
            .is_ok_and(|metadata| metadata.file_type().is_symlink())
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("{} must not be a symlink", allowed.display()),
            ));
        }
        let allowed = std::fs::canonicalize(&allowed)?;
        let parent = self
            .path
            .parent()
            .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::PermissionDenied))?;
        let parent = std::fs::canonicalize(parent)?;
        let target_is_symlink = std::fs::symlink_metadata(&self.path)
            .is_ok_and(|metadata| metadata.file_type().is_symlink());
        if !parent.starts_with(&allowed) || target_is_symlink {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("{} is outside /etc/pacman.d", self.path.display()),
            ));
        }
        let backup = backup_path(&self.path);
        if self.backup || self.remove_backup {
            if std::fs::symlink_metadata(&backup)
                .is_ok_and(|metadata| metadata.file_type().is_symlink())
            {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("{} must not be a symlink", backup.display()),
                ));
            }
            if self.backup && !backup.exists() && self.path.exists() {
                let original = std::fs::read(&self.path)?;
                let permissions = std::fs::metadata(&self.path)?.permissions();
                atomic_write(&backup, &original, Some(permissions))?;
            }
        }
        let permissions = std::fs::metadata(&self.path)
            .ok()
            .map(|metadata| metadata.permissions());
        atomic_write(&self.path, self.contents.as_bytes(), permissions)?;
        if self.remove_backup {
            match std::fs::remove_file(backup) {
                Ok(()) => {}
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                Err(err) => return Err(err),
            }
        }
        Ok(())
    }
}

static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

fn atomic_write(
    path: &Path,
    contents: &[u8],
    permissions: Option<std::fs::Permissions>,
) -> std::io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
    let temp = parent.join(format!(
        ".omapac-write-{}-{}",
        std::process::id(),
        NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
    ));
    let result = (|| {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp)?;
        file.write_all(contents)?;
        if let Some(permissions) = permissions {
            file.set_permissions(permissions)?;
        }
        file.sync_all()?;
        std::fs::rename(&temp, path)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temp);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn channels_from_urls() {
        assert_eq!(
            channel_of_url("https://pkgs.omarchy.org/stable/x86_64"),
            Some("stable".into())
        );
        assert_eq!(
            channel_of_url("https://pkgs.omarchy.org/edge/$arch"),
            Some("edge".into())
        );
        assert_eq!(channel_of_url("https://mirror.example/x86_64"), None);
    }

    #[test]
    fn pin_text_and_backup() {
        let text = pin_text("https://mirror.omarchy.org/snapshots/", "2026-09-03T06");
        assert!(text.contains("# omapac-pin: 2026-09-03T06\n"));
        assert!(text.contains(
            "Server = https://mirror.omarchy.org/snapshots/2026-09-03T06/$repo/os/$arch\n"
        ));
        assert_eq!(
            backup_path(Path::new("/etc/pacman.d/mirrorlist")),
            PathBuf::from("/etc/pacman.d/mirrorlist.omapac-unpinned")
        );
        let dir = tempfile::tempdir().unwrap();
        let etc = dir.path().join("etc/pacman.d");
        std::fs::create_dir_all(&etc).unwrap();
        let mirrorlist = etc.join("mirrorlist");
        std::fs::write(&mirrorlist, "Server = https://orig/$repo/os/$arch\n").unwrap();
        assert_eq!(current_pin(&mirrorlist), None);
        WriteRequest {
            path: mirrorlist.clone(),
            contents: text.clone(),
            backup: true,
            remove_backup: false,
        }
        .apply(Some(dir.path()))
        .unwrap();
        assert_eq!(current_pin(&mirrorlist).as_deref(), Some("2026-09-03T06"));
        assert_eq!(
            std::fs::read_to_string(backup_path(&mirrorlist)).unwrap(),
            "Server = https://orig/$repo/os/$arch\n"
        );
        // A second pin keeps the first backup.
        WriteRequest {
            path: mirrorlist.clone(),
            contents: pin_text("https://m", "2026-09-04T06"),
            backup: true,
            remove_backup: false,
        }
        .apply(Some(dir.path()))
        .unwrap();
        assert!(
            std::fs::read_to_string(backup_path(&mirrorlist))
                .unwrap()
                .contains("orig")
        );

        let outside = dir.path().join("outside");
        std::fs::write(&outside, "keep").unwrap();
        let backup = backup_path(&mirrorlist);
        std::fs::remove_file(&backup).unwrap();
        std::os::unix::fs::symlink(&outside, &backup).unwrap();
        let err = WriteRequest {
            path: mirrorlist.clone(),
            contents: "changed".into(),
            backup: true,
            remove_backup: false,
        }
        .apply(Some(dir.path()))
        .unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        assert_eq!(std::fs::read_to_string(outside).unwrap(), "keep");
        let outside = WriteRequest {
            path: dir.path().join("etc/passwd"),
            contents: String::new(),
            backup: false,
            remove_backup: false,
        };
        assert!(outside.apply(Some(dir.path())).is_err());
    }

    #[test]
    fn release_parses() {
        let release: Release = serde_json::from_str(
            r#"{"version":1,"id":"2026-09-03T06","channel":"stable","arch_snapshot":"2026-09-03T06","opr_index_sequence":1042,
                "created_at":"2026-09-03T06:00:00Z","tests":{"suite":"omarchy-train","result":"pass"},
                "tested_pkgbases":["hyprland","omarchy"],"promoted":{"rc":"2026-09-03T08:00:00Z"},"db_digests":{"core":"aa"}}"#,
        )
        .unwrap();
        assert!(release.is_tested("hyprland"));
        assert!(!release.is_tested("helix"));
        assert!(release.was_promoted());
        assert_eq!(release.tests.unwrap().result, TestResult::Pass);
    }
}
