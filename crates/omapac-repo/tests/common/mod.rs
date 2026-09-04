//! Shared helpers for omapac-repo tests: a local HTTP server, fake
//! programs on a temp PATH, and test keys.

#![allow(dead_code)]

pub mod aur;
pub mod http;

use std::path::{Path, PathBuf};
use std::process::Command;

use packslip::minisign::SecretKey;

/// A temp dir with `bin/` holding the fakes and `FAKE_*` log files.
pub struct Rig {
    pub dir: tempfile::TempDir,
    pub bin: PathBuf,
    pub gpg_log: PathBuf,
}

impl Rig {
    pub fn new() -> Rig {
        let dir = tempfile::tempdir().unwrap();
        let bin = dir.path().join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        let fakes = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fakes");
        for entry in std::fs::read_dir(&fakes).unwrap() {
            let entry = entry.unwrap();
            let dest = bin.join(entry.file_name());
            std::fs::copy(entry.path(), &dest).unwrap();
            let mut perm = std::fs::metadata(&dest).unwrap().permissions();
            use std::os::unix::fs::PermissionsExt as _;
            perm.set_mode(0o755);
            std::fs::set_permissions(&dest, perm).unwrap();
        }
        let gpg_log = dir.path().join("gpg.log");
        Rig { dir, bin, gpg_log }
    }

    pub fn path(&self) -> &Path {
        self.dir.path()
    }

    /// Run omapac-repo with the fakes on PATH.
    pub fn run(&self, args: &[&str]) -> (i32, String, String) {
        self.run_env(args, &[])
    }

    pub fn run_env(&self, args: &[&str], env: &[(&str, &str)]) -> (i32, String, String) {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_omapac-repo"));
        cmd.current_dir(self.path())
            .env("PATH", format!("{}:/usr/bin:/bin", self.bin.display()))
            .env("FAKE_GPG_LOG", &self.gpg_log)
            .args(args);
        for (k, v) in env {
            cmd.env(k, v);
        }
        let output = cmd.output().unwrap();
        (
            output.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&output.stdout).into_owned(),
            String::from_utf8_lossy(&output.stderr).into_owned(),
        )
    }

    pub fn gpg_log(&self) -> Vec<String> {
        std::fs::read_to_string(&self.gpg_log)
            .unwrap_or_default()
            .lines()
            .map(str::to_string)
            .collect()
    }

    /// Write a deterministic key pair as `<name>.key` and `<name>.pub`.
    pub fn keygen(&self, name: &str, seed: u8) -> SecretKey {
        let key = SecretKey::from_seed([seed; 32]);
        std::fs::write(self.path().join(format!("{name}.key")), key.to_file()).unwrap();
        std::fs::write(
            self.path().join(format!("{name}.pub")),
            key.public_key().to_file(),
        )
        .unwrap();
        key
    }
}
