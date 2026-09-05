//! A test rig: a fixture sysroot plus a fake pacman and sudo on PATH.

#![allow(dead_code)]

pub mod aur;
pub mod http;
pub mod tools;

use std::path::{Path, PathBuf};
use std::process::Command;

pub fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../alpm-db/fixtures")
}

pub struct Rig {
    pub dir: tempfile::TempDir,
    pub root: PathBuf,
    pub bin: PathBuf,
    pub log: PathBuf,
    pub home: PathBuf,
}

pub const DEFAULT_CONF: &str = "[options]\nArchitecture = x86_64\nSigLevel = Required DatabaseOptional\nHoldPkg = pacman glibc\n\
     [core]\nServer = https://m/$repo/os/$arch\n\
     [omarchy]\nServer = https://pkgs.omarchy.org/stable/$arch\n\
     [chaotic-aur]\nServer = https://example.invalid/$arch\nSigLevel = Never\n";

impl Rig {
    pub fn new() -> Rig {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("root");
        std::fs::create_dir_all(root.join("etc")).unwrap();
        std::fs::create_dir_all(root.join("var/lib/pacman/sync")).unwrap();
        std::fs::write(root.join("etc/pacman.conf"), DEFAULT_CONF).unwrap();
        copy_dir(
            &fixtures().join("local"),
            &root.join("var/lib/pacman/local"),
        );
        for db in ["core.db", "omarchy.db"] {
            std::fs::copy(
                fixtures().join("sync").join(db),
                root.join("var/lib/pacman/sync").join(db),
            )
            .unwrap();
        }
        let bin = dir.path().join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        for fake in ["pacman", "sudo"] {
            let target = bin.join(fake);
            std::fs::copy(
                Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("tests/fakes")
                    .join(fake),
                &target,
            )
            .unwrap();
            let mut perms = std::fs::metadata(&target).unwrap().permissions();
            std::os::unix::fs::PermissionsExt::set_mode(&mut perms, 0o755);
            std::fs::set_permissions(&target, perms).unwrap();
        }
        let home = dir.path().join("home");
        std::fs::create_dir_all(&home).unwrap();
        let log = dir.path().join("log");
        Rig {
            dir,
            root,
            bin,
            log,
            home,
        }
    }

    /// The user manifest path the rig's HOME maps to.
    pub fn user_manifest(&self) -> PathBuf {
        self.home.join(".config/pacvamp/pacvamp.toml")
    }

    /// Write a file under the sysroot.
    pub fn write_root(&self, path: &str, text: &str) {
        let full = self.root.join(path.trim_start_matches('/'));
        std::fs::create_dir_all(full.parent().unwrap()).unwrap();
        std::fs::write(full, text).unwrap();
    }

    pub fn run(&self, args: &[&str], print: &str, status: i32) -> (i32, String, String) {
        let output = Command::new(env!("CARGO_BIN_EXE_pacvamp"))
            .env("PATH", format!("{}:/usr/bin:/bin", self.bin.display()))
            .env("PACVAMP_TEST_PACMAN", self.bin.join("pacman"))
            .env("HOME", &self.home)
            .env("XDG_CACHE_HOME", self.home.join(".cache"))
            .env_remove("XDG_CONFIG_HOME")
            .env_remove("PACVAMP_MANAGED_CONFIG_PATH")
            .env("FAKE_PACMAN_LOG", &self.log)
            .env("FAKE_PACMAN_PRINT", print)
            .env("FAKE_PACMAN_STATUS", status.to_string())
            .arg("--sysroot")
            .arg(&self.root)
            .args(args)
            .output()
            .unwrap();
        (
            output.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&output.stdout).into_owned(),
            String::from_utf8_lossy(&output.stderr).into_owned(),
        )
    }

    pub fn log(&self) -> Vec<String> {
        std::fs::read_to_string(&self.log)
            .unwrap_or_default()
            .lines()
            .map(str::to_string)
            .collect()
    }

    /// Replace the rig's temporary paths in `text` for snapshots.
    pub fn redact(&self, text: &str) -> String {
        text.replace(self.bin.to_str().unwrap(), "<bin>")
            .replace(self.root.to_str().unwrap(), "<root>")
            .replace(self.home.to_str().unwrap(), "<home>")
    }
}

pub fn copy_dir(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for entry in std::fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let target = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_dir(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), target).unwrap();
        }
    }
}
