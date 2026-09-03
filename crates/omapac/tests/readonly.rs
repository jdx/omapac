//! The read-only commands against a fixture sysroot: Omarchy's pacman.conf,
//! the alpm-db local database fixture, and real core and omarchy sync
//! databases.

use std::path::{Path, PathBuf};
use std::process::Command;

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../alpm-db/fixtures")
}

/// Build a sysroot with the fixtures laid out where pacman expects them.
fn sysroot() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    std::fs::create_dir_all(root.join("etc/pacman.d")).unwrap();
    std::fs::create_dir_all(root.join("var/lib/pacman/sync")).unwrap();
    std::fs::write(
        root.join("etc/pacman.conf"),
        "[options]\nArchitecture = x86_64\nSigLevel = Required DatabaseOptional\n\
         [core]\nInclude = /etc/pacman.d/mirrorlist\n\
         [omarchy]\nServer = https://pkgs.omarchy.org/stable/$arch\n\
         [weak-db]\nServer = https://example.invalid/$arch\nSigLevel = PackageRequired DatabaseNever\n\
         [arch-mact2]\nServer = https://example.invalid/$arch\nSigLevel = Never\n",
    )
    .unwrap();
    std::fs::write(
        root.join("etc/pacman.d/mirrorlist"),
        "Server = https://stable-mirror.omarchy.org/$repo/os/$arch\n",
    )
    .unwrap();
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
    dir
}

fn copy_dir(from: &Path, to: &Path) {
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

fn omapac(root: &Path, args: &[&str]) -> (i32, String, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_omapac"))
        .arg("--sysroot")
        .arg(root)
        .args(args)
        .output()
        .unwrap();
    (
        output.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

#[test]
fn present_and_missing() {
    let root = sysroot();
    let root = root.path();
    assert_eq!(omapac(root, &["present", "pacman"]).0, 0);
    assert_eq!(omapac(root, &["present", "pacman>=7", "glibc"]).0, 0);
    assert_eq!(
        omapac(root, &["present", "libalpm.so=16-64"]).0,
        0,
        "by provision"
    );
    assert_eq!(omapac(root, &["present", "pacman", "helix"]).0, 1);
    assert_eq!(omapac(root, &["present", "pacman<7"]).0, 1);
    assert_eq!(omapac(root, &["missing", "helix", "zathura"]).0, 0);
    assert_eq!(omapac(root, &["missing", "helix", "pacman"]).0, 1);
}

#[test]
fn list_with_tiers_and_filters() {
    let root = sysroot();
    let (code, out, _) = omapac(root.path(), &["list"]);
    assert_eq!(code, 0);
    insta::assert_snapshot!(out);

    let (_, out, _) = omapac(root.path(), &["list", "--explicit"]);
    assert_eq!(out.lines().count(), 1);
    assert!(out.starts_with("pacman"));

    let (_, out, _) = omapac(root.path(), &["list", "--orphans"]);
    // glibc is a dependency that pacman depends on; yay is a dependency
    // nothing needs.
    assert_eq!(out.lines().count(), 1, "{out}");
    assert!(out.starts_with("yay"));

    let (_, out, _) = omapac(root.path(), &["list", "--foreign"]);
    assert!(out.is_empty(), "yay is carried by [omarchy]: {out}");

    let (_, out, _) = omapac(root.path(), &["list", "--json", "--native"]);
    let entries: Vec<serde_json::Value> = serde_json::from_str(&out).unwrap();
    assert_eq!(entries.len(), 3);
    assert_eq!(entries[2]["name"], "yay");
    assert_eq!(entries[2]["tier"]["tier"], "opr");
    assert_eq!(entries[0]["repo"], "core");
}

#[test]
fn search_by_terms() {
    let root = sysroot();
    let (code, out, _) = omapac(root.path(), &["search", "package", "manager"]);
    assert_eq!(code, 0);
    assert!(out.contains("core/pacman "), "{out}");
    assert!(out.contains("[installed: 7.1.0-2]"), "{out}");
    assert!(out.contains("[arch]"), "{out}");

    let (_, out, _) = omapac(root.path(), &["search", "--json", "yay"]);
    let hits: Vec<serde_json::Value> = serde_json::from_str(&out).unwrap();
    let yay = hits
        .iter()
        .find(|h| h["name"] == "yay")
        .expect("omarchy has yay");
    assert_eq!(yay["repo"], "omarchy");
    assert_eq!(yay["tier"]["tier"], "opr");
    assert_eq!(yay["installed"], "13.0.1-1");

    let (_, out, _) = omapac(root.path(), &["search", "--installed", "pacman"]);
    assert!(
        out.lines()
            .all(|l| !l.starts_with(char::is_alphabetic) || l.contains("[installed")),
        "{out}"
    );
}

#[test]
fn info_for_sync_and_installed_packages() {
    let root = sysroot();
    let (code, out, _) = omapac(root.path(), &["info", "pacman"]);
    assert_eq!(code, 0);
    assert!(out.contains("Repository       core [arch]"), "{out}");
    assert!(out.contains("Installed        7.1.0-2 (explicit)"), "{out}");
    assert!(out.contains("Signature        present"), "{out}");

    // --no-aur keeps the unknown name from falling through to the real
    // AUR over the network.
    let (code, out, err) = omapac(
        root.path(),
        &["info", "--no-aur", "glibc", "nonexistent-package"],
    );
    assert_eq!(code, 1);
    assert!(out.contains("Name             glibc"), "{out}");
    assert!(
        err.contains("package not found: nonexistent-package"),
        "{err}"
    );

    let (_, out, _) = omapac(root.path(), &["info", "--json", "yay"]);
    let infos: Vec<serde_json::Value> = serde_json::from_str(&out).unwrap();
    assert_eq!(infos[0]["repo"], "omarchy");
    assert_eq!(infos[0]["installed"]["reason"], "dependency");

    // Installed-only packages retain their local package base.
    std::fs::remove_file(root.path().join("var/lib/pacman/sync/omarchy.db")).unwrap();
    let (_, out, _) = omapac(root.path(), &["info", "--json", "--no-aur", "yay"]);
    let infos: Vec<serde_json::Value> = serde_json::from_str(&out).unwrap();
    assert_eq!(infos[0]["pkgbase"], "yay");
}

#[test]
fn doctor_reports_signature_floor_and_missing_databases() {
    let root = sysroot();
    let (code, out, _) = omapac(root.path(), &["doctor"]);
    // arch-mact2 has SigLevel = Never, which fails the floor.
    assert_eq!(code, 1, "{out}");
    assert!(
        out.contains("[arch-mact2] custom:arch-mact2 SigLevel = Never"),
        "{out}"
    );
    assert!(out.contains("packages are not signature-checked"), "{out}");
    assert!(
        out.contains("[weak-db] custom:weak-db SigLevel = Required DatabaseNever")
            && out.contains("weaker than the floor (Required DatabaseOptional)"),
        "{out}"
    );
    assert!(
        out.contains("[core] arch SigLevel = Required DatabaseOptional"),
        "{out}"
    );
    assert!(out.contains("has no sync database yet"), "{out}");
    assert!(out.contains("format 9, 3 packages"), "{out}");
    assert!(
        out.contains(&root.path().join("etc/pacman.conf").display().to_string()),
        "{out}"
    );

    let (_, out, _) = omapac(root.path(), &["doctor", "--json"]);
    let findings: Vec<serde_json::Value> = serde_json::from_str(&out).unwrap();
    assert!(
        findings
            .iter()
            .any(|f| f["check"] == "signatures" && f["status"] == "fail")
    );
}

#[test]
fn help_lists_the_commands() {
    let output = Command::new(env!("CARGO_BIN_EXE_omapac"))
        .arg("--help")
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&output.stdout);
    for command in [
        "doctor", "info", "list", "missing", "present", "search", "version",
    ] {
        assert!(text.contains(&format!("\n  {command}")), "{text}");
    }
}
