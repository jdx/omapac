//! `install` and `remove` driven through a fake pacman and a fake sudo on a
//! temporary PATH, against the same fixture sysroot the read-only tests use.

use std::path::{Path, PathBuf};
use std::process::Command;

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../alpm-db/fixtures")
}

struct Rig {
    _dir: tempfile::TempDir,
    root: PathBuf,
    bin: PathBuf,
    log: PathBuf,
}

impl Rig {
    fn new() -> Rig {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("root");
        std::fs::create_dir_all(root.join("etc")).unwrap();
        std::fs::create_dir_all(root.join("var/lib/pacman/sync")).unwrap();
        std::fs::write(
            root.join("etc/pacman.conf"),
            "[options]\nArchitecture = x86_64\nSigLevel = Required DatabaseOptional\nHoldPkg = pacman glibc\n\
             [core]\nServer = https://m/$repo/os/$arch\n\
             [omarchy]\nServer = https://pkgs.omarchy.org/stable/$arch\n\
             [chaotic-aur]\nServer = https://example.invalid/$arch\nSigLevel = Never\n",
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
        let log = dir.path().join("log");
        Rig {
            _dir: dir,
            root,
            bin,
            log,
        }
    }

    fn run(&self, args: &[&str], print: &str, status: i32) -> (i32, String, String) {
        let output = Command::new(env!("CARGO_BIN_EXE_omapac"))
            .env("PATH", format!("{}:/usr/bin:/bin", self.bin.display()))
            .env("OMAPAC_TEST_PACMAN", self.bin.join("pacman"))
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

    fn log(&self) -> Vec<String> {
        std::fs::read_to_string(&self.log)
            .unwrap_or_default()
            .lines()
            .map(str::to_string)
            .collect()
    }
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

const HELIX_PLAN: &str = "helix\\t26.03-1\\textra\\thttps://m/extra/os/x86_64/helix-26.03-1-x86_64.pkg.tar.zst\\t12000000\\n\
                          tree-sitter\\t0.26.0-1\\tcore\\thttps://m/core/os/x86_64/tree-sitter-0.26.0-1-x86_64.pkg.tar.zst\\t500000\\n";

#[test]
fn install_dry_run_shows_plan_and_command_without_running_pacman_for_real() {
    let rig = Rig::new();
    // pacman is in core; the fake resolves it to a helix-shaped plan.
    let (code, out, err) = rig.run(&["install", "--dry-run", "pacman"], HELIX_PLAN, 0);
    assert_eq!(code, 0, "{err}");
    insta::assert_snapshot!(
        out.replace(rig.bin.to_str().unwrap(), "<bin>")
            .replace(rig.root.to_str().unwrap(), "<root>")
    );
    let log = rig.log();
    assert_eq!(log.len(), 1, "only the --print call: {log:?}");
    assert!(log[0].contains("--print --print-format"), "{log:?}");
    assert!(log[0].contains("-S --noconfirm --print"), "{log:?}");
    assert!(log[0].ends_with("--needed -- pacman"), "{log:?}");
}

#[test]
fn install_yes_applies_through_sudo() {
    let rig = Rig::new();
    let (code, _, err) = rig.run(&["install", "-y", "core/pacman", "yay"], HELIX_PLAN, 0);
    assert_eq!(code, 0, "{err}");
    let log = rig.log();
    assert_eq!(log.len(), 3, "{log:?}");
    assert!(
        log[1].starts_with("sudo -n"),
        "non-interactive elevation: {log:?}"
    );
    assert!(
        log[2].ends_with("-S --noconfirm --needed -- core/pacman yay"),
        "{log:?}"
    );
}

#[test]
fn install_does_not_apply_removal_only_warnings() {
    let rig = Rig::new();
    let plan = "pacman\\t7.1.0-3\\tcore\\thttps://m/pacman.pkg\\t1\\n";
    let (code, out, err) = rig.run(&["install", "-y", "pacman"], plan, 0);
    assert_eq!(code, 0, "{err}\n{out}");
    assert!(!out.contains("HoldPkg"), "{out}");
}

#[test]
fn install_reports_a_failing_pacman() {
    let rig = Rig::new();
    let (code, _, err) = rig.run(&["install", "-y", "pacman"], HELIX_PLAN, 3);
    assert_ne!(code, 0);
    assert!(err.contains("exited with status 3"), "{err}");
}

#[test]
fn install_refuses_unknown_packages_before_touching_pacman() {
    let rig = Rig::new();
    let (code, _, err) = rig.run(&["install", "-y", "pacman", "not-a-package"], HELIX_PLAN, 0);
    assert_ne!(code, 0);
    assert!(
        err.contains("not in any repository: not-a-package"),
        "{err}"
    );
    assert!(rig.log().is_empty());
}

#[test]
fn unattended_install_refuses_warnings() {
    let rig = Rig::new();
    let plan = "foo\\t1-1\\tchaotic-aur\\thttps://x/foo.pkg\\t1\\n";
    let (code, out, err) = rig.run(&["install", "-y", "pacman"], plan, 0);
    assert_ne!(code, 0);
    assert!(out.contains("[custom:chaotic-aur]"), "{out}");
    assert!(out.contains("does not check package signatures"), "{out}");
    assert!(out.contains("does not check database signatures"), "{out}");
    assert!(out.contains("outside Arch and Omarchy review"), "{out}");
    assert!(
        err.contains("refusing to install unattended with 3 warning(s)"),
        "{err}"
    );
    assert_eq!(rig.log().len(), 1, "only the plan ran");

    let conf = std::fs::read_to_string(rig.root.join("etc/pacman.conf"))
        .unwrap()
        .replace(
            "[core]\nServer = https://m/$repo/os/$arch",
            "[core]\nServer = https://m/$repo/os/$arch\nSigLevel = Never",
        );
    std::fs::write(rig.root.join("etc/pacman.conf"), conf).unwrap();
    let calls = rig.log().len();
    let plan = "pacman\\t7.1.0-2\\tcore\\thttps://x/pacman.pkg\\t1\\n";
    let (code, out, _) = rig.run(&["install", "-y", "pacman"], plan, 0);
    assert_ne!(code, 0);
    assert!(
        out.contains("[core] does not check package signatures"),
        "{out}"
    );
    assert_eq!(rig.log().len(), calls + 1, "only the second plan ran");
}

#[test]
fn install_json_prints_the_plan() {
    let rig = Rig::new();
    let (code, out, _) = rig.run(&["install", "--json", "pacman"], HELIX_PLAN, 0);
    assert_eq!(code, 0);
    let plan: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(plan["changes"].as_array().unwrap().len(), 2);
    assert_eq!(plan["changes"][0]["tier"]["tier"], "arch");
    assert_eq!(plan["download_size"], 12_500_000);
    assert!(
        plan["command"]
            .as_str()
            .unwrap()
            .contains("-S --noconfirm --needed -- pacman")
    );
}

#[test]
fn remove_plans_with_hold_warning_and_applies() {
    let rig = Rig::new();
    let plan = "yay\\t13.0.1-1\\tlocal\\tyay-13.0.1-1\\t(null)\\n";
    let (code, out, _) = rig.run(&["remove", "--dry-run", "yay"], plan, 0);
    assert_eq!(code, 0);
    assert!(out.contains("remove 1 package(s):"), "{out}");
    assert!(out.contains("yay  13.0.1-1  [opr]"), "{out}");
    assert!(!out.contains("outside Arch and Omarchy review"), "{out}");
    assert!(!out.contains("does not check package signatures"), "{out}");
    assert!(out.contains("would run:"), "{out}");
    assert!(
        rig.log()[0].contains("-R --noconfirm --print"),
        "{:?}",
        rig.log()
    );

    let plan = "pacman\\t7.1.0-2\\tlocal\\tpacman-7.1.0-2\\t(null)\\n";
    let (code, out, err) = rig.run(&["remove", "-y", "--keep-deps", "pacman"], plan, 0);
    assert_ne!(code, 0, "HoldPkg is a warning, so -y refuses");
    assert!(out.contains("warning: HoldPkg: pacman"), "{out}");
    assert!(err.contains("refusing to remove unattended"), "{err}");

    let (code, out, err) = rig.run(&["remove", "--dry-run", "pacman"], plan, 0);
    assert_eq!(code, 0, "{err}\n{out}");
    let command = out
        .lines()
        .find(|line| line.starts_with("would run:"))
        .unwrap();
    assert!(!command.contains("--noconfirm"), "{command}");

    let (code, _, err) = rig.run(&["remove", "helix"], plan, 0);
    assert_ne!(code, 0);
    assert!(err.contains("not installed: helix"), "{err}");
}

#[test]
fn asking_without_a_terminal_is_an_error_not_a_hang() {
    let rig = Rig::new();
    let (code, _, err) = rig.run(&["install", "pacman"], HELIX_PLAN, 0);
    assert_ne!(code, 0);
    assert!(err.contains("no terminal to ask on; pass -y"), "{err}");
}
