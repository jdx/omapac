//! `aur build` and `install --aur` through a fake makepkg and pacman,
//! against the fake AUR remote and replayed RPC responses.

mod common;

use std::path::Path;
use std::process::Command;

use common::Rig;
use common::aur::{FakeAur, YAY_PKGBUILD, YAY_SRCINFO};

const INFO: &str = include_str!("../fixtures/aur/info.json");

struct Setup {
    rig: Rig,
    aur: FakeAur,
    rpc: String,
}

fn setup() -> Setup {
    let rig = Rig::new();
    let makepkg = rig.bin.join("makepkg");
    std::fs::copy(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fakes/makepkg"),
        &makepkg,
    )
    .unwrap();
    let mut perms = std::fs::metadata(&makepkg).unwrap().permissions();
    std::os::unix::fs::PermissionsExt::set_mode(&mut perms, 0o755);
    std::fs::set_permissions(&makepkg, perms).unwrap();
    let bsdtar = rig.bin.join("bsdtar");
    std::fs::copy(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fakes/bsdtar"),
        &bsdtar,
    )
    .unwrap();
    let mut perms = std::fs::metadata(&bsdtar).unwrap().permissions();
    std::os::unix::fs::PermissionsExt::set_mode(&mut perms, 0o755);
    std::fs::set_permissions(&bsdtar, perms).unwrap();
    let aur = FakeAur::new(rig.dir.path());
    aur.create(
        "yay",
        &[("PKGBUILD", YAY_PKGBUILD), (".SRCINFO", YAY_SRCINFO)],
        "2026-01-01T00:00:00Z",
    );
    let rpc = common::http::serve(vec![("/rpc/v5/info", INFO.to_string())]);
    Setup { rig, aur, rpc }
}

fn run(s: &Setup, args: &[&str], print: &str) -> (i32, String, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_omapac"))
        .env("PATH", format!("{}:/usr/bin:/bin", s.rig.bin.display()))
        .env("HOME", &s.rig.home)
        .env_remove("XDG_CONFIG_HOME")
        .env("XDG_CACHE_HOME", s.rig.dir.path().join("cache"))
        .env("OMAPAC_AUR_RPC_BASE", &s.rpc)
        .env("OMAPAC_AUR_GIT_BASE", s.aur.base())
        .env("FAKE_PACMAN_LOG", &s.rig.log)
        .env("FAKE_PACMAN_PRINT", print)
        .env("GITHUB_TOKEN", "hunter2")
        .arg("--sysroot")
        .arg(&s.rig.root)
        .args(args)
        .output()
        .unwrap();
    (
        output.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

/// The user manifest that turns the jail off, since the fake makepkg is a
/// bash script that needs to write its log outside the build directory.
fn no_jail(s: &Setup) {
    std::fs::create_dir_all(s.rig.home.join(".config/omapac")).unwrap();
    std::fs::write(
        s.rig.home.join(".config/omapac/omapac.toml"),
        "[policy]\naur.jail = false\n",
    )
    .unwrap();
}

#[test]
fn build_runs_both_phases_with_a_scrubbed_environment() {
    let s = setup();
    no_jail(&s);
    let split = format!("{YAY_SRCINFO}\npkgname = yay-docs\n\tdepends = yay\n");
    s.aur.commit(
        "yay",
        &[(".SRCINFO", &split)],
        "add sibling package",
        "2026-01-02T00:00:00Z",
    );
    run(&s, &["aur", "approve", "-y", "yay"], "");
    let (code, out, err) = run(&s, &["aur", "build", "yay"], "");
    assert_eq!(code, 0, "{err}");
    assert!(out.contains("yay-13.0.1-1-x86_64.pkg.tar.zst"), "{out}");
    let log = s.rig.log();
    let makepkg: Vec<&String> = log.iter().filter(|l| l.starts_with("makepkg")).collect();
    assert_eq!(
        makepkg[0], "makepkg --verifysource --noconfirm --force",
        "{log:?}"
    );
    assert_eq!(
        makepkg[1], "makepkg --noconfirm --force --holdver",
        "{log:?}"
    );
    assert_eq!(makepkg[2], "makepkg --packagelist", "{log:?}");
    assert!(
        log.contains(&"env GITHUB_TOKEN=unset".to_string()),
        "scrubbed: {log:?}"
    );
    let pkg = s
        .rig
        .dir
        .path()
        .join("cache/omapac/aur/.omapac-build/pkgs/yay/yay-13.0.1-1-x86_64.pkg.tar.zst");
    assert!(pkg.exists(), "{}", pkg.display());
    assert!(
        s.rig
            .dir
            .path()
            .join("cache/omapac/aur/.omapac-build/build/yay/worktree/PKGBUILD")
            .is_file()
    );
}

#[test]
fn build_requires_approval_unattended() {
    let s = setup();
    no_jail(&s);
    let (code, _, err) = run(&s, &["aur", "build", "yay"], "");
    assert_ne!(code, 0);
    assert!(err.contains("not approved"), "{err}");
    assert!(s.rig.log().iter().all(|l| !l.starts_with("makepkg")));
}

#[test]
fn install_without_yes_requires_a_terminal_confirmation() {
    let s = setup();
    no_jail(&s);
    run(&s, &["aur", "approve", "-y", "yay"], "");
    let (code, _, err) = run(&s, &["install", "--aur", "yay"], "");
    assert_ne!(code, 0);
    assert!(err.contains("no terminal to ask on; pass -y"), "{err}");
    assert!(s.rig.log().iter().all(|line| !line.contains("-U")));
}

#[test]
fn install_aur_builds_then_installs_the_file_and_records_the_commit() {
    let s = setup();
    no_jail(&s);
    run(&s, &["aur", "approve", "-y", "yay"], "");
    let (code, out, err) = run(&s, &["install", "--aur", "-y", "yay"], "");
    assert_eq!(code, 0, "{err}\n{out}");
    let log = s.rig.log();
    let last = log
        .iter()
        .rev()
        .find(|l| !l.starts_with("makepkg") && !l.starts_with("env"))
        .unwrap();
    assert!(
        last.contains("-U --noconfirm -- ") && last.ends_with("yay-13.0.1-1-x86_64.pkg.tar.zst"),
        "{log:?}"
    );
    let ledger = std::fs::read_to_string(s.rig.root.join("var/lib/omapac/state.json")).unwrap();
    let state: serde_json::Value = serde_json::from_str(&ledger).unwrap();
    assert_eq!(state["packages"]["yay"]["tier"]["tier"], "aur");
    assert_eq!(state["packages"]["yay"]["aur_commit"], s.aur.head("yay"));
    assert_eq!(state["packages"]["yay"]["by"], "install");
}

#[test]
fn install_aur_only_installs_the_requested_split_package() {
    let s = setup();
    no_jail(&s);
    let split = format!("{YAY_SRCINFO}\npkgname = yay-docs\n\tdepends = yay\n");
    s.aur.commit(
        "yay",
        &[(".SRCINFO", &split)],
        "add sibling package",
        "2026-01-02T00:00:00Z",
    );
    run(&s, &["aur", "approve", "-y", "yay"], "");
    let (code, out, err) = run(&s, &["install", "--aur", "-y", "yay"], "");
    assert_eq!(code, 0, "{err}\n{out}");
    let install = s
        .rig
        .log()
        .into_iter()
        .find(|line| line.contains("-U --noconfirm --"))
        .unwrap();
    assert!(
        install.ends_with("yay-13.0.1-1-x86_64.pkg.tar.zst"),
        "{install}"
    );
    assert!(!install.contains("yay-docs"), "{install}");
    let ledger = std::fs::read_to_string(s.rig.root.join("var/lib/omapac/state.json")).unwrap();
    let state: serde_json::Value = serde_json::from_str(&ledger).unwrap();
    assert!(state["packages"]["yay-docs"].is_null());
}

#[test]
fn install_aur_installs_missing_repo_dependencies_first() {
    let s = setup();
    no_jail(&s);
    // curl is in core.db and not installed in the fixture.
    let srcinfo = YAY_SRCINFO.replace("\tarch = x86_64\n", "\tarch = x86_64\n\tdepends = curl\n");
    s.aur.commit(
        "yay",
        &[(".SRCINFO", &srcinfo)],
        "add dep",
        "2026-01-02T00:00:00Z",
    );
    run(&s, &["aur", "approve", "-y", "yay"], "");
    let plan = "curl\\t8.16.0-1\\tcore\\thttps://m/curl.pkg\\t1000\\n";
    let (code, _, err) = run(&s, &["install", "--aur", "-y", "yay"], plan);
    assert_eq!(code, 0, "{err}");
    let log = s.rig.log();
    assert!(
        log.iter()
            .any(|l| l.ends_with("-S --noconfirm --needed --asdeps -- core/curl")),
        "{log:?}"
    );
    let makepkg_at = log.iter().position(|l| l.starts_with("makepkg")).unwrap();
    let deps_at = log.iter().position(|l| l.contains("--asdeps")).unwrap();
    assert!(
        deps_at < makepkg_at,
        "dependencies before the build: {log:?}"
    );
    let ledger: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(s.rig.root.join("var/lib/omapac/state.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(ledger["packages"]["curl"]["explicit"], false);
}

#[test]
fn install_scripts_can_be_denied_by_policy() {
    let s = setup();
    std::fs::create_dir_all(s.rig.home.join(".config/omapac")).unwrap();
    std::fs::write(
        s.rig.home.join(".config/omapac/omapac.toml"),
        "[policy]\naur.jail = false\naur.install_scripts = \"deny\"\n",
    )
    .unwrap();
    let srcinfo = YAY_SRCINFO.replace(
        "\tarch = x86_64\n",
        "\tarch = x86_64\n\tinstall = yay.install\n",
    );
    s.aur.commit(
        "yay",
        &[
            (".SRCINFO", &srcinfo),
            ("yay.install", "post_install() { :; }\n"),
        ],
        "add scriptlet",
        "2026-01-02T00:00:00Z",
    );
    run(&s, &["aur", "approve", "--force", "yay"], "");
    let (code, _, err) = run(&s, &["aur", "build", "yay"], "");
    assert_ne!(code, 0);
    assert!(
        err.contains("install scriptlet") && err.contains("deny"),
        "{err}"
    );
}
