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
    let output = Command::new(env!("CARGO_BIN_EXE_pacvamp"))
        .env("PATH", format!("{}:/usr/bin:/bin", s.rig.bin.display()))
        .env("PACVAMP_TEST_PACMAN", s.rig.bin.join("pacman"))
        .env("HOME", &s.rig.home)
        .env_remove("XDG_CONFIG_HOME")
        .env("XDG_CACHE_HOME", s.rig.dir.path().join("cache"))
        .env("PACVAMP_AUR_RPC_BASE", &s.rpc)
        .env("PACVAMP_AUR_GIT_BASE", s.aur.base())
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
    std::fs::create_dir_all(s.rig.home.join(".config/pacvamp")).unwrap();
    std::fs::write(
        s.rig.home.join(".config/pacvamp/pacvamp.toml"),
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
    let runs = s
        .rig
        .dir
        .path()
        .join("cache/pacvamp/aur/.pacvamp-build/runs");
    let first = std::fs::read_dir(&runs)
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let pkg = first.join("pkgs/yay-13.0.1-1-x86_64.pkg.tar.zst");
    assert!(pkg.exists(), "{}", pkg.display());
    let (receipt, reference) = pacvamp::aur::receipt::for_artifact(&pkg).unwrap();
    assert_eq!(receipt.commit, s.aur.head("yay"));
    assert!(!receipt.dependencies["pacman"].is_empty());
    assert!(reference.path.is_file());

    assert!(first.join("build/worktree/PKGBUILD").is_file());
    // Untracked cache files must never enter a later approved build.
    std::fs::write(
        s.rig.dir.path().join("cache/pacvamp/aur/yay/unreviewed"),
        "poison",
    )
    .unwrap();
    let (code, _, err) = run(&s, &["aur", "build", "yay"], "");
    assert_eq!(code, 0, "{err}");
    assert!(
        pkg.exists(),
        "a later build must not remove returned artifacts"
    );
    let runs: Vec<_> = std::fs::read_dir(runs).unwrap().collect();
    assert_eq!(runs.len(), 2);
    std::fs::write(&pkg, "tampered artifact").unwrap();
    assert!(
        pacvamp::aur::receipt::for_artifact(&pkg)
            .unwrap_err()
            .to_string()
            .contains("does not match")
    );

    for run in runs {
        assert!(
            !run.unwrap()
                .path()
                .join("build/worktree/unreviewed")
                .exists()
        );
    }
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
fn approval_cannot_be_reused_for_a_different_commit() {
    let s = setup();
    no_jail(&s);
    assert_eq!(run(&s, &["aur", "approve", "-y", "yay"], "").0, 0);
    s.aur.commit(
        "yay",
        &[("PKGBUILD", &format!("{YAY_PKGBUILD}\n# changed\n"))],
        "changed recipe",
        "2026-01-02T00:00:00Z",
    );
    let target = s.aur.head("yay");
    let (code, _, err) = run(&s, &["aur", "build", "--commit", &target, "yay"], "");
    assert_ne!(code, 0);
    assert!(err.contains("not approved"), "{err}");
    assert!(s.rig.log().iter().all(|l| !l.starts_with("makepkg")));
}

#[test]
fn a_recipe_cannot_return_an_unrelated_package_file() {
    let s = setup();
    no_jail(&s);
    let unrelated = s.rig.dir.path().join("unrelated.pkg.tar.zst");
    std::fs::write(&unrelated, "not this build").unwrap();
    let script = format!(
        "#!/bin/bash\nif [[ $* == *--packagelist* ]]; then echo '{}'; fi\n",
        unrelated.display()
    );
    std::fs::write(s.rig.bin.join("makepkg"), script).unwrap();
    assert_eq!(run(&s, &["aur", "approve", "-y", "yay"], "").0, 0);
    let (code, _, err) = run(&s, &["install", "--aur", "-y", "yay"], "");
    assert_ne!(code, 0);
    assert!(err.contains("unexpected package output"), "{err}");
    assert!(s.rig.log().iter().all(|l| !l.contains("-U")));
}

#[test]
fn every_build_phase_confines_recipe_code() {
    let s = setup();
    let secret = s.rig.home.join("credentials");
    std::fs::write(&secret, "fake credential").unwrap();
    // Run recipe top-level code on every makepkg invocation, including the
    // network-enabled source phase and the output-listing phase.
    let script = "#!/bin/bash\nset -euo pipefail\nsource PKGBUILD\ntouch \"$PKGDEST/write-probe\"\ncase \" $* \" in\n *' --verifysource '*) echo verified > \"$SRCDEST/input\"; echo planted > \"$PKGDEST/verify-only\";;\n *' --packagelist '*) echo \"$PKGDEST/yay.pkg.tar.zst\";;\n *) test ! -e \"$PKGDEST/verify-only\"; test \"$(cat \"$SRCDEST/input\")\" = verified; if echo poison > \"$SRCDEST/input\"; then exit 91; fi; echo package > \"$PKGDEST/yay.pkg.tar.zst\";;\nesac\n";
    std::fs::write(s.rig.bin.join("makepkg"), script).unwrap();
    let recipe = format!(
        "{YAY_PKGBUILD}\nif cat '{}'; then exit 92; fi\nif cat /proc/$PPID/environ; then exit 93; fi\nif echo poisoned > '{}'; then exit 94; fi\ntest -z \"${{GITHUB_TOKEN:-}}\"\ntest \"$TMPDIR\" = \"$BUILDDIR/tmp\"\necho scratch > \"$TMPDIR/probe\"\necho phase >> \"$LOGDEST/phases\"\n",
        secret.display(),
        s.rig.dir.path().join("other-build").display()
    );
    s.aur.commit(
        "yay",
        &[("PKGBUILD", &recipe)],
        "adversarial fixture",
        "2026-01-02T00:00:00Z",
    );
    assert_eq!(run(&s, &["aur", "approve", "--force", "yay"], "").0, 0);
    let (code, out, err) = run(&s, &["aur", "build", "yay"], "");
    if code != 0 && err.contains("this kernel cannot enforce") {
        assert!(std::env::var_os("PACVAMP_REQUIRE_JAIL").is_none(), "{err}");
        eprintln!("skipping: {err}");
        return;
    }
    assert_eq!(code, 0, "{out}\n{err}");
    assert!(!out.contains("fake credential"));
    assert!(!s.rig.dir.path().join("other-build").exists());
    let runs = s
        .rig
        .dir
        .path()
        .join("cache/pacvamp/aur/.pacvamp-build/runs");
    let phases = std::fs::read_dir(runs)
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path()
        .join("logs/phases");
    assert_eq!(std::fs::read_to_string(phases).unwrap().lines().count(), 3);
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
    let ledger = std::fs::read_to_string(s.rig.root.join("var/lib/pacvamp/state.json")).unwrap();
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
    let ledger = std::fs::read_to_string(s.rig.root.join("var/lib/pacvamp/state.json")).unwrap();
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
        &std::fs::read_to_string(s.rig.root.join("var/lib/pacvamp/state.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(ledger["packages"]["curl"]["explicit"], false);
}

#[test]
fn install_scripts_can_be_denied_by_policy() {
    let s = setup();
    std::fs::create_dir_all(s.rig.home.join(".config/pacvamp")).unwrap();
    std::fs::write(
        s.rig.home.join(".config/pacvamp/pacvamp.toml"),
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

/// yay depending on an AUR-only library, and the library as its own
/// recipe; the RPC answers for both.
const YAY_NEEDS_LIB_PKGBUILD: &str = "# Maintainer: jguer\npkgname=yay\npkgver=13.0.1\npkgrel=1\ndepends=('zorbqlib>=1.0')\nmakedepends=('zorbqlib>=1.0')\nsource=(\"yay-13.0.1.tar.gz::https://github.com/Jguer/yay/archive/v13.0.1.tar.gz\")\nsha256sums=('b77454bce87110180a1b6664c2d260de78124c9894b71101610ba84f551eb0d0')\nbuild() {\n  make build\n}\npackage() {\n  make DESTDIR=\"$pkgdir\" install\n}\n";
const YAY_NEEDS_LIB_SRCINFO: &str = "pkgbase = yay\n\tpkgver = 13.0.1\n\tpkgrel = 1\n\tarch = x86_64\n\tmakedepends = zorbqlib>=1.0\n\tdepends = zorbqlib>=1.0\n\tsource = yay-13.0.1.tar.gz::https://github.com/Jguer/yay/archive/v13.0.1.tar.gz\n\tsha256sums = b77454bce87110180a1b6664c2d260de78124c9894b71101610ba84f551eb0d0\n\npkgname = yay\n";
const ZORBQLIB_PKGBUILD: &str = "# Maintainer: jguer\npkgname=zorbqlib\npkgver=1.2\npkgrel=1\nsource=(\"https://github.com/example/zorbqlib/archive/v1.2.tar.gz\")\nsha256sums=('0000000000000000000000000000000000000000000000000000000000000000')\npackage() {\n  :\n}\n";
const MIDDLELIB_PKGBUILD: &str = "# Maintainer: jguer\npkgname=middlelib\npkgver=1.0\npkgrel=1\ndepends=('zorbqlib')\nsource=(\"https://github.com/example/middlelib/archive/v1.0.tar.gz\")\nsha256sums=('0000000000000000000000000000000000000000000000000000000000000000')\npackage() {\n  :\n}\n";
const MIDDLELIB_SRCINFO: &str = "pkgbase = middlelib\n\tpkgver = 1.0\n\tpkgrel = 1\n\tarch = x86_64\n\tdepends = zorbqlib\n\tsource = https://github.com/example/middlelib/archive/v1.0.tar.gz\n\tsha256sums = 0000000000000000000000000000000000000000000000000000000000000000\n\npkgname = middlelib\n";
const ZORBQLIB_SRCINFO: &str = "pkgbase = zorbqlib\n\tpkgver = 1.2\n\tpkgrel = 1\n\tarch = x86_64\n\tsource = https://github.com/example/zorbqlib/archive/v1.2.tar.gz\n\tsha256sums = 0000000000000000000000000000000000000000000000000000000000000000\n\npkgname = zorbqlib\n";
const ZORBQLIB_NEEDS_YAY_SRCINFO: &str = "pkgbase = zorbqlib\n\tpkgver = 1.2\n\tpkgrel = 1\n\tarch = x86_64\n\tdepends = yay>13.5\n\tsource = https://github.com/example/zorbqlib/archive/v1.2.tar.gz\n\tsha256sums = 0000000000000000000000000000000000000000000000000000000000000000\n\npkgname = zorbqlib\n";
const ZORBQLIB_NEEDS_YAY_LIB_SRCINFO: &str = "pkgbase = zorbqlib\n\tpkgver = 1.2\n\tpkgrel = 1\n\tarch = x86_64\n\tdepends = yay-api\n\tsource = https://github.com/example/zorbqlib/archive/v1.2.tar.gz\n\tsha256sums = 0000000000000000000000000000000000000000000000000000000000000000\n\npkgname = zorbqlib\n";
const YAY_LIB_SPLIT_SRCINFO: &str = "pkgbase = yay\n\tpkgver = 13.0.1\n\tpkgrel = 1\n\tarch = x86_64\n\tmakedepends = curl\n\tsource = yay-13.0.1.tar.gz::https://github.com/Jguer/yay/archive/v13.0.1.tar.gz\n\tsha256sums = b77454bce87110180a1b6664c2d260de78124c9894b71101610ba84f551eb0d0\n\npkgname = yay\n\tdepends = zorbqlib>=1.0\n\tdepends = yay-lib\n\npkgname = yay-lib\n\tprovides = yay-api\n";

fn info_with_zorbqlib() -> String {
    let mut info: serde_json::Value = serde_json::from_str(INFO).unwrap();
    let mut zorbqlib = info["results"][0].clone();
    zorbqlib["Name"] = "zorbqlib".into();
    zorbqlib["PackageBase"] = "zorbqlib".into();
    zorbqlib["Version"] = "1.2-1".into();
    zorbqlib["Depends"] = serde_json::json!([]);
    zorbqlib["MakeDepends"] = serde_json::json!([]);
    info["results"].as_array_mut().unwrap().push(zorbqlib);
    info["resultcount"] = serde_json::json!(info["results"].as_array().unwrap().len());
    info.to_string()
}

fn info_with_yay_lib_and_zorbqlib() -> String {
    let mut info: serde_json::Value = serde_json::from_str(&info_with_zorbqlib()).unwrap();
    let mut yay_lib = info["results"][0].clone();
    yay_lib["Name"] = "yay-lib".into();
    yay_lib["PackageBase"] = "yay".into();
    info["results"].as_array_mut().unwrap().push(yay_lib);
    info["resultcount"] = serde_json::json!(info["results"].as_array().unwrap().len());
    info.to_string()
}

fn info_with_long_split_chain() -> String {
    let mut info: serde_json::Value =
        serde_json::from_str(&info_with_yay_lib_and_zorbqlib()).unwrap();
    let mut middlelib = info["results"][0].clone();
    middlelib["Name"] = "middlelib".into();
    middlelib["PackageBase"] = "middlelib".into();
    middlelib["Version"] = "1.0-1".into();
    middlelib["Depends"] = serde_json::json!(["zorbqlib"]);
    middlelib["MakeDepends"] = serde_json::json!([]);
    info["results"].as_array_mut().unwrap().push(middlelib);
    info["resultcount"] = serde_json::json!(info["results"].as_array().unwrap().len());
    info.to_string()
}

fn setup_with_zorbqlib(zorbqlib_srcinfo: &str) -> Setup {
    let s = setup();
    s.aur.commit(
        "yay",
        &[
            ("PKGBUILD", YAY_NEEDS_LIB_PKGBUILD),
            (".SRCINFO", YAY_NEEDS_LIB_SRCINFO),
        ],
        "need zorbqlib",
        "2026-01-02T00:00:00Z",
    );
    s.aur.create(
        "zorbqlib",
        &[
            ("PKGBUILD", ZORBQLIB_PKGBUILD),
            (".SRCINFO", zorbqlib_srcinfo),
        ],
        "2026-01-01T00:00:00Z",
    );
    let rpc = common::http::serve(vec![("/rpc/v5/info", info_with_zorbqlib())]);
    Setup {
        rig: s.rig,
        aur: s.aur,
        rpc,
    }
}

#[test]
fn aur_dependencies_are_built_first_and_installed_as_deps() {
    let s = setup_with_zorbqlib(ZORBQLIB_SRCINFO);
    no_jail(&s);
    // Both recipes need approval; unattended, an unapproved dependency
    // is refused like any other package.
    run(&s, &["aur", "approve", "-y", "yay"], "");
    let (code, _, err) = run(&s, &["install", "--aur", "-y", "yay"], "");
    assert_ne!(code, 0);
    assert!(
        err.contains("zorbqlib at") && err.contains("is not approved"),
        "{err}"
    );
    assert!(
        s.rig.log().iter().all(|l| !l.contains("-U")),
        "nothing installed: {:?}",
        s.rig.log()
    );

    let (code, out, err) = run(&s, &["aur", "approve", "-y", "zorbqlib"], "");
    assert_eq!(code, 0, "{err}\n{out}");
    let lock = std::fs::read_to_string(s.rig.home.join(".config/pacvamp/pacvamp.lock")).unwrap();
    let (code, out, err) = run(&s, &["install", "--aur", "-y", "yay"], "");
    assert_eq!(code, 0, "{err}\n{out}\nlock before install:\n{lock}");
    assert!(
        out.contains("yay needs zorbqlib>=1.0 from the AUR; reviewing it first"),
        "{out}"
    );
    assert!(
        out.contains("installed zorbqlib 1.2-1 from AUR commit") && out.contains("as a dependency"),
        "{out}"
    );
    assert!(
        out.contains("installed yay 13.0.1-1 from AUR commit"),
        "{out}"
    );
    let log = s.rig.log();
    let builds: Vec<&String> = log
        .iter()
        .filter(|line| line.as_str() == "makepkg --noconfirm --force --holdver")
        .collect();
    assert_eq!(builds.len(), 2, "{log:?}");
    // sudo and pacman both log the install line; count pacman's.
    let installs: Vec<&String> = log
        .iter()
        .filter(|l| l.starts_with("--sysroot") && l.contains("-U"))
        .collect();
    assert_eq!(installs.len(), 2, "{log:?}");
    assert!(
        installs[0].contains("zorbqlib-1.2-1") && installs[0].contains("--asdeps"),
        "{installs:?}"
    );
    assert!(
        installs[1].contains("yay-13.0.1-1") && !installs[1].contains("--asdeps"),
        "{installs:?}"
    );
    let ledger: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(s.rig.root.join("var/lib/pacvamp/state.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(ledger["packages"]["zorbqlib"]["explicit"], false);
    assert_eq!(ledger["packages"]["yay"]["explicit"], true);
}

#[test]
fn upgrading_an_explicit_aur_dependency_keeps_it_explicit() {
    let s = setup_with_zorbqlib(ZORBQLIB_SRCINFO);
    no_jail(&s);
    s.rig.write_root(
        "/var/lib/pacman/local/zorbqlib-0.9-1/desc",
        "%NAME%\nzorbqlib\n\n%VERSION%\n0.9-1\n\n%REASON%\n0\n",
    );
    run(&s, &["aur", "approve", "-y", "yay"], "");
    run(&s, &["aur", "approve", "-y", "zorbqlib"], "");
    let (code, out, err) = run(&s, &["install", "--aur", "-y", "yay"], "");
    assert_eq!(code, 0, "{err}\n{out}");
    let installs: Vec<String> = s
        .rig
        .log()
        .into_iter()
        .filter(|line| line.starts_with("--sysroot") && line.contains("-U"))
        .collect();
    assert_eq!(installs.len(), 2, "{installs:?}");
    assert!(
        installs[0].contains("zorbqlib-1.2-1") && !installs[0].contains("--asdeps"),
        "{installs:?}"
    );
    let ledger: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(s.rig.root.join("var/lib/pacvamp/state.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(ledger["packages"]["zorbqlib"]["explicit"], true);
}

#[test]
fn split_siblings_do_not_create_false_aur_cycles() {
    let mut s = setup_with_zorbqlib(ZORBQLIB_NEEDS_YAY_LIB_SRCINFO);
    s.aur.commit(
        "yay",
        &[
            (
                "PKGBUILD",
                &YAY_NEEDS_LIB_PKGBUILD.replace("pkgname=yay", "pkgname=('yay' 'yay-lib')"),
            ),
            (".SRCINFO", YAY_LIB_SPLIT_SRCINFO),
        ],
        "split out the library",
        "2026-01-03T00:00:00Z",
    );
    s.rpc = common::http::serve(vec![("/rpc/v5/info", info_with_yay_lib_and_zorbqlib())]);
    no_jail(&s);
    run(&s, &["aur", "approve", "-y", "yay"], "");
    run(&s, &["aur", "approve", "-y", "zorbqlib"], "");
    let plan = "curl\\t8.16.0-1\\tcore\\thttps://m/curl.pkg\\t1000\\n";
    let (code, out, err) = run(&s, &["install", "--aur", "-y", "yay"], plan);
    assert_eq!(code, 0, "{err}\n{out}");
    assert!(!err.contains("dependency cycle"), "{err}");
    assert!(
        out.contains("installed yay-lib 13.0.1-1 from AUR commit")
            && out.contains("installed yay, yay-lib 13.0.1-1 from AUR commit"),
        "{out}"
    );
    let builds = s
        .rig
        .log()
        .into_iter()
        .filter(|line| line.starts_with("makepkg --noconfirm --force --holdver"))
        .count();
    assert_eq!(
        builds, 3,
        "the split pkgbase is bootstrapped, then rebuilt normally"
    );
    let log = s.rig.log();
    let bootstrap = log
        .iter()
        .position(|line| line == "makepkg --noconfirm --force --holdver --nodeps")
        .expect("split pkgbase bootstrap");
    let build_dependency_install = log
        .iter()
        .position(|line| line.ends_with("-S --noconfirm --needed --asdeps -- core/curl"))
        .expect("ancestor build dependency install");
    let sibling_install = log
        .iter()
        .position(|line| line.contains("-U --noconfirm --asdeps") && line.contains("yay-lib"))
        .expect("bootstrapped sibling install");
    let dependency_build = log
        .iter()
        .enumerate()
        .skip(sibling_install + 1)
        .find(|(_, line)| *line == "makepkg --noconfirm --force --holdver")
        .map(|(index, _)| index)
        .expect("dependent package build");
    assert!(
        build_dependency_install < bootstrap
            && bootstrap < sibling_install
            && sibling_install < dependency_build,
        "{log:?}"
    );
    let final_installs: Vec<_> = log
        .iter()
        .filter(|line| line.starts_with("--sysroot") && line.contains("-U"))
        .rev()
        .take(2)
        .collect();
    assert!(
        final_installs
            .iter()
            .any(|line| line.contains("yay-lib") && line.contains("--asdeps")),
        "{final_installs:?}"
    );
    assert!(
        final_installs
            .iter()
            .any(|line| line.contains("yay-13.0.1-1") && !line.contains("--asdeps")),
        "{final_installs:?}"
    );
    let ledger: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(s.rig.root.join("var/lib/pacvamp/state.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(ledger["packages"]["yay-lib"]["explicit"], false);
    assert_eq!(ledger["packages"]["yay"]["explicit"], true);
}

#[test]
fn longer_split_dependency_chains_bootstrap_without_a_false_cycle() {
    let mut s = setup_with_zorbqlib(ZORBQLIB_NEEDS_YAY_LIB_SRCINFO);
    let split = YAY_LIB_SPLIT_SRCINFO.replace("depends = zorbqlib>=1.0", "depends = middlelib");
    s.aur.commit(
        "yay",
        &[
            (
                "PKGBUILD",
                &YAY_NEEDS_LIB_PKGBUILD.replace("pkgname=yay", "pkgname=('yay' 'yay-lib')"),
            ),
            (".SRCINFO", &split),
        ],
        "split out the library behind a longer chain",
        "2026-01-03T00:00:00Z",
    );
    s.aur.create(
        "middlelib",
        &[
            ("PKGBUILD", MIDDLELIB_PKGBUILD),
            (".SRCINFO", MIDDLELIB_SRCINFO),
        ],
        "2026-01-01T00:00:00Z",
    );
    s.rpc = common::http::serve(vec![("/rpc/v5/info", info_with_long_split_chain())]);
    no_jail(&s);
    for package in ["yay", "middlelib", "zorbqlib"] {
        run(&s, &["aur", "approve", "-y", package], "");
    }

    let plan = "curl\\t8.16.0-1\\tcore\\thttps://m/curl.pkg\\t1000\\n";
    let (code, out, err) = run(&s, &["install", "--aur", "-y", "yay"], plan);
    assert_eq!(code, 0, "{err}\n{out}");
    assert!(!err.contains("dependency cycle"), "{err}");
    assert!(out.contains("installed yay-lib 13.0.1-1"), "{out}");
}

#[test]
fn aur_dependency_cycles_and_unknown_deps_are_refused() {
    let s = setup_with_zorbqlib(ZORBQLIB_NEEDS_YAY_SRCINFO);
    no_jail(&s);
    run(&s, &["aur", "approve", "-y", "yay"], "");
    run(&s, &["aur", "approve", "-y", "zorbqlib"], "");
    // The installed yay does not satisfy yay>13.5, so the dependency
    // leads back to the package being built.
    let (code, _, err) = run(&s, &["install", "--aur", "-y", "yay"], "");
    assert_ne!(code, 0);
    assert!(
        err.contains("AUR dependency cycle: yay -> zorbqlib -> yay"),
        "{err}"
    );
    assert!(
        s.rig.log().iter().all(|l| !l.contains("-U")),
        "{:?}",
        s.rig.log()
    );

    // A dependency nobody has.
    s.aur.commit(
        "zorbqlib",
        &[(
            ".SRCINFO",
            &ZORBQLIB_SRCINFO.replace(
                "\tarch = x86_64\n",
                "\tarch = x86_64\n\tdepends = libnowhere\n",
            ),
        )],
        "need nowhere",
        "2026-01-03T00:00:00Z",
    );
    // The recipe moved, so unattended approval refuses the drift; a
    // reviewer approves the new commit with --force.
    let (code, out, err) = run(&s, &["aur", "approve", "--force", "zorbqlib"], "");
    assert_eq!(code, 0, "{err}\n{out}");
    let (code, _, err) = run(&s, &["install", "--aur", "-y", "zorbqlib"], "");
    assert_ne!(code, 0);
    assert!(
        err.contains("dependency libnowhere is in no repository and not on the AUR"),
        "{err}"
    );
}

#[test]
fn concurrent_aur_operation_fails_before_touching_shared_checkout() {
    use nix::fcntl::{Flock, FlockArg};
    let s = setup();
    let dir = s.rig.dir.path().join("cache/pacvamp/aur/.locks");
    std::fs::create_dir_all(&dir).unwrap();
    let file = std::fs::File::create(dir.join("yay.lock")).unwrap();
    let held = Flock::lock(file, FlockArg::LockExclusive).unwrap();
    let (code, _, err) = run(&s, &["aur", "approve", "--force", "yay"], "");
    assert_ne!(code, 0);
    assert!(err.contains("yay is busy"), "{err}");
    assert!(!s.rig.dir.path().join("cache/pacvamp/aur/yay").exists());
    drop(held);
    let (code, _, err) = run(&s, &["aur", "approve", "--force", "yay"], "");
    assert_eq!(code, 0, "{err}");
}

#[test]
fn exports_raw_reviewed_blobs_without_archive_attributes_or_untracked_files() {
    let s = setup();
    s.aur.commit(
        "yay",
        &[
            (
                ".gitattributes",
                "PKGBUILD export-ignore\nversion export-subst\n",
            ),
            ("version", "$Format:%H$\n"),
        ],
        "archive attributes",
        "2026-01-02T00:00:00Z",
    );
    let checkout = pacvamp::aur::git::Checkout {
        pkgbase: "yay".into(),
        dir: s.aur.dir.join("yay.git"),
    };
    let destination = s.rig.dir.path().join("export");
    checkout.export(&s.aur.head("yay"), &destination).unwrap();
    assert_eq!(
        std::fs::read_to_string(destination.join("PKGBUILD")).unwrap(),
        YAY_PKGBUILD
    );
    assert_eq!(
        std::fs::read_to_string(destination.join("version")).unwrap(),
        "$Format:%H$\n"
    );
}

#[test]
fn source_inventory_records_links_without_reading_outside_the_tree_and_pins_git_refs() {
    let s = setup();
    let source = s.rig.dir.path().join("source-inputs");
    std::fs::create_dir_all(&source).unwrap();
    std::fs::write(source.join("archive"), "downloaded source").unwrap();
    std::os::unix::fs::symlink("/outside/private", source.join("link")).unwrap();
    let inventory = pacvamp::aur::receipt::inputs(&source).unwrap();
    assert_eq!(
        inventory[Path::new("archive")].sha256.as_ref().unwrap(),
        &packslip::digest_file(&source.join("archive")).unwrap().0
    );
    assert_eq!(
        inventory[Path::new("link")].link.as_deref(),
        Some(Path::new("/outside/private"))
    );
    let refs = pacvamp::aur::receipt::vcs_refs(&s.aur.dir).unwrap();
    assert!(refs[Path::new("yay.git")].contains(&s.aur.head("yay")));
}

#[test]
fn chroot_checks_image_dependencies_without_installing_host_packages() {
    let s = setup();
    let image = s.rig.dir.path().join("image");
    std::fs::create_dir_all(image.join("usr/bin")).unwrap();
    std::fs::create_dir_all(image.join("etc")).unwrap();
    std::fs::create_dir_all(image.join("var/lib/pacman/local")).unwrap();
    std::fs::write(image.join("usr/bin/makepkg"), "").unwrap();
    std::fs::write(image.join("usr/bin/bash"), "").unwrap();
    std::fs::write(
        image.join("etc/pacman.conf"),
        "[options]\nArchitecture = x86_64\n",
    )
    .unwrap();
    let srcinfo = YAY_SRCINFO.replace("\tarch = x86_64\n", "\tarch = x86_64\n\tdepends = pacman\n");
    s.aur.commit(
        "yay",
        &[(".SRCINFO", &srcinfo)],
        "image dependency",
        "2026-01-02T00:00:00Z",
    );
    no_jail(&s);
    std::fs::write(
        s.rig.user_manifest(),
        format!("[policy.aur]\nchroot = true\nchroot_root = {:?}\n", image),
    )
    .unwrap();
    assert_eq!(run(&s, &["aur", "approve", "--force", "yay"], "").0, 0);
    let (code, _, err) = run(&s, &["aur", "build", "yay"], "");
    assert_ne!(code, 0);
    assert!(
        err.contains("clean chroot is missing build dependencies: pacman"),
        "{err}"
    );
    let (code, _, err) = run(&s, &["aur", "build", "yay", "--prepare-image"], "");
    assert_ne!(code, 0);
    assert!(
        err.contains("image is missing AUR dependencies: pacman"),
        "{err}"
    );
    assert!(err.contains("--dependency-artifact"), "{err}");
    assert!(
        s.rig.log().is_empty(),
        "must not install the image's missing dependencies on the host"
    );
}

#[test]
fn chroot_rejects_the_host_root_and_images_that_link_to_it() {
    assert!(pacvamp::aur::chroot::host(Path::new("/")).is_err());
    let dir = tempfile::tempdir().unwrap();
    std::os::unix::fs::symlink("/", dir.path().join("root")).unwrap();
    assert!(
        pacvamp::aur::chroot::host(&dir.path().join("root"))
            .err()
            .unwrap()
            .to_string()
            .contains("host root")
    );
}
