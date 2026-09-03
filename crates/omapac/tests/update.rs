//! `omapac update` through the fake pacman, makepkg, AUR remote, and RPC.

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

/// An RPC fixture where yay is at 13.0.2, newer than the installed 13.0.1.
fn rpc_with_newer_yay() -> String {
    INFO.replace("\"Version\":\"13.0.1-1\"", "\"Version\":\"13.0.2-1\"")
}

fn setup(rpc_body: String) -> Setup {
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
    let rpc = common::http::serve(vec![("/rpc/v5/info", rpc_body)]);
    // Without the OPR database yay is foreign, so it is an AUR candidate
    // rather than a repository upgrade.
    std::fs::remove_file(rig.root.join("var/lib/pacman/sync/omarchy.db")).unwrap();
    std::fs::create_dir_all(rig.home.join(".config/omapac")).unwrap();
    std::fs::write(
        rig.home.join(".config/omapac/omapac.toml"),
        "[policy]\naur.jail = false\n",
    )
    .unwrap();
    Setup { rig, aur, rpc }
}

fn run(s: &Setup, args: &[&str], print: &str) -> (i32, String, String) {
    run_with_status(s, args, print, 0)
}

fn run_with_status(s: &Setup, args: &[&str], print: &str, status: i32) -> (i32, String, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_omapac"))
        .env("PATH", format!("{}:/usr/bin:/bin", s.rig.bin.display()))
        .env("HOME", &s.rig.home)
        .env_remove("XDG_CONFIG_HOME")
        .env("XDG_CACHE_HOME", s.rig.dir.path().join("cache"))
        .env("OMAPAC_AUR_RPC_BASE", &s.rpc)
        .env("OMAPAC_AUR_GIT_BASE", s.aur.base())
        .env("FAKE_PACMAN_LOG", &s.rig.log)
        .env("FAKE_PACMAN_PRINT", print)
        .env("FAKE_PACMAN_STATUS", status.to_string())
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

const UPGRADE: &str = "pacman\\t7.1.0.r9.g54d9411-2\\tcore\\thttps://m/pacman.pkg\\t991730\\n";

#[test]
fn update_refreshes_plans_with_holds_and_applies() {
    let s = setup(INFO.to_string());
    // A manifest hold and a release-age floor that catches core's pacman
    // (built 2026-05, younger than a year).
    s.rig.write_root(
        "/etc/omapac/conf.d/10-omarchy.toml",
        "[packages]\nglibc = { hold = true }\n[policy]\nrepo.min_release_age.arch = \"365d\"\n[update]\noverwrite = [\"/usr/share/omarchy/*\"]\npre_hooks = [\"echo hook-pre >> $FAKE_PACMAN_LOG\"]\npost_hooks = [\"echo hook-post >> $FAKE_PACMAN_LOG\"]\n",
    );
    s.rig.write_root("/etc/pacman.conf.pacnew", "");
    let (code, out, err) = run(&s, &["update", "-y"], UPGRADE);
    assert_eq!(code, 0, "{err}\n{out}");
    assert!(out.contains("hold: glibc: held by"), "{out}");
    assert!(
        out.contains("hold: pacman: core 7.1.0.r9.g54d9411-2 was built"),
        "{out}"
    );
    assert!(out.contains("aur: nothing newer"), "{out}");
    assert!(
        out.contains("orphans: yay (pass --prune-orphans to remove)"),
        "{out}"
    );
    assert!(
        out.contains("pacnew: ") && out.contains("pacman.conf.pacnew"),
        "{out}"
    );
    let log = s.rig.log();
    let pre = log.iter().position(|line| line == "hook-pre").unwrap();
    let plan_pos = log
        .iter()
        .position(|line| line.contains("-Su --noconfirm --print"))
        .unwrap();
    let apply_pos = log
        .iter()
        .position(|line| line.contains("-Su --noconfirm") && !line.contains("--print"))
        .unwrap();
    assert!(
        plan_pos < pre && pre < apply_pos,
        "hooks bracket apply: {log:?}"
    );
    let plan = log
        .iter()
        .find(|l| l.contains("-Su --noconfirm --print"))
        .unwrap();
    assert!(plan.contains("--ignore glibc,pacman"), "{plan}");
    assert!(plan.contains("--overwrite /usr/share/omarchy/*"), "{plan}");
    let apply = log
        .iter()
        .find(|l| l.contains("-Su --noconfirm") && !l.contains("--print"))
        .unwrap();
    assert!(
        apply.starts_with("sudo -n env OMARCHY_UPDATE_PACMAN=1"),
        "the guard variable: {apply}"
    );
    assert_eq!(log.last().unwrap(), "hook-post", "{log:?}");
}

#[test]
fn dry_run_and_json_run_nothing() {
    let s = setup(INFO.to_string());
    let (code, out, _) = run(&s, &["update", "-n"], UPGRADE);
    assert_eq!(code, 0);
    assert!(out.contains("would run:"), "{out}");
    let log = s.rig.log();
    assert!(
        log.iter().all(|l| l.contains("--print")),
        "only planning: {log:?}"
    );
    let (_, out, _) = run(&s, &["update", "--json"], UPGRADE);
    let json: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(json["repo"]["changes"][0]["name"], "pacman");
    assert_eq!(json["orphans"][0], "yay");
}

#[test]
fn post_hooks_run_after_an_apply_failure() {
    let s = setup(INFO.to_string());
    s.rig.write_root(
        "/etc/omapac/conf.d/10-hooks.toml",
        "[update]\npre_hooks = [\"echo hook-pre >> $FAKE_PACMAN_LOG\"]\npost_hooks = [\"echo hook-post >> $FAKE_PACMAN_LOG\"]\n",
    );
    let (code, _, _) = run_with_status(
        &s,
        &["update", "-y", "--no-aur", "--no-refresh"],
        UPGRADE,
        7,
    );
    assert_ne!(code, 0);
    let log = s.rig.log();
    assert!(log.iter().any(|line| line == "hook-pre"), "{log:?}");
    assert_eq!(log.last().map(String::as_str), Some("hook-post"), "{log:?}");
}

#[test]
fn aur_upgrade_is_reviewed_built_and_installed_when_clean() {
    let s = setup(rpc_with_newer_yay());
    // A benign bump committed long ago, same host, no scriptlets.
    let pkgbuild = YAY_PKGBUILD.replace("pkgver=13.0.1", "pkgver=13.0.2");
    let srcinfo = YAY_SRCINFO.replace("pkgver = 13.0.1", "pkgver = 13.0.2");
    s.aur.commit(
        "yay",
        &[("PKGBUILD", &pkgbuild), (".SRCINFO", &srcinfo)],
        "bump to 13.0.2",
        "2026-02-01T00:00:00Z",
    );
    let (code, _, err) = run(&s, &["update", "--aur-only"], "");
    assert_ne!(code, 0);
    assert!(err.contains("no terminal to ask on; pass -y"), "{err}");
    assert!(s.rig.log().iter().all(|line| !line.starts_with("makepkg")));
    let (code, out, err) = run(&s, &["update", "-y", "--aur-only"], "");
    assert_eq!(code, 0, "{err}\n{out}");
    assert!(
        out.contains("aur: 1 package(s) have a newer commit:"),
        "{out}"
    );
    assert!(out.contains("yay  13.0.1-1 -> 13.0.2-1"), "{out}");
    assert!(
        out.contains("updated yay to 13.0.2-1 from AUR commit"),
        "{out}"
    );
    let log = s.rig.log();
    assert!(
        log.iter()
            .any(|line| line.as_str() == "makepkg --noconfirm --force --holdver"),
        "{log:?}"
    );
    assert!(
        log.iter()
            .any(|l| l.contains("-U --noconfirm -- ") && l.contains("yay-13.0.2-1")),
        "{log:?}"
    );
    let lock = std::fs::read_to_string(s.rig.home.join(".config/omapac/omapac.lock")).unwrap();
    assert!(
        lock.contains("pkgver = \"13.0.2-1\""),
        "auto-approved: {lock}"
    );
    let ledger = std::fs::read_to_string(s.rig.root.join("var/lib/omapac/state.json")).unwrap();
    let ledger: serde_json::Value = serde_json::from_str(&ledger).unwrap();
    assert_eq!(ledger["packages"]["yay"]["explicit"], false);
}

#[test]
fn unattended_update_allows_signed_custom_repo_warnings() {
    let s = setup(INFO.to_string());
    let conf =
        common::DEFAULT_CONF.replace("SigLevel = Never", "SigLevel = Required DatabaseOptional");
    s.rig.write_root("/etc/pacman.conf", &conf);
    let plan = "foo\\t2-1\\tchaotic-aur\\thttps://x/foo.pkg\\t1\\n";
    let (code, out, err) = run(&s, &["update", "-y", "--no-aur", "--no-refresh"], plan);
    assert_eq!(code, 0, "{err}\n{out}");
    assert!(out.contains("outside Arch and Omarchy review"), "{out}");
    assert!(
        s.rig
            .log()
            .iter()
            .any(|line| line.contains("-Su --noconfirm") && !line.contains("--print")),
        "{:?}",
        s.rig.log()
    );

    std::fs::write(
        s.rig.home.join(".config/omapac/omapac.toml"),
        "[policy]\naur.jail = false\ntrust.custom_repos = \"deny\"\n",
    )
    .unwrap();
    let calls = s.rig.log().len();
    let (code, out, err) = run(&s, &["update", "-y", "--no-aur", "--no-refresh"], plan);
    assert_ne!(code, 0, "{out}");
    assert!(out.contains("denied by trust.custom_repos policy"), "{out}");
    assert!(err.contains("refusing to upgrade unattended"), "{err}");
    let log = s.rig.log();
    assert_eq!(log.len(), calls + 1, "only the planning call is expected");
    assert!(log.last().unwrap().contains("--print"), "{log:?}");
}

#[test]
fn aur_upgrade_with_denials_is_skipped_unattended() {
    let s = setup(rpc_with_newer_yay());
    use common::aur::{EVIL_INSTALL, EVIL_PKGBUILD, EVIL_SRCINFO};
    s.aur.commit(
        "yay",
        &[
            ("PKGBUILD", EVIL_PKGBUILD),
            (".SRCINFO", EVIL_SRCINFO),
            ("yay.install", EVIL_INSTALL),
        ],
        "bump",
        "2026-09-03T00:00:00Z",
    );
    let (code, out, err) = run(&s, &["update", "-y", "--aur-only"], "");
    assert_eq!(code, 0, "a skipped package does not fail the update: {err}");
    assert!(err.contains("skipped yay: "), "{err}");
    assert!(err.contains("checksum-skip"), "{err}");
    assert!(err.contains("1 AUR package(s) skipped: yay"), "{err}");
    assert!(!out.contains("updated yay"), "{out}");
    assert!(
        s.rig.log().iter().all(|l| !l.starts_with("makepkg")),
        "nothing built"
    );
}

#[test]
fn prune_orphans_and_pacnew_command() {
    let s = setup(INFO.to_string());
    let remove = "yay\\t13.0.1-1\\tlocal\\tyay-13.0.1-1\\t(null)\\n";
    let (code, out, err) = run(
        &s,
        &[
            "update",
            "-y",
            "--no-aur",
            "--no-refresh",
            "--prune-orphans",
        ],
        remove,
    );
    assert_eq!(code, 0, "{err}\n{out}");
    assert!(out.contains("orphans: yay (will be removed)"), "{out}");
    let log = s.rig.log();
    assert!(
        log.iter().any(|l| l.ends_with("-R --noconfirm -s -- yay")),
        "{log:?}"
    );
    assert!(
        log.iter().all(|l| !l.ends_with("-Sy")),
        "--no-refresh: {log:?}"
    );

    s.rig.write_root("/etc/pacman.conf", "a\n");
    s.rig.write_root("/etc/pacman.conf.pacnew", "b\n");
    let (code, out, _) = run(&s, &["pacnew", "--diff"], "");
    assert_eq!(code, 0);
    assert!(out.contains("pacman.conf.pacnew"), "{out}");
    assert!(out.contains("-a\n+b"), "{out}");

    s.rig.write_root("/etc/removed.conf.pacsave", "old\n");
    let (code, _, err) = run(&s, &["pacnew", "--diff"], "");
    assert_ne!(code, 0);
    assert!(
        err.contains("removed.conf") && err.contains("failed"),
        "{err}"
    );
}
