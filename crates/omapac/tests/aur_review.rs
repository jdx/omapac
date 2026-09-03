//! `aur review`, `aur approve`, and `aur diff` against a fake AUR git
//! remote and replayed RPC responses.

mod common;

use std::process::Command;

use common::Rig;
use common::aur::{EVIL_INSTALL, EVIL_PKGBUILD, EVIL_SRCINFO, FakeAur, YAY_PKGBUILD, YAY_SRCINFO};

const INFO: &str = include_str!("../fixtures/aur/info.json");

struct Setup {
    rig: Rig,
    aur: FakeAur,
    rpc: String,
}

fn setup() -> Setup {
    let rig = Rig::new();
    let aur = FakeAur::new(rig.dir.path());
    aur.create(
        "yay",
        &[("PKGBUILD", YAY_PKGBUILD), (".SRCINFO", YAY_SRCINFO)],
        "2026-01-01T00:00:00Z",
    );
    let rpc = common::http::serve(vec![("/rpc/v5/info", INFO.to_string())]);
    Setup { rig, aur, rpc }
}

fn run(s: &Setup, args: &[&str]) -> (i32, String, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_omapac"))
        .env("HOME", &s.rig.home)
        .env_remove("XDG_CONFIG_HOME")
        .env("XDG_CACHE_HOME", s.rig.dir.path().join("cache"))
        .env("OMAPAC_AUR_RPC_BASE", &s.rpc)
        .env("OMAPAC_AUR_GIT_BASE", s.aur.base())
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

#[test]
fn review_approve_then_catch_the_takeover() {
    let s = setup();
    // First review: yay is installed in the fixture, the commit is old,
    // the maintainer matches the submitter. Nothing to flag.
    let (code, out, err) = run(&s, &["aur", "review", "yay"]);
    assert_eq!(code, 0, "{err}");
    assert!(out.contains("yay 13.0.1-1 at "), "{out}");
    assert!(out.contains("approved: never (first review)"), "{out}");
    assert!(out.contains("findings: none"), "{out}");
    assert!(
        out.contains("==> PKGBUILD"),
        "first review shows the whole recipe: {out}"
    );

    // Approve unattended: nothing denies, so -y suffices.
    let (code, out, err) = run(&s, &["aur", "approve", "-y", "yay"]);
    assert_eq!(code, 0, "{err}");
    let first = s.aur.head("yay");
    assert!(
        out.contains(&format!("approved yay at {}", &first[..12])),
        "{out}"
    );
    let lock = std::fs::read_to_string(s.rig.home.join(".config/omapac/omapac.lock")).unwrap();
    assert!(lock.contains("[aur.yay]"), "{lock}");
    assert!(lock.contains(&format!("commit = \"{first}\"")), "{lock}");
    assert!(lock.contains("source_hosts = [\"github.com\"]"), "{lock}");
    assert!(lock.contains("maintainer = \"jguer\""), "{lock}");

    // Reviewing again: this commit is the approved one.
    let (_, out, _) = run(&s, &["aur", "review", "yay", "--no-diff"]);
    assert!(out.contains("approved: this commit"), "{out}");

    // The takeover: new host, SKIP, install script, npm install, today.
    s.aur.commit(
        "yay",
        &[
            ("PKGBUILD", EVIL_PKGBUILD),
            (".SRCINFO", EVIL_SRCINFO),
            ("yay.install", EVIL_INSTALL),
        ],
        "bump to 13.0.2",
        "2026-09-03T00:00:00Z",
    );
    let (code, out, _) = run(&s, &["aur", "review", "yay", "--unattended"]);
    assert_eq!(code, 1, "a denied review exits 1: {out}");
    assert!(
        out.contains("approved: ") && out.contains("reviewing the change since"),
        "{out}"
    );
    for finding in [
        "DENY  source-domain-changed",
        "DENY  checksum-skip",
        "DENY  install-script",
        "DENY  language-dep",
        "DENY  suspicious-content",
    ] {
        assert!(out.contains(finding), "missing {finding}: {out}");
    }
    assert!(
        out.contains("+source=(\"https://evil.example/yay.tar.gz\")"),
        "diff shown: {out}"
    );
    assert!(
        out.contains("+++ b/yay.install"),
        "new scriptlet in the diff: {out}"
    );

    // Unattended approval is refused; --force records it anyway.
    let (code, _, err) = run(&s, &["aur", "approve", "-y", "yay"]);
    assert_ne!(code, 0);
    assert!(err.contains("finding(s) deny"), "{err}");
    let (code, _, err) = run(&s, &["aur", "approve", "--force", "yay"]);
    assert_eq!(code, 0, "{err}");
    let lock = std::fs::read_to_string(s.rig.home.join(".config/omapac/omapac.lock")).unwrap();
    assert!(
        lock.contains(&format!("commit = \"{}\"", s.aur.head("yay"))),
        "{lock}"
    );
    assert!(lock.contains("install_files = [\"yay.install\"]"), "{lock}");
    assert!(lock.contains("findings = \"sha256:"), "{lock}");

    // A pinned older commit reviews as drift against the new approval.
    let (code, out, _) = run(
        &s,
        &[
            "aur",
            "review",
            "--unattended",
            "--no-diff",
            "--commit",
            &first,
            "yay",
        ],
    );
    assert_eq!(code, 1);
    assert!(out.contains("commit-drift"), "{out}");
}

#[test]
fn diff_and_json() {
    let s = setup();
    run(&s, &["aur", "approve", "-y", "yay"]);
    let (code, out, err) = run(&s, &["aur", "diff", "yay"]);
    assert_eq!(code, 0, "{err}");
    assert!(out.is_empty(), "approved commit has no diff: {out}");
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
    let (code, out, err) = run(&s, &["aur", "diff", "yay"]);
    assert_eq!(code, 0, "{err}");
    assert!(out.starts_with("diff --git a/PKGBUILD b/PKGBUILD"), "{out}");

    let (_, out, _) = run(&s, &["aur", "review", "--json", "--unattended", "yay"]);
    let json: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(json["pkgbase"], "yay");
    assert_eq!(json["version"], "13.0.2-1");
    assert_eq!(json["report"]["mode"], "unattended");
    let ids: Vec<&str> = json["report"]["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["id"].as_str().unwrap())
        .collect();
    assert!(ids.contains(&"checksum-skip"), "{ids:?}");
    assert!(json["diff"].as_str().unwrap().contains("evil.example"));
}

#[test]
fn unknown_packages_and_wrong_names() {
    let s = setup();
    let (code, _, err) = run(&s, &["aur", "review", "no-such-package-zzz"]);
    assert_ne!(code, 0);
    assert!(err.contains("not on the AUR"), "{err}");
    // google-chrome is in the RPC fixture but not in the fake git remote.
    let (code, _, err) = run(&s, &["aur", "review", "google-chrome"]);
    assert_ne!(code, 0);
    assert!(
        err.contains("git clone") || err.contains("not on the AUR"),
        "{err}"
    );
}

#[test]
fn split_package_approval_is_keyed_by_pkgbase() {
    let rig = Rig::new();
    let aur = FakeAur::new(rig.dir.path());
    let srcinfo = "pkgbase = demo\n\tpkgver = 1\n\tpkgrel = 1\n\n\
                   pkgname = demo-cli\n\n\
                   pkgname = demo-libs\n";
    aur.create(
        "demo",
        &[
            (
                "PKGBUILD",
                "pkgbase=demo\npkgname=(demo-cli demo-libs)\npkgver=1\npkgrel=1\n",
            ),
            (".SRCINFO", srcinfo),
        ],
        "2026-01-01T00:00:00Z",
    );
    let mut info: serde_json::Value = serde_json::from_str(INFO).unwrap();
    let package = &mut info["results"][0];
    package["Name"] = "demo-cli".into();
    package["PackageBase"] = "demo".into();
    let rpc = common::http::serve(vec![("/rpc/v5/info", info.to_string())]);
    let setup = Setup { rig, aur, rpc };

    let (code, _, err) = run(&setup, &["aur", "approve", "-y", "demo-cli"]);
    assert_eq!(code, 0, "{err}");
    let lock = std::fs::read_to_string(setup.rig.home.join(".config/omapac/omapac.lock")).unwrap();
    assert!(lock.contains("[aur.demo]"), "{lock}");
    assert!(!lock.contains("[aur.demo-cli]"), "{lock}");
}
