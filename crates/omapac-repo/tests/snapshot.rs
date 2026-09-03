//! The snapshot store: cut, test, promote, hold, prune, and the built-in
//! check, against a fixture mirror.

mod common;

use std::os::unix::fs::MetadataExt as _;
use std::path::Path;

use common::Rig;

fn fixtures() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../alpm-db/fixtures")
}

struct Train {
    rig: Rig,
}

impl Train {
    fn new() -> Train {
        let rig = Rig::new();
        rig.keygen("index", 7);
        let mirror = rig.path().join("mirror");
        for repo in ["core", "omarchy"] {
            let pool = mirror.join(repo).join("os/x86_64");
            std::fs::create_dir_all(&pool).unwrap();
            std::fs::copy(
                fixtures().join("sync").join(format!("{repo}.db")),
                pool.join(format!("{repo}.db")),
            )
            .unwrap();
        }
        std::fs::write(
            mirror.join("core/os/x86_64/shared-1-1-x86_64.pkg.tar.zst"),
            "shared bytes",
        )
        .unwrap();
        Train { rig }
    }

    fn run(&self, now: &str, args: &[&str]) -> (i32, String, String) {
        let mut full = vec!["snapshot", "--store", "store", "--key", "index.key"];
        full.extend_from_slice(args);
        self.rig.run_env(&full, &[("OMAPAC_REPO_NOW", now)])
    }

    fn release(&self, id: &str) -> omapac::channel::Release {
        let path = self
            .rig
            .path()
            .join("store/snapshots")
            .join(id)
            .join("release.json");
        let bytes = std::fs::read(&path).unwrap();
        let sig = packslip::minisign::Sig::parse(
            &std::fs::read_to_string(
                self.rig
                    .path()
                    .join("store/snapshots")
                    .join(id)
                    .join("release.json.minisig"),
            )
            .unwrap(),
        )
        .unwrap();
        packslip::minisign::SecretKey::from_seed([7u8; 32])
            .public_key()
            .verify(&bytes, &sig)
            .unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    fn target(&self, channel: &str) -> Option<String> {
        std::fs::read_link(self.rig.path().join("store/channels").join(channel))
            .ok()
            .and_then(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))
    }
}

#[test]
fn failed_retest_never_advances_past_a_manual_rc_rollback() {
    let t = Train::new();
    for id in ["2026-09-01T06", "2026-09-02T06", "2026-09-03T06"] {
        let (code, _, err) = t.run(
            &format!("{id}:10:00Z"),
            &["cut", "--from", "mirror", "--id", id],
        );
        assert_eq!(code, 0, "{err}");
        let (code, _, err) = t.run(
            &format!("{id}:20:00Z"),
            &["test", "--id", id, "--suite", "true"],
        );
        assert_eq!(code, 0, "{err}");
    }
    assert_eq!(t.target("rc").as_deref(), Some("2026-09-03T06"));

    let (code, _, err) = t.run(
        "2026-09-03T07:00:00Z",
        &["promote", "--channel", "rc", "--id", "2026-09-02T06"],
    );
    assert_eq!(code, 0, "{err}");
    let (code, _, _) = t.run(
        "2026-09-03T08:00:00Z",
        &["test", "--id", "2026-09-02T06", "--suite", "false"],
    );
    assert_ne!(code, 0);
    assert_eq!(
        t.target("rc").as_deref(),
        Some("2026-09-01T06"),
        "the newer passing snapshot must not be selected"
    );
}

#[test]
fn fallback_skips_a_former_rc_whose_latest_test_failed() {
    let t = Train::new();
    for id in ["2026-09-01T06", "2026-09-02T06", "2026-09-03T06"] {
        assert_eq!(
            t.run(
                &format!("{id}:10:00Z"),
                &["cut", "--from", "mirror", "--id", id]
            )
            .0,
            0
        );
        assert_eq!(
            t.run(
                &format!("{id}:20:00Z"),
                &["test", "--id", id, "--suite", "true"]
            )
            .0,
            0
        );
    }

    assert_ne!(
        t.run(
            "2026-09-03T07:00:00Z",
            &["test", "--id", "2026-09-02T06", "--suite", "false"]
        )
        .0,
        0
    );
    assert_ne!(
        t.run(
            "2026-09-03T08:00:00Z",
            &["test", "--id", "2026-09-03T06", "--suite", "false"]
        )
        .0,
        0
    );
    assert_eq!(t.target("rc").as_deref(), Some("2026-09-01T06"));
}

#[test]
fn passing_retest_does_not_retreat_a_held_rc_without_a_fallback() {
    let t = Train::new();
    let id = "2026-09-01T06";
    assert_eq!(
        t.run(
            "2026-09-01T06:10:00Z",
            &["cut", "--from", "mirror", "--id", id]
        )
        .0,
        0
    );
    assert_eq!(
        t.run(
            "2026-09-01T06:20:00Z",
            &["test", "--id", id, "--suite", "true"]
        )
        .0,
        0
    );
    assert_eq!(
        t.run(
            "2026-09-01T06:30:00Z",
            &["hold", "--id", id, "--reason", "investigating"]
        )
        .0,
        0
    );
    assert_eq!(t.target("rc").as_deref(), Some(id));
    assert_eq!(
        t.run(
            "2026-09-01T06:40:00Z",
            &["test", "--id", id, "--suite", "true"]
        )
        .0,
        0
    );
    assert_eq!(t.target("rc").as_deref(), Some(id));
    assert!(t.release(id).promoted.rc.is_some());
}

#[test]
fn cut_test_promote_hold_prune() {
    let t = Train::new();

    // Cut: edge moves, databases are digested, release.json is signed.
    let (code, out, err) = t.run("2026-09-01T06:10:00Z", &["cut", "--from", "mirror"]);
    assert_eq!(code, 0, "{err}");
    assert!(
        out.contains("cut snapshot 2026-09-01T06 (2 databases), edge -> 2026-09-01T06"),
        "{out}"
    );
    let r1 = t.release("2026-09-01T06");
    assert_eq!(r1.channel, "edge");
    assert_eq!(r1.db_digests.len(), 2);
    assert!(r1.tests.is_none());
    assert_eq!(t.target("edge").as_deref(), Some("2026-09-01T06"));
    assert!(
        t.rig
            .path()
            .join("store/snapshots/2026-09-01T06/omarchy/os/x86_64/omarchy.db")
            .is_file()
    );
    let (code, _, err) = t.run("2026-09-01T06:20:00Z", &["cut", "--from", "mirror"]);
    assert_ne!(code, 0, "same hour, same id");
    assert!(err.contains("snapshot 2026-09-01T06 exists"), "{err}");

    // The built-in check: databases parse, files are missing (partial
    // mirror) so it fails unless allowed, and it labels nothing tested
    // that it did not verify.
    let (code, _, err) = t.run("2026-09-01T07:00:00Z", &["test", "--id", "2026-09-01T06"]);
    assert_ne!(code, 0);
    assert!(
        err.contains("package file(s) listed in the databases are missing"),
        "{err}"
    );
    let r1 = t.release("2026-09-01T06");
    assert_eq!(
        r1.tests.as_ref().unwrap().result,
        omapac::channel::TestResult::Fail
    );
    assert!(t.target("rc").is_none());
    let (code, out, err) = t.run(
        "2026-09-01T07:00:00Z",
        &["test", "--id", "2026-09-01T06", "--allow-missing"],
    );
    assert_eq!(code, 0, "{err}");
    assert!(
        out.contains("tests pass, 0 tested pkgbase(s), rc -> 2026-09-01T06"),
        "{out}"
    );
    let r1 = t.release("2026-09-01T06");
    assert_eq!(r1.promoted.rc.as_deref(), Some("2026-09-01T07:00:00Z"));
    assert_eq!(t.target("rc").as_deref(), Some("2026-09-01T06"));

    // A second cut shares unchanged package files by hard link.
    let (code, _, err) = t.run(
        "2026-09-02T06:00:00Z",
        &["cut", "--from", "mirror", "--id", "2026-09-02T06"],
    );
    assert_eq!(code, 0, "{err}");
    let a = std::fs::metadata(
        t.rig
            .path()
            .join("store/snapshots/2026-09-01T06/core/os/x86_64/shared-1-1-x86_64.pkg.tar.zst"),
    )
    .unwrap();
    let b = std::fs::metadata(
        t.rig
            .path()
            .join("store/snapshots/2026-09-02T06/core/os/x86_64/shared-1-1-x86_64.pkg.tar.zst"),
    )
    .unwrap();
    assert_eq!(a.ino(), b.ino(), "package files are shared");
    assert_eq!(t.target("edge").as_deref(), Some("2026-09-02T06"));

    // An external suite: its tested lines are recorded, a failure keeps
    // rc where it is, a pass moves it.
    let (code, out, _) = t.run(
        "2026-09-02T07:00:00Z",
        &[
            "test",
            "--id",
            "2026-09-02T06",
            "--suite",
            "echo tested: hyprland; test -n \"$OMAPAC_SNAPSHOT_DIR\"; exit 1",
        ],
    );
    assert_ne!(code, 0);
    assert!(out.contains("tests fail, 1 tested pkgbase(s)"), "{out}");
    assert_eq!(t.target("rc").as_deref(), Some("2026-09-01T06"));
    let (code, out, err) = t.run(
        "2026-09-02T08:00:00Z",
        &["test", "--id", "2026-09-02T06", "--suite", "echo suite-log; echo suite-error >&2; echo tested: hyprland; echo tested: omarchy; echo tested: hyprland; test \"$OMAPAC_SNAPSHOT_ID\" = 2026-09-02T06", "--commit", "abc", "--log-url", "https://ci/1"],
    );
    assert_eq!(code, 0, "{err}");
    assert!(out.contains("suite-log"), "{out}");
    assert!(err.contains("suite-error"), "{err}");
    assert!(
        out.contains("tests pass, 2 tested pkgbase(s), rc -> 2026-09-02T06"),
        "{out}"
    );
    let r2 = t.release("2026-09-02T06");
    assert_eq!(r2.tested_pkgbases, vec!["hyprland", "omarchy"]);
    assert_eq!(r2.tests.as_ref().unwrap().commit.as_deref(), Some("abc"));
    assert!(r2.is_tested("omarchy"));

    // A failed re-test removes a snapshot from rc, and a later pass can
    // promote it again.
    let (code, _, _) = t.run(
        "2026-09-02T09:00:00Z",
        &["test", "--id", "2026-09-02T06", "--suite", "exit 1"],
    );
    assert_ne!(code, 0);
    assert_eq!(t.target("rc").as_deref(), Some("2026-09-01T06"));
    let (code, _, err) = t.run(
        "2026-09-02T10:00:00Z",
        &["test", "--id", "2026-09-02T06", "--suite", "true"],
    );
    assert_eq!(code, 0, "{err}");
    assert_eq!(t.target("rc").as_deref(), Some("2026-09-02T06"));

    // Stable needs the soak.
    let (code, _, err) = t.run("2026-09-03T08:00:00Z", &["promote", "--channel", "stable"]);
    assert_ne!(code, 0);
    assert!(err.contains("has soaked 22h of 3d; not promoting"), "{err}");
    assert!(t.target("stable").is_none());
    let (code, out, err) = t.run("2026-09-05T10:00:00Z", &["promote", "--channel", "stable"]);
    assert_eq!(code, 0, "{err}");
    assert!(out.contains("stable -> 2026-09-02T06"), "{out}");
    assert_eq!(
        t.release("2026-09-02T06").promoted.stable.as_deref(),
        Some("2026-09-05T10:00:00Z")
    );
    let (code, out, _) = t.run("2026-09-05T10:00:00Z", &["promote", "--channel", "stable"]);
    assert_eq!(code, 0);
    assert!(
        out.contains("stable already points at 2026-09-02T06"),
        "{out}"
    );
    // A maintainer promotes the older snapshot to stable deliberately, expedited.
    let (code, out, err) = t.run(
        "2026-09-05T11:00:00Z",
        &[
            "promote",
            "--channel",
            "stable",
            "--id",
            "2026-09-01T06",
            "--expedited",
        ],
    );
    assert_eq!(code, 0, "{err}");
    assert!(out.contains("stable -> 2026-09-01T06"), "{out}");
    assert!(t.release("2026-09-01T06").expedited);
    let (code, _, _) = t.run(
        "2026-09-05T12:00:00Z",
        &["promote", "--channel", "stable", "--id", "2026-09-02T06"],
    );
    assert_eq!(code, 0);

    // Hold the stable snapshot: stable and rc fall back to the earlier one.
    let (code, out, err) = t.run(
        "2026-09-06T00:00:00Z",
        &[
            "hold",
            "--id",
            "2026-09-02T06",
            "--reason",
            "hyprland regression #42",
        ],
    );
    assert_eq!(code, 0, "{err}");
    assert!(
        out.contains("held 2026-09-02T06: hyprland regression #42"),
        "{out}"
    );
    assert!(out.contains("stable -> 2026-09-01T06"), "{out}");
    assert!(out.contains("rc -> 2026-09-01T06"), "{out}");
    assert_eq!(t.target("edge").as_deref(), Some("2026-09-01T06"));
    let held = t.release("2026-09-02T06");
    assert!(held.held);
    assert_eq!(held.hold_reason.as_deref(), Some("hyprland regression #42"));
    let (code, _, err) = t.run(
        "2026-09-06T01:00:00Z",
        &["promote", "--channel", "stable", "--id", "2026-09-02T06"],
    );
    assert_ne!(code, 0);
    assert!(err.contains("is held"), "{err}");

    // Status.
    let (code, out, _) = t.run("2026-09-06T02:00:00Z", &["status", "--json"]);
    assert_eq!(code, 0);
    let status: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(status["channels"]["stable"], "2026-09-01T06");
    assert_eq!(status["snapshots"][0]["id"], "2026-09-02T06");
    assert_eq!(status["snapshots"][0]["held"], "hyprland regression #42");
    assert_eq!(status["snapshots"][0]["tests"], "true:pass");
    let (_, out, _) = t.run("2026-09-06T02:00:00Z", &["status"]);
    assert!(out.contains("stable  -> 2026-09-01T06"), "{out}");
    assert!(out.contains("HELD: hyprland regression #42"), "{out}");

    // Unhold clears the flag but moves nothing.
    let (code, _, _) = t.run("2026-09-06T03:00:00Z", &["unhold", "--id", "2026-09-02T06"]);
    assert_eq!(code, 0);
    assert!(!t.release("2026-09-02T06").held);
    assert_eq!(t.target("stable").as_deref(), Some("2026-09-01T06"));

    // Prune: channel targets are kept; a snapshot that was ever stable
    // keeps the longer retention.
    let (code, _, _) = t.run(
        "2026-09-10T00:00:00Z",
        &["cut", "--from", "mirror", "--id", "2026-09-10T00"],
    );
    assert_eq!(code, 0);
    let (code, out, _) = t.run(
        "2026-12-15T00:00:00Z",
        &["prune", "--retain", "90d", "--stable-retain", "365d"],
    );
    assert_eq!(code, 0);
    assert!(
        out.contains("0 snapshot(s) past retention"),
        "2026-09-02T06 was stable once, so it stays for a year: {out}"
    );
    let (code, out, _) = t.run(
        "2026-12-15T00:00:00Z",
        &[
            "prune",
            "--retain",
            "90d",
            "--stable-retain",
            "100d",
            "--dry-run",
        ],
    );
    assert_eq!(code, 0);
    assert!(out.contains("would remove 2026-09-02T06 (103d"), "{out}");
    assert!(
        !out.contains("2026-09-01T06"),
        "stable target is kept: {out}"
    );
    assert!(!out.contains("2026-09-10T00"), "edge target is kept: {out}");
    assert!(t.rig.path().join("store/snapshots/2026-09-02T06").is_dir());
    let (code, out, _) = t.run(
        "2026-12-15T00:00:00Z",
        &["prune", "--retain", "90d", "--stable-retain", "100d"],
    );
    assert_eq!(code, 0);
    assert!(out.contains("removed 2026-09-02T06"), "{out}");
    assert!(!t.rig.path().join("store/snapshots/2026-09-02T06").is_dir());
    assert!(t.rig.path().join("store/snapshots/2026-09-01T06").is_dir());
}

#[test]
fn check_catches_a_tampered_database() {
    let t = Train::new();
    let second_arch = t.rig.path().join("mirror/core/os/aarch64");
    std::fs::create_dir_all(&second_arch).unwrap();
    std::fs::copy(fixtures().join("sync/core.db"), second_arch.join("core.db")).unwrap();
    let (code, _, err) = t.run("2026-09-01T06:00:00Z", &["cut", "--from", "mirror"]);
    assert_eq!(code, 0, "{err}");
    let release = t.release("2026-09-01T06");
    assert!(release.db_digests.contains_key("core/os/x86_64/core.db"));
    assert!(release.db_digests.contains_key("core/os/aarch64/core.db"));
    let (code, out, err) = t.run(
        "2026-09-01T07:00:00Z",
        &["check", "--id", "2026-09-01T06", "--allow-missing"],
    );
    assert_eq!(code, 0, "{err}");
    assert!(out.is_empty(), "nothing verified without files: {out}");
    // Replace the omarchy database in the snapshot.
    let db = t
        .rig
        .path()
        .join("store/snapshots/2026-09-01T06/omarchy/os/x86_64/omarchy.db");
    std::fs::copy(fixtures().join("sync/core.db"), &db).unwrap();
    let (code, _, err) = t.run(
        "2026-09-01T07:00:00Z",
        &["check", "--id", "2026-09-01T06", "--allow-missing"],
    );
    assert_ne!(code, 0);
    assert!(
        err.contains("omarchy/os/x86_64/omarchy.db: database digest"),
        "{err}"
    );
    assert!(err.contains("is inconsistent"), "{err}");
}

#[test]
fn store_and_key_are_required() {
    let rig = Rig::new();
    let (code, _, err) = rig.run(&["snapshot", "status"]);
    assert_ne!(code, 0);
    assert!(err.contains("--store is required"), "{err}");
    let (code, _, err) = rig.run(&["snapshot", "--store", "s", "cut", "--from", "m"]);
    assert_ne!(code, 0);
    assert!(err.contains("--key is required"), "{err}");
}
