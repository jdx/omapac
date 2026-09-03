//! `channel`, `channel pin`, `channel unpin`, and `rollback` against
//! signed release manifests from a local server and the fake pacman.

mod common;

use std::process::Command;

use common::Rig;
use packslip::minisign::SecretKey;

fn release(id: &str, channel: &str, promoted: &str, result: &str) -> String {
    format!(
        r#"{{"version":1,"id":"{id}","channel":"{channel}","arch_snapshot":"{id}","opr_index_sequence":7,
           "created_at":"{id}:00:00Z","tests":{{"suite":"omarchy-train","result":"{result}"}},
           "tested_pkgbases":["pacman","glibc"],"promoted":{promoted},"db_digests":{{}}}}"#
    )
}

struct Setup {
    rig: Rig,
    base: String,
}

fn setup() -> Setup {
    let rig = Rig::new();
    let key = SecretKey::from_seed([42u8; 32]);
    rig.write_root("/etc/omapac/keys/omarchy.pub", &key.public_key().to_file());
    let sign = |body: &str| key.sign(body.as_bytes(), "feed").to_file();
    let current = release(
        "2026-09-03T06",
        "stable",
        r#"{"rc":"2026-09-03T08:00:00Z","stable":"2026-09-06T08:00:00Z"}"#,
        "pass",
    );
    let good = release(
        "2026-09-01T06",
        "stable",
        r#"{"rc":"2026-09-01T08:00:00Z"}"#,
        "pass",
    );
    let bad = release("2026-09-02T06", "edge", "{}", "fail");
    let base = common::http::serve(vec![
        ("/stable/x86_64/release.json.minisig", sign(&current)),
        ("/stable/x86_64/release.json", current.clone()),
        ("/snapshots/2026-09-01T06/release.json.minisig", sign(&good)),
        ("/snapshots/2026-09-01T06/release.json", good.clone()),
        ("/snapshots/2026-09-02T06/release.json.minisig", sign(&bad)),
        ("/snapshots/2026-09-02T06/release.json", bad.clone()),
    ]);
    let conf = common::DEFAULT_CONF.replace(
        "Server = https://pkgs.omarchy.org/stable/$arch",
        &format!("Server = {base}/stable/$arch"),
    );
    rig.write_root("/etc/pacman.conf", &conf);
    rig.write_root(
        "/etc/pacman.d/mirrorlist",
        "Server = https://stable-mirror.omarchy.org/$repo/os/$arch\n",
    );
    rig.write_root(
        "/etc/omapac/conf.d/10-omarchy.toml",
        &format!(
            "[channel]\nsnapshot_base = \"{base}/snapshots\"\n[update]\nignore_group = [\"legacy\"]\n"
        ),
    );
    Setup { rig, base }
}

fn run(s: &Setup, args: &[&str], print: &str) -> (i32, String, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_omapac"))
        .env("PATH", format!("{}:/usr/bin:/bin", s.rig.bin.display()))
        .env("HOME", &s.rig.home)
        .env_remove("XDG_CONFIG_HOME")
        .env("XDG_CACHE_HOME", s.rig.dir.path().join("cache"))
        .env("FAKE_PACMAN_LOG", &s.rig.log)
        .env("FAKE_PACMAN_PRINT", print)
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
fn channel_shows_the_release_and_pin_state() {
    let s = setup();
    let (code, out, err) = run(&s, &["channel"], "");
    assert_eq!(code, 0, "{err}\n{out}");
    assert!(out.contains("channel: stable"), "{out}");
    assert!(
        out.contains("snapshot: 2026-09-03T06 (tests pass, stable since 2026-09-06T08:00:00Z)"),
        "{out}"
    );
    assert!(out.contains("tested packages: 2"), "{out}");
    assert!(out.contains("pinned: no"), "{out}");
    let (_, out, _) = run(&s, &["channel", "--json"], "");
    let json: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(json["release"]["id"], "2026-09-03T06");
    assert!(json["pinned"].is_null());
}

#[test]
fn update_records_the_release_when_no_packages_change() {
    let s = setup();
    let (code, out, err) = run(&s, &["update", "--no-aur", "-y"], "");
    assert_eq!(code, 0, "{err}\n{out}");
    let ledger = std::fs::read_to_string(s.rig.root.join("var/lib/omapac/state.json")).unwrap();
    assert!(
        ledger.contains("\"snapshot\": \"2026-09-03T06\""),
        "{ledger}"
    );
    assert!(
        s.rig
            .log()
            .iter()
            .any(|line| line.ends_with("-Sy --noconfirm"))
    );
}

#[test]
fn pin_writes_the_mirrorlist_and_unpin_restores_it() {
    let s = setup();
    let mirrorlist = s.rig.root.join("etc/pacman.d/mirrorlist");
    let (code, _, err) = run(&s, &["channel", "pin", "2026-09-02T06"], "");
    assert_ne!(code, 0, "an unpromoted snapshot needs --force");
    assert!(
        err.contains("never reached rc or stable (tests: Fail)"),
        "{err}"
    );

    let (code, out, err) = run(&s, &["channel", "pin", "2026-09-01T06"], "");
    assert_eq!(code, 0, "{err}");
    assert!(
        out.contains("pinned the Arch mirror to snapshot 2026-09-01T06 (tests pass, rc since"),
        "{out}"
    );
    let text = std::fs::read_to_string(&mirrorlist).unwrap();
    assert!(
        text.contains(&format!(
            "Server = {}/snapshots/2026-09-01T06/$repo/os/$arch",
            s.base
        )),
        "{text}"
    );
    assert!(text.contains("# omapac-pin: 2026-09-01T06"), "{text}");
    let backup =
        std::fs::read_to_string(s.rig.root.join("etc/pacman.d/mirrorlist.omapac-unpinned"))
            .unwrap();
    assert!(backup.contains("stable-mirror.omarchy.org"), "{backup}");
    let ledger = std::fs::read_to_string(s.rig.root.join("var/lib/omapac/state.json")).unwrap();
    assert!(
        ledger.contains("\"snapshot\": \"2026-09-01T06\""),
        "{ledger}"
    );

    let (_, out, _) = run(&s, &["channel"], "");
    assert!(out.contains("pinned: 2026-09-01T06"), "{out}");
    assert!(out.contains("last converged: 2026-09-01T06"), "{out}");

    let (code, out, err) = run(&s, &["channel", "unpin"], "");
    assert_eq!(code, 0, "{err}");
    assert!(out.contains("restored"), "{out}");
    let text = std::fs::read_to_string(&mirrorlist).unwrap();
    assert_eq!(
        text,
        "Server = https://stable-mirror.omarchy.org/$repo/os/$arch\n"
    );
    assert!(
        !s.rig
            .root
            .join("etc/pacman.d/mirrorlist.omapac-unpinned")
            .exists()
    );
    // The next pin must back up edits made after unpinning.
    std::fs::write(&mirrorlist, "Server = https://new/$repo/os/$arch\n").unwrap();
    let (code, _, err) = run(&s, &["channel", "pin", "2026-09-01T06"], "");
    assert_eq!(code, 0, "{err}");
    let backup =
        std::fs::read_to_string(s.rig.root.join("etc/pacman.d/mirrorlist.omapac-unpinned"))
            .unwrap();
    assert!(backup.contains("https://new/"), "{backup}");
    let (code, _, err) = run(&s, &["channel", "unpin"], "");
    assert_eq!(code, 0, "{err}");
    let (_, out, _) = run(&s, &["channel", "unpin"], "");
    assert!(out.contains("not pinned"), "{out}");

    let (code, _, err) = run(&s, &["channel", "pin", "2026-09-09T09"], "");
    assert_ne!(code, 0);
    assert!(err.contains("fetching release.json"), "{err}");
}

#[test]
fn offline_pin_uses_the_cached_snapshot_manifest() {
    let s = setup();
    let (code, _, err) = run(&s, &["channel", "pin", "2026-09-01T06"], "");
    assert_eq!(code, 0, "{err}");
    let (code, _, err) = run(&s, &["channel", "unpin"], "");
    assert_eq!(code, 0, "{err}");
    s.rig.write_root(
        "/etc/omapac/conf.d/10-omarchy.toml",
        "[channel]\nsnapshot_base = \"http://127.0.0.1:9/snapshots\"\n",
    );
    let (code, _, err) = run(&s, &["channel", "--offline", "pin", "2026-09-01T06"], "");
    assert_eq!(code, 0, "cached offline pin failed: {err}");
}

#[test]
fn rollback_pins_refreshes_and_syncs_with_downgrades() {
    let s = setup();
    let plan = "pacman\\t7.0.0-1\\tcore\\thttps://m/pacman.pkg\\t1000\\n";
    let (code, out, err) = run(&s, &["rollback", "--snapshot", "2026-09-01T06", "-y"], plan);
    assert_eq!(code, 0, "{err}\n{out}");
    assert!(out.contains("pinned to snapshot 2026-09-01T06"), "{out}");
    let log = s.rig.log();
    assert!(
        log[0].contains("-Syy --noconfirm"),
        "forced refresh after pinning: {log:?}"
    );
    assert!(log.iter().any(|l| l.contains("-Suu --print")), "{log:?}");
    assert!(
        log.iter().any(|l| l.contains("--ignoregroup legacy")),
        "{log:?}"
    );
    let apply = log.iter().find(|l| l.contains("-Suu --noconfirm")).unwrap();
    assert!(apply.contains("OMARCHY_UPDATE_PACMAN=1"), "{apply}");
    let ledger = std::fs::read_to_string(s.rig.root.join("var/lib/omapac/state.json")).unwrap();
    assert!(ledger.contains("\"by\": \"rollback\""), "{ledger}");
}

#[test]
fn rollback_dry_run_prints_the_downgrade_plan_and_command() {
    let s = setup();
    let plan = "pacman\\t7.0.0-1\\tcore\\thttps://m/pacman.pkg\\t1000\\n";
    let (code, out, err) = run(&s, &["rollback", "--snapshot", "2026-09-01T06", "-n"], plan);
    assert_eq!(code, 0, "{err}\n{out}");
    assert!(out.contains("roll back 1 package(s)"), "{out}");
    assert!(out.contains("would run:") && out.contains("-Suu"), "{out}");
    let log = s.rig.log();
    assert!(log[0].contains("-Syy --noconfirm"), "{log:?}");
    assert!(log[0].contains("--sysroot"), "{log:?}");
    assert!(log[1].contains("-Suu --print"), "{log:?}");
    assert_eq!(
        std::fs::read_to_string(s.rig.root.join("etc/pacman.d/mirrorlist")).unwrap(),
        "Server = https://stable-mirror.omarchy.org/$repo/os/$arch\n"
    );
}

#[test]
fn rollback_restores_the_pin_when_confirmation_fails() {
    let s = setup();
    let original = std::fs::read_to_string(s.rig.root.join("etc/pacman.d/mirrorlist")).unwrap();
    let plan = "pacman\\t7.0.0-1\\tcore\\thttps://m/pacman.pkg\\t1000\\n";
    let (code, _, err) = run(&s, &["rollback", "--snapshot", "2026-09-01T06"], plan);
    assert_ne!(code, 0);
    assert!(err.contains("no terminal to ask on; pass -y"), "{err}");
    assert_eq!(
        std::fs::read_to_string(s.rig.root.join("etc/pacman.d/mirrorlist")).unwrap(),
        original
    );
    let ledger = std::fs::read_to_string(s.rig.root.join("var/lib/omapac/state.json")).unwrap();
    assert!(!ledger.contains("2026-09-01T06"), "{ledger}");
}

#[test]
fn no_snapshot_base_is_a_clear_error() {
    let s = setup();
    std::fs::remove_file(s.rig.root.join("etc/omapac/conf.d/10-omarchy.toml")).unwrap();
    let (code, _, err) = run(&s, &["channel", "pin", "2026-09-01T06"], "");
    assert_ne!(code, 0);
    assert!(err.contains("no snapshot store configured"), "{err}");
}
