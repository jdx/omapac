//! The ledger records what omapac did, and `list --ledger` / `--drift`
//! read it back.

mod common;

use common::Rig;

const CURL_PLAN: &str = "curl\\t8.16.0-1\\tcore\\thttps://m/core/os/x86_64/curl-8.16.0-1-x86_64.pkg.tar.zst\\t1000000\\n\
                         libpsl\\t0.21.5-2\\tcore\\thttps://m/core/os/x86_64/libpsl-0.21.5-2-x86_64.pkg.tar.zst\\t50000\\n";

#[test]
fn install_records_and_remove_forgets() {
    let rig = Rig::new();
    let ledger = rig.root.join("var/lib/omapac/state.json");
    rig.write_root(
        "/var/lib/omapac/state.json",
        r#"{"schema":1,"packages":{"oldcurl":{"version":"1","tier":{"tier":"arch"},"repo":"core","explicit":true,"by":"install","at":1}}}"#,
    );
    let replace_plan = format!("{CURL_PLAN}oldcurl\t1\tlocal\toldcurl\t(null)\n");
    let (code, _, err) = rig.run(&["install", "-y", "curl"], &replace_plan, 0);
    assert_eq!(code, 0, "{err}");
    let state: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&ledger).unwrap()).unwrap();
    assert_eq!(state["schema"], 1);
    assert_eq!(state["packages"]["curl"]["explicit"], true);
    assert_eq!(state["packages"]["curl"]["by"], "install");
    assert_eq!(state["packages"]["curl"]["tier"]["tier"], "arch");
    assert_eq!(state["packages"]["libpsl"]["explicit"], false);
    assert!(
        state["packages"]["oldcurl"].is_null(),
        "install-time replacements are removed from the ledger: {state}"
    );

    // Dry runs and refused plans record nothing.
    let before = std::fs::read_to_string(&ledger).unwrap();
    rig.run(&["install", "-n", "pacman"], CURL_PLAN, 0);
    rig.run(&["install", "-y", "pacman"], CURL_PLAN, 2);
    assert_eq!(std::fs::read_to_string(&ledger).unwrap(), before);

    // The fake never really installed curl, so the ledger is ahead of the
    // machine: that is drift.
    let (_, out, _) = rig.run(&["list", "--drift"], "", 0);
    assert!(
        out.contains("curl") && out.contains("removed outside omapac"),
        "{out}"
    );
    let (_, out, _) = rig.run(&["list", "--drift", "--explicit"], "", 0);
    assert!(out.contains("curl") && !out.contains("libpsl"), "{out}");
    let (_, out, _) = rig.run(&["list", "--drift", "--deps"], "", 0);
    assert!(!out.contains("curl") && out.contains("libpsl"), "{out}");
    let (_, out, _) = rig.run(&["list", "--drift", "--foreign"], "", 0);
    assert!(out.is_empty(), "{out}");
    let (_, out, _) = rig.run(&["list", "--drift", "--orphans"], "", 0);
    assert!(out.is_empty(), "{out}");

    let remove = "yay\\t13.0.1-1\\tlocal\\tyay-13.0.1-1\\t(null)\\ncurl\\t8.16.0-1\\tlocal\\tcurl\\t(null)\\n";
    let (code, _, err) = rig.run(&["remove", "-y", "yay"], remove, 0);
    assert_eq!(code, 0, "{err}");
    let state: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&ledger).unwrap()).unwrap();
    assert!(state["packages"]["curl"].is_null(), "{state}");
    assert!(state["packages"]["libpsl"].is_object(), "{state}");
}

#[test]
fn as_deps_records_named_targets_as_dependencies() {
    let rig = Rig::new();
    let (code, _, err) = rig.run(&["install", "-y", "--as-deps", "curl"], CURL_PLAN, 0);
    assert_eq!(code, 0, "{err}");
    let state: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(rig.root.join("var/lib/omapac/state.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(state["packages"]["curl"]["explicit"], false);
    assert_eq!(state["packages"]["libpsl"]["explicit"], false);
}

#[test]
fn repeated_commands_repair_a_missing_ledger_write() {
    let rig = Rig::new();
    let ledger = rig.root.join("var/lib/omapac/state.json");

    let (code, _, err) = rig.run(&["install", "-y", "pacman"], "", 0);
    assert_eq!(code, 0, "{err}");
    let state: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&ledger).unwrap()).unwrap();
    assert_eq!(state["packages"]["pacman"]["version"], "7.1.0-2");

    rig.write_root(
        "/var/lib/omapac/state.json",
        r#"{"schema":1,"packages":{"curl":{"version":"8.16.0-1","tier":{"tier":"arch"},"repo":"core","explicit":true,"by":"install","at":1}}}"#,
    );
    let (code, out, err) = rig.run(&["remove", "-y", "curl"], "", 0);
    assert_eq!(code, 0, "{out}\n{err}");
    let state: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&ledger).unwrap()).unwrap();
    assert!(state["packages"]["curl"].is_null(), "{state}");

    std::fs::create_dir_all(rig.user_manifest().parent().unwrap()).unwrap();
    std::fs::write(rig.user_manifest(), "[packages]\npacman = {}\n").unwrap();
    std::fs::remove_file(&ledger).unwrap();
    let (code, _, err) = rig.run(&["apply", "-y"], "", 0);
    assert_eq!(code, 0, "{err}");
    let state: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&ledger).unwrap()).unwrap();
    assert_eq!(state["packages"]["pacman"]["by"], "apply");

    let mut preserved = state;
    preserved["packages"]["pacman"]["by"] = "install".into();
    preserved["packages"]["pacman"]["at"] = 123.into();
    std::fs::write(&ledger, serde_json::to_vec(&preserved).unwrap()).unwrap();
    let (code, _, err) = rig.run(&["apply", "-y"], "", 0);
    assert_eq!(code, 0, "{err}");
    let state: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&ledger).unwrap()).unwrap();
    assert_eq!(state["packages"]["pacman"]["by"], "install");
    assert_eq!(state["packages"]["pacman"]["at"], 123);

    std::fs::remove_file(&ledger).unwrap();
    let (code, _, err) = rig.run(&["add", "-y", "pacman"], "", 0);
    assert_eq!(code, 0, "{err}");
    let state: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&ledger).unwrap()).unwrap();
    assert_eq!(state["packages"]["pacman"]["by"], "add");
}

#[test]
fn ledger_and_drift_views() {
    let rig = Rig::new();
    // Pretend omapac installed pacman at an older version than the fixture
    // local database now has, and yay at the version it has.
    rig.write_root(
        "/var/lib/omapac/state.json",
        r#"{"schema":1,"packages":{
            "pacman":{"version":"7.0.0-1","tier":{"tier":"arch"},"repo":"core","explicit":true,"by":"add","at":1756800000},
            "yay":{"version":"13.0.1-1","tier":{"tier":"opr"},"repo":"omarchy","explicit":true,"by":"install","at":1756800000}
        }}"#,
    );
    let (code, out, err) = rig.run(&["list", "--ledger"], "", 0);
    assert_eq!(code, 0, "{err}");
    insta::assert_snapshot!(out);

    let (_, out, _) = rig.run(&["list", "--drift"], "", 0);
    assert!(
        out.contains("pacman") && out.contains("recorded 7.0.0-1, installed 7.1.0-2"),
        "{out}"
    );
    assert!(!out.contains("yay"), "yay matches the ledger: {out}");

    let (_, out, _) = rig.run(&["list", "--json", "--ledger"], "", 0);
    let entries: Vec<serde_json::Value> = serde_json::from_str(&out).unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0]["recorded"]["by"], "add");
    assert_eq!(entries[0]["drift"], "recorded 7.0.0-1, installed 7.1.0-2");
    assert!(entries[1]["drift"].is_null());
}

#[test]
fn a_newer_schema_is_refused() {
    let rig = Rig::new();
    rig.write_root("/var/lib/omapac/state.json", r#"{"schema":9}"#);
    let (code, _, err) = rig.run(&["list", "--ledger"], "", 0);
    assert_ne!(code, 0);
    assert!(err.contains("schema 9"), "{err}");

    let (code, out, err) = rig.run(&["list"], "", 0);
    assert_eq!(code, 0, "{err}");
    assert!(out.contains("pacman"), "{out}");
}

#[test]
fn hidden_ledger_merge_reads_a_patch_from_stdin() {
    use std::io::Write as _;
    use std::process::{Command, Stdio};
    let rig = Rig::new();
    let mut child = Command::new(env!("CARGO_BIN_EXE_omapac"))
        .arg("--sysroot")
        .arg(&rig.root)
        .arg("__ledger")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(br#"{"upsert":{"curl":{"version":"1-1","tier":{"tier":"arch"},"explicit":true,"by":"test","at":1}}}"#)
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let state = std::fs::read_to_string(rig.root.join("var/lib/omapac/state.json")).unwrap();
    assert!(state.contains("\"curl\""), "{state}");

    let help = Command::new(env!("CARGO_BIN_EXE_omapac"))
        .arg("--help")
        .output()
        .unwrap();
    assert!(
        !String::from_utf8_lossy(&help.stdout).contains("__ledger"),
        "hidden"
    );
}
