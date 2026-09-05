mod common;

use common::Rig;
use std::process::Command;

fn run(rig: &Rig, args: &[&str], rpc: &str) -> (i32, String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_pacvamp"))
        .env("HOME", &rig.home)
        .env_remove("XDG_CONFIG_HOME")
        .env_remove("PACVAMP_MANAGED_CONFIG_PATH")
        .env("PACVAMP_AUR_RPC_BASE", rpc)
        .arg("--sysroot")
        .arg(&rig.root)
        .arg("import")
        .args(args)
        .output()
        .unwrap();
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into(),
        String::from_utf8_lossy(&out.stderr).into(),
    )
}

#[test]
fn preview_and_import_preserve_policy_and_never_create_approvals() {
    let rig = Rig::new();
    rig.write_root(
        "/var/lib/pacman/local/local-tool-1/desc",
        "%NAME%\nlocal-tool\n\n%VERSION%\n1\n\n%REASON%\n0\n",
    );
    // Make yay explicit and foreign; glibc remains a dependency.
    rig.write_root(
        "/var/lib/pacman/local/yay-13.0.1-1/desc",
        "%NAME%\nyay\n\n%VERSION%\n13.0.1-1\n\n%REASON%\n0\n",
    );
    std::fs::remove_file(rig.root.join("var/lib/pacman/sync/omarchy.db")).unwrap();
    rig.write_root(
        "/etc/pacvamp/pacvamp.toml",
        "[packages]\npacman = { hold = true }\n",
    );
    std::fs::create_dir_all(rig.user_manifest().parent().unwrap()).unwrap();
    let original = "# keep my settings\n[policy]\naur.min_commit_age = \"72h\"\n";
    std::fs::write(rig.user_manifest(), original).unwrap();
    let rpc = common::http::serve(vec![(
        "/rpc/v5/info",
        include_str!("../fixtures/aur/info.json").into(),
    )]);
    let (code, out, err) = run(&rig, &["--json"], &rpc);
    assert_eq!(code, 0, "{err}");
    let json: serde_json::Value = serde_json::from_str(&out).unwrap();
    let entries = json["entries"].as_array().unwrap();
    assert!(!entries.iter().any(|e| e["name"] == "glibc"));
    assert_eq!(
        entries.iter().find(|e| e["name"] == "pacman").unwrap()["action"],
        "preserve"
    );
    assert_eq!(
        entries.iter().find(|e| e["name"] == "local-tool").unwrap()["action"],
        "skip"
    );
    let yay = entries.iter().find(|e| e["name"] == "yay").unwrap();
    assert_eq!(yay["source"], "aur");
    assert_eq!(yay["review"], "unreviewed");
    assert_eq!(
        std::fs::read_to_string(rig.user_manifest()).unwrap(),
        original
    );
    assert!(!rig.user_manifest().with_extension("lock").exists());
    let (code, out, err) = run(&rig, &["--write"], &rpc);
    assert_eq!(code, 0, "{out}\n{err}");
    let written = std::fs::read_to_string(rig.user_manifest()).unwrap();
    assert!(written.contains("# keep my settings"));
    assert!(written.contains("72h"));
    assert!(written.contains("yay = { source = \"aur\" }"), "{written}");
    assert!(!written.contains("pacman ="));
    assert!(!written.contains("local-tool ="));
    assert!(!rig.user_manifest().with_extension("lock").exists());
    assert!(!rig.root.join("var/lib/pacvamp/state.json").exists());
    assert!(rig.log().is_empty());
    assert_eq!(run(&rig, &["--write"], &rpc).0, 0);
    assert_eq!(
        std::fs::read_to_string(rig.user_manifest()).unwrap(),
        written
    );
}

#[test]
fn offline_import_adds_repository_packages_and_leaves_foreign_unresolved() {
    let rig = Rig::new();
    rig.write_root(
        "/var/lib/pacman/local/foreign-1/desc",
        "%NAME%\nforeign\n\n%VERSION%\n1\n\n%REASON%\n0\n",
    );
    let (code, out, err) = run(&rig, &["--offline", "--json"], "http://127.0.0.1:1");
    assert_eq!(code, 0, "{err}");
    let json: serde_json::Value = serde_json::from_str(&out).unwrap();
    let entries = json["entries"].as_array().unwrap();
    let native = entries.iter().find(|e| e["name"] == "pacman").unwrap();
    assert_eq!(native["action"], "add");
    assert_eq!(native["repo"], "core");
    assert_eq!(
        entries.iter().find(|e| e["name"] == "foreign").unwrap()["action"],
        "skip"
    );
    assert!(!rig.user_manifest().exists());
    assert_eq!(
        run(&rig, &["--offline", "--write"], "http://127.0.0.1:1").0,
        0
    );
    assert!(
        std::fs::read_to_string(rig.user_manifest())
            .unwrap()
            .contains("repo = \"core\"")
    );
    assert_ne!(run(&rig, &["--json", "--write"], "http://127.0.0.1:1").0, 0);
}

#[test]
fn failed_aur_lookup_does_not_guess_a_foreign_source() {
    let rig = Rig::new();
    rig.write_root(
        "/var/lib/pacman/local/foreign-1/desc",
        "%NAME%\nforeign\n\n%VERSION%\n1\n\n%REASON%\n0\n",
    );
    let (code, out, err) = run(&rig, &["--json"], "http://127.0.0.1:1");
    assert_eq!(code, 0, "{err}");
    let json: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert!(!json["warnings"].as_array().unwrap().is_empty());
    let foreign = json["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["name"] == "foreign")
        .unwrap();
    assert!(foreign["source"].is_null());
    assert_eq!(foreign["action"], "skip");
}
