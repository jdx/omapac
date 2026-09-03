//! `search --aur` and the `info` fallback to the AUR, against a local HTTP
//! server that replays captured RPC responses.

mod common;

use std::process::Command;

use common::Rig;

const INFO: &str = include_str!("../fixtures/aur/info.json");
const SEARCH: &str = include_str!("../fixtures/aur/search.json");

fn rpc_server() -> String {
    common::http::serve(vec![
        ("/rpc/v5/info", INFO.to_string()),
        ("/rpc/v5/search/", SEARCH.to_string()),
    ])
}

fn run(rig: &Rig, base: &str, args: &[&str]) -> (i32, String, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_omapac"))
        .env("HOME", &rig.home)
        .env("OMAPAC_AUR_RPC_BASE", base)
        .arg("--sysroot")
        .arg(&rig.root)
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
fn search_aur_shows_votes_maintainer_and_age() {
    let rig = Rig::new();
    let base = rpc_server();
    let (code, out, err) = run(&rig, &base, &["search", "--aur", "yay"]);
    assert_eq!(code, 0, "{err}");
    assert!(out.contains("aur/yay 13.0.1-1 [aur] [installed]"), "{out}");
    assert!(
        out.contains("votes 2651, maintainer jguer, updated"),
        "{out}"
    );
    assert!(out.contains("ago)"), "{out}");
    let first = out.lines().next().unwrap();
    assert!(first.starts_with("aur/yay "), "most popular first: {first}");

    // A second term filters the RPC's results locally.
    let (_, out, _) = run(&rig, &base, &["search", "--aur", "yay", "flatpak"]);
    assert!(out.contains("aur/akp"), "{out}");
    assert!(!out.contains("aur/yay "), "{out}");

    let (_, out, _) = run(&rig, &base, &["search", "--aur", "--json", "yay"]);
    let hits: Vec<serde_json::Value> = serde_json::from_str(&out).unwrap();
    let yay = hits.iter().find(|h| h["name"] == "yay").unwrap();
    assert_eq!(yay["tier"]["tier"], "aur");
    assert_eq!(yay["aur"]["votes"], 2651);
    assert_eq!(yay["installed"], "13.0.1-1");
}

#[test]
fn info_falls_back_to_the_aur() {
    let rig = Rig::new();
    let base = rpc_server();
    // google-chrome is in no fixture database, so info asks the AUR.
    let (code, out, err) = run(&rig, &base, &["info", "google-chrome"]);
    assert_eq!(code, 0, "{err}");
    assert!(out.contains("Repository       aur [aur]"), "{out}");
    assert!(out.contains("Maintainer       gromit"), "{out}");
    assert!(!out.contains("Submitter"), "absent in the fixture: {out}");
    assert!(out.contains("Votes            2368"), "{out}");
    assert!(out.contains("First Submitted  2010-05-25"), "{out}");
    assert!(out.contains("Out Of Date      no"), "{out}");
    assert!(out.contains("Installed        no"), "{out}");
    assert!(!out.contains("Signature"), "{out}");

    // --aur forces the AUR view even for a repository package.
    let (_, out, _) = run(&rig, &base, &["info", "--aur", "yay"]);
    assert!(out.contains("Repository       aur [aur]"), "{out}");
    assert!(out.contains("Submitter        jguer"), "{out}");
    assert!(
        out.contains("Installed        13.0.1-1 (dependency)"),
        "{out}"
    );

    // Without --aur, yay comes from [omarchy].
    let (_, out, _) = run(&rig, &base, &["info", "yay"]);
    assert!(out.contains("Repository       omarchy [opr]"), "{out}");

    // --no-aur never asks.
    let (code, _, err) = run(&rig, &base, &["info", "--no-aur", "google-chrome"]);
    assert_ne!(code, 0);
    assert!(err.contains("package not found: google-chrome"), "{err}");

    let (_, out, _) = run(&rig, &base, &["info", "--json", "google-chrome"]);
    let infos: Vec<serde_json::Value> = serde_json::from_str(&out).unwrap();
    assert_eq!(infos[0]["aur"]["maintainer"], "gromit");
    assert!(infos[0]["aur"]["submitter"].is_null());
}

#[test]
fn an_unreachable_aur_is_a_clear_error() {
    let rig = Rig::new();
    let (code, _, err) = run(&rig, "http://127.0.0.1:9", &["search", "--aur", "yay"]);
    assert_ne!(code, 0);
    assert!(err.contains("searching the AUR"), "{err}");

    // Installed foreign metadata remains useful during an AUR outage.
    std::fs::remove_file(rig.root.join("var/lib/pacman/sync/omarchy.db")).unwrap();
    let (code, out, err) = run(&rig, "http://127.0.0.1:9", &["info", "yay"]);
    assert_eq!(code, 0, "{err}");
    assert!(out.contains("Repository       none [foreign]"), "{out}");
    assert!(err.contains("AUR metadata unavailable"), "{err}");
}
