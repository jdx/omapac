//! `audit` against a local copy of the security tracker and the fixture
//! local database (pacman 7.1.0-2, glibc, yay).

mod common;

use std::process::Command;

use common::Rig;

const TRACKER: &str = r#"[
  {"name":"AVG-100","packages":["pacman"],"status":"Vulnerable","severity":"High","type":"arbitrary code execution","affected":"7.1.0-2","fixed":"7.1.1-1","ticket":null,"issues":["CVE-2026-1000"],"advisories":[]},
  {"name":"AVG-101","packages":["glibc"],"status":"Fixed","severity":"Critical","type":"privilege escalation","affected":"2.3-1","fixed":"2.4-1","ticket":null,"issues":["CVE-2026-1001"],"advisories":["ASA-202609-1"]},
  {"name":"AVG-102","packages":["yay"],"status":"Vulnerable","severity":"Medium","type":"denial of service","affected":"13.0.1-1","fixed":null,"ticket":null,"issues":["CVE-2026-1002"],"advisories":[]},
  {"name":"AVG-103","packages":["pacman"],"status":"Not affected","severity":"Critical","type":"other","affected":"7.1.0-2","fixed":null,"ticket":null,"issues":[],"advisories":[]},
  {"name":"AVG-104","packages":["notinstalled"],"status":"Vulnerable","severity":"Critical","type":"other","affected":"1-1","fixed":null,"ticket":null,"issues":[],"advisories":[]}
]"#;

fn run(rig: &Rig, url: &str, args: &[&str]) -> (i32, String, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_omapac"))
        .env("PATH", format!("{}:/usr/bin:/bin", rig.bin.display()))
        .env("HOME", &rig.home)
        .env_remove("XDG_CONFIG_HOME")
        .env("XDG_CACHE_HOME", rig.dir.path().join("cache"))
        .env("OMAPAC_SECURITY_TRACKER_URL", url)
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
fn audit_lists_open_issues_by_severity() {
    let rig = Rig::new();
    let base = common::http::serve(vec![("/all.json", TRACKER.to_string())]);
    let url = format!("{base}/all.json");
    let (code, out, err) = run(&rig, &url, &["audit"]);
    assert_eq!(code, 0, "{err}");
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(lines.len(), 2, "{out}");
    assert!(lines[0].starts_with("High      pacman 7.1.0-2 (AVG-100) arbitrary code execution: fixed in 7.1.1-1  [CVE-2026-1000]"), "{out}");
    assert!(
        lines[1].starts_with("Medium    yay 13.0.1-1 (AVG-102) denial of service: no fix yet"),
        "{out}"
    );
    assert!(
        !out.contains("glibc"),
        "fixed below the installed version: {out}"
    );

    let (code, out, _) = run(&rig, &url, &["audit", "--upgradable", "--json"]);
    assert_eq!(code, 0);
    let report: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(report["from_cache"], false);
    assert_eq!(report["vulnerabilities"].as_array().unwrap().len(), 1);
    assert_eq!(report["vulnerabilities"][0]["package"], "pacman");
    assert_eq!(report["vulnerabilities"][0]["fix_available"], true);

    let (code, _, _) = run(&rig, &url, &["audit", "--fail"]);
    assert_eq!(code, 1, "--fail exits 1 with issues");

    // Offline reads the cache the first run wrote; without a cache it
    // is an error, and a dead tracker falls back to the cache with a note.
    let (code, out, err) = run(&rig, "http://127.0.0.1:9/all.json", &["audit", "--offline"]);
    assert_eq!(code, 0, "{err}");
    assert!(err.contains("tracker read from the cache"), "{err}");
    assert!(out.contains("pacman"), "{out}");
    let (code, out, err) = run(&rig, "http://127.0.0.1:9/all.json", &["audit"]);
    assert_eq!(code, 0, "{err}");
    assert!(err.contains("using the cached tracker"), "{err}");
    assert!(out.contains("pacman"), "{out}");
    std::fs::remove_dir_all(rig.dir.path().join("cache")).unwrap();
    let (code, _, err) = run(&rig, "http://127.0.0.1:9/all.json", &["audit", "--offline"]);
    assert_ne!(code, 0);
    assert!(err.contains("no cached security tracker"), "{err}");
    let (code, _, err) = run(&rig, "http://127.0.0.1:9/all.json", &["audit"]);
    assert_ne!(code, 0);
    assert!(
        err.contains("fetching http://127.0.0.1:9/all.json"),
        "{err}"
    );
}

#[test]
fn audit_with_nothing_open() {
    let rig = Rig::new();
    let base = common::http::serve(vec![("/all.json", "[]".to_string())]);
    let (code, out, _) = run(&rig, &format!("{base}/all.json"), &["audit", "--fail"]);
    assert_eq!(code, 0);
    assert!(out.contains("no open security issues"), "{out}");
}

#[test]
fn audit_uses_live_data_when_the_cache_cannot_be_written() {
    let rig = Rig::new();
    let cache_parent = rig.dir.path().join("cache/omapac");
    std::fs::create_dir_all(&cache_parent).unwrap();
    std::fs::write(cache_parent.join("audit"), "not a directory").unwrap();
    let base = common::http::serve(vec![("/all.json", TRACKER.to_string())]);

    let (code, out, err) = run(&rig, &format!("{base}/all.json"), &["audit"]);

    assert_eq!(code, 0, "{err}");
    assert!(out.contains("pacman"), "{out}");
    assert!(
        err.contains("could not cache the live security tracker"),
        "{err}"
    );
    assert!(!err.contains("using the cached tracker"), "{err}");
}
