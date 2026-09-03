//! `omapac tools` against a hand-built channel store served locally: the
//! index, listing, and a fetch that verifies the whole chain.

mod common;

use std::collections::BTreeMap;
use std::process::Command;

use common::Rig;
use omapac::trust::tools::{ToolArtifact, ToolEntry, ToolIndex, ToolVersion};
use packslip::create::{ArtifactInput, Request};
use packslip::minisign::SecretKey;

struct Store {
    rig: Rig,
    base: String,
    channel_key: SecretKey,
}

fn build_store(tamper: bool) -> Store {
    let rig = Rig::new();
    let channel_key = SecretKey::from_seed([21u8; 32]);
    let vendor_key = SecretKey::from_seed([22u8; 32]);
    std::fs::write(
        rig.dir.path().join("channel.pub"),
        channel_key.public_key().to_file(),
    )
    .unwrap();
    let work = rig.dir.path().join("work");
    std::fs::create_dir_all(&work).unwrap();
    let mut routes: Vec<(&'static str, String)> = Vec::new();
    let mut versions = BTreeMap::new();
    for (version, published, channels, held) in [
        (
            "1.0.0",
            "2026-08-01T00:00:00Z",
            vec!["edge", "rc", "stable"],
            None,
        ),
        (
            "1.1.0",
            "2026-08-20T00:00:00Z",
            vec!["edge", "rc"],
            Some("regression"),
        ),
        ("1.2.0", "2026-09-01T00:00:00Z", vec!["edge"], None),
    ] {
        let name = format!("tool-{version}-linux-x64.tar.gz");
        let path = work.join(&name);
        let content = format!("bytes of {version}");
        std::fs::write(&path, &content).unwrap();
        let created = packslip::create::create(&Request {
            project: "pkg:github/example/tool",
            version,
            published_at: Some(published),
            source: None,
            artifacts: vec![ArtifactInput {
                path: &path,
                os: None,
                arch: None,
                libc: None,
                provenance: vec![],
            }],
            url_base: Some("https://dl.example/"),
            sbom: None,
            supersedes: None,
            key: &vendor_key,
        })
        .unwrap();
        let (sha256, size) = packslip::digest_file(&path).unwrap();
        let rel = format!("tools/tool/{version}/{name}");
        let sidecar = serde_json::json!({
            "document": String::from_utf8(created.document).unwrap(),
            "signature": created.signature,
            "level": "l2", "key_id": "x", "verified_at": published,
        });
        let statement = serde_json::json!({
            "_type": "https://in-toto.io/Statement/v1",
            "subject": [{"name": name, "digest": {"sha256": sha256}}],
            "predicateType": "https://slsa.dev/provenance/v1",
            "predicate": {}
        });
        let envelope = packslip::dsse::Envelope::sign(
            packslip::dsse::IN_TOTO_PAYLOAD_TYPE,
            &serde_json::to_vec(&statement).unwrap(),
            &channel_key,
        );
        let served = if tamper && version == "1.2.0" {
            "tampered".repeat(1024)
        } else {
            content.clone()
        };
        // Sidecars first: the test server matches by prefix.
        routes.push((
            Box::leak(format!("/{rel}.vendor.json").into_boxed_str()),
            sidecar.to_string(),
        ));
        routes.push((
            Box::leak(format!("/{rel}.provenance.json").into_boxed_str()),
            serde_json::to_string(&envelope).unwrap(),
        ));
        routes.push((Box::leak(format!("/{rel}").into_boxed_str()), served));
        let mut artifacts = BTreeMap::new();
        artifacts.insert(
            "linux-x64".to_string(),
            ToolArtifact {
                name: name.clone(),
                sha256,
                size,
                path: rel,
                sidecars: vec![
                    format!("{name}.vendor.json"),
                    format!("{name}.provenance.json"),
                ],
            },
        );
        versions.insert(
            version.to_string(),
            ToolVersion {
                published_at: published.into(),
                vetted_at: published.into(),
                level: packslip::model::Level::L2,
                key_id: "x".into(),
                vendor_pubkey: vendor_key.public_key().to_file(),
                channels: channels.iter().map(|c| c.to_string()).collect(),
                held: held.map(str::to_string),
                artifacts,
            },
        );
    }
    let mut index = ToolIndex::empty("2026-09-03T00:00:00Z");
    index.sequence = 5;
    index.tools.insert(
        "tool".into(),
        ToolEntry {
            project: "pkg:github/example/tool".into(),
            vendor_pubkey: vendor_key.public_key().to_file(),
            versions,
        },
    );
    let index_text = serde_json::to_string(&index).unwrap();
    routes.push((
        "/tools/index.json.minisig",
        channel_key
            .sign(index_text.as_bytes(), "tool index")
            .to_file(),
    ));
    routes.push(("/tools/index.json", index_text));
    let base = common::http::serve(routes);
    Store {
        rig,
        base,
        channel_key,
    }
}

fn run(s: &Store, args: &[&str]) -> (i32, String, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_omapac"))
        .env("PATH", format!("{}:/usr/bin:/bin", s.rig.bin.display()))
        .env("HOME", &s.rig.home)
        .env_remove("XDG_CONFIG_HOME")
        .env("XDG_CACHE_HOME", s.rig.dir.path().join("cache"))
        .arg("--sysroot")
        .arg(&s.rig.root)
        .arg("tools")
        .arg("--base")
        .arg(&s.base)
        .arg("--pubkey")
        .arg(s.rig.dir.path().join("channel.pub"))
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
fn index_and_list() {
    let s = build_store(false);
    let (code, out, err) = run(&s, &["index"]);
    assert_eq!(code, 0, "{err}");
    assert!(
        out.contains("(sequence 5, generated 2026-09-03T00:00:00Z, signed by"),
        "{out}"
    );
    assert!(
        out.contains("tool: 3 version(s) from pkg:github/example/tool"),
        "{out}"
    );
    let (code, out, _) = run(&s, &["list", "tool"]);
    assert_eq!(code, 0);
    assert_eq!(out, "1.0.0\n1.2.0\n", "held excluded, oldest first");
    let (_, out, _) = run(&s, &["list", "tool", "--all"]);
    assert_eq!(out, "1.0.0\n1.1.0\theld: regression\n1.2.0\n");
    let (_, out, _) = run(&s, &["list", "tool", "--channel", "stable"]);
    assert_eq!(out, "1.0.0\n");
    let (_, out, _) = run(&s, &["list", "tool", "--json"]);
    let rows: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(rows[1]["version"], "1.2.0");
    assert_eq!(rows[1]["platforms"][0], "linux-x64");
    let (code, _, err) = run(&s, &["list", "other"]);
    assert_ne!(code, 0);
    assert!(err.contains("other is not in the tool channel"), "{err}");

    // Rollback protection: a lower sequence than the one seen is refused.
    std::fs::write(
        s.rig
            .dir
            .path()
            .join("cache/omapac/trust/tools/index.sequence"),
        "9",
    )
    .unwrap();
    let (code, _, err) = run(&s, &["list", "tool"]);
    assert_ne!(code, 0);
    assert!(
        err.contains("sequence 5 is below the 9 seen before"),
        "{err}"
    );
}

#[test]
fn fetch_verifies_the_chain() {
    let s = build_store(false);
    let dest = s.rig.dir.path().join("dl");
    let (code, out, err) = run(
        &s,
        &[
            "fetch",
            "tool",
            "1.0.0",
            "--platform",
            "linux-x64",
            "--dest",
            dest.to_str().unwrap(),
            "--json",
        ],
    );
    assert_eq!(code, 0, "{err}\n{out}");
    let report: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(report["verified"]["packslip"], true);
    assert_eq!(report["verified"]["provenance"], true);
    assert_eq!(report["level"], "l2");
    assert_eq!(report["channels"][2], "stable");
    assert_eq!(
        std::fs::read_to_string(dest.join("tool-1.0.0-linux-x64.tar.gz")).unwrap(),
        "bytes of 1.0.0"
    );
    let (_, out, _) = run(
        &s,
        &[
            "fetch",
            "tool",
            "1.0.0",
            "--platform",
            "linux-x64",
            "--dest",
            dest.to_str().unwrap(),
        ],
    );
    assert!(
        out.contains("(evidence L2, packslip verified, provenance verified)"),
        "{out}"
    );

    let (code, _, err) = run(
        &s,
        &[
            "fetch",
            "tool",
            "1.1.0",
            "--platform",
            "linux-x64",
            "--dest",
            dest.to_str().unwrap(),
        ],
    );
    assert_ne!(code, 0);
    assert!(err.contains("is held by the channel: regression"), "{err}");
    let (code, _, err) = run(
        &s,
        &[
            "fetch",
            "tool",
            "1.1.0",
            "--platform",
            "linux-x64",
            "--dest",
            dest.to_str().unwrap(),
            "--force",
        ],
    );
    assert_eq!(code, 0, "{err}");
    let (code, _, err) = run(
        &s,
        &[
            "fetch",
            "tool",
            "2.0.0",
            "--platform",
            "linux-x64",
            "--dest",
            dest.to_str().unwrap(),
        ],
    );
    assert_ne!(code, 0);
    assert!(
        err.contains("is not vetted; vetted versions: 1.0.0, 1.2.0"),
        "{err}"
    );
    let (code, _, err) = run(
        &s,
        &[
            "fetch",
            "tool",
            "1.0.0",
            "--platform",
            "macos-arm64",
            "--dest",
            dest.to_str().unwrap(),
        ],
    );
    assert_ne!(code, 0);
    assert!(
        err.contains("no artifact for macos-arm64; platforms: linux-x64"),
        "{err}"
    );
    let _ = &s.channel_key;
}

#[test]
fn a_tampered_mirror_is_caught() {
    let s = build_store(true);
    let dest = s.rig.dir.path().join("dl");
    let (code, _, err) = run(
        &s,
        &[
            "fetch",
            "tool",
            "1.2.0",
            "--platform",
            "linux-x64",
            "--dest",
            dest.to_str().unwrap(),
        ],
    );
    assert_ne!(code, 0);
    assert!(
        err.contains("reading") || err.contains("response exceeds"),
        "{err}"
    );
    assert!(
        !dest.join("tool-1.2.0-linux-x64.tar.gz").exists(),
        "nothing written"
    );
}

#[test]
fn channel_must_be_configured() {
    let rig = Rig::new();
    let output = Command::new(env!("CARGO_BIN_EXE_omapac"))
        .env("HOME", &rig.home)
        .env_remove("XDG_CONFIG_HOME")
        .arg("--sysroot")
        .arg(&rig.root)
        .args(["tools", "index"])
        .output()
        .unwrap();
    let err = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success());
    assert!(err.contains("no tool channel configured"), "{err}");
    rig.write_root(
        "/etc/omapac/conf.d/10-omarchy.toml",
        "[channel]\ntools_base = \"http://127.0.0.1:9\"\n",
    );
    let output = Command::new(env!("CARGO_BIN_EXE_omapac"))
        .env("HOME", &rig.home)
        .env_remove("XDG_CONFIG_HOME")
        .arg("--sysroot")
        .arg(&rig.root)
        .args(["tools", "index"])
        .output()
        .unwrap();
    let err = String::from_utf8_lossy(&output.stderr);
    assert!(
        err.contains("no trust keys to verify the tool channel"),
        "{err}"
    );
}
