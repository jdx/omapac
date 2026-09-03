//! The tool channel publisher against a local vendor: publish, promote,
//! hold, verdict blocks, and immutability.

mod common;

use std::path::Path;

use common::Rig;
use packslip::create::{ArtifactInput, Request};
use packslip::minisign::SecretKey;

/// A vendor serving a signed release list, packslips, and artifacts from
/// one local base URL.
fn vendor(dir: &Path, key: &SecretKey, versions: &[(&str, &str)]) -> String {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    drop(listener);
    let mut routes = Vec::new();
    let mut list = Vec::new();
    for (version, published_at) in versions {
        let x64 = dir.join(format!("tool-{version}-linux-x64.tar.gz"));
        let arm = dir.join(format!("tool-{version}-linux-arm64.tar.gz"));
        std::fs::write(&x64, format!("x64 {version}")).unwrap();
        std::fs::write(&arm, format!("arm {version}")).unwrap();
        let created = packslip::create::create(&Request {
            project: "pkg:github/example/tool",
            version,
            published_at: Some(published_at),
            source: None,
            artifacts: vec![
                ArtifactInput {
                    path: &x64,
                    os: None,
                    arch: None,
                    libc: None,
                    provenance: vec![],
                },
                ArtifactInput {
                    path: &arm,
                    os: None,
                    arch: None,
                    libc: None,
                    provenance: vec![],
                },
            ],
            url_base: Some(&format!("{base}/dl/")),
            sbom: None,
            supersedes: None,
            key,
        })
        .unwrap();
        routes.push((
            format!("/releases/{version}/packslip.json"),
            String::from_utf8(created.document).unwrap(),
        ));
        routes.push((
            format!("/releases/{version}/packslip.json.minisig"),
            created.signature,
        ));
        routes.push((
            format!("/dl/tool-{version}-linux-x64.tar.gz"),
            format!("x64 {version}"),
        ));
        routes.push((
            format!("/dl/tool-{version}-linux-arm64.tar.gz"),
            format!("arm {version}"),
        ));
        list.push(serde_json::json!({"version": version, "published_at": published_at, "packslip": format!("{base}/releases/{version}/packslip.json")}));
    }
    let list_text =
        serde_json::json!({"project": "pkg:github/example/tool", "releases": list}).to_string();
    routes.push((
        "/.well-known/packslip/tool.json.minisig".into(),
        key.sign(list_text.as_bytes(), "releases").to_file(),
    ));
    routes.push(("/.well-known/packslip/tool.json".into(), list_text));
    common::http::serve_at(&base, routes)
}

fn write_config(rig: &Rig, base: &str, vendor_key: &SecretKey, extra: &str) {
    let dir = rig.path().join("tool");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("vendor.pub"), vendor_key.public_key().to_file()).unwrap();
    std::fs::write(
        dir.join("tool.toml"),
        format!(
            "[tool]\nname = \"tool\"\n[upstream]\nproject = \"pkg:github/example/tool\"\nreleases = \"{base}/.well-known/packslip/tool.json\"\npubkey = \"vendor.pub\"\n{extra}\n[artifacts]\nlinux-x64 = {{ os = \"linux\", arch = \"x86_64\" }}\nlinux-arm64 = {{ os = \"linux\", arch = \"aarch64\" }}\n"
        ),
    )
    .unwrap();
}

const NOW: &str = "2026-09-03T00:00:00Z";

fn tc(rig: &Rig, args: &[&str]) -> (i32, String, String) {
    let mut full = vec!["tool-channel", "--store", "store", "--key", "channel.key"];
    full.extend_from_slice(args);
    rig.run_env(&full, &[("OMAPAC_REPO_NOW", NOW)])
}

fn index(rig: &Rig) -> omapac::trust::tools::ToolIndex {
    let bytes = std::fs::read(rig.path().join("store/tools/index.json")).unwrap();
    let sig = packslip::minisign::Sig::parse(
        &std::fs::read_to_string(rig.path().join("store/tools/index.json.minisig")).unwrap(),
    )
    .unwrap();
    SecretKey::from_seed([11u8; 32])
        .public_key()
        .verify(&bytes, &sig)
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

#[test]
fn publish_promote_hold_and_immutability() {
    let rig = Rig::new();
    let channel_key = rig.keygen("channel", 11);
    let vendor_key = SecretKey::from_seed([9u8; 32]);
    let art = rig.path().join("artifacts");
    std::fs::create_dir_all(&art).unwrap();
    let base = vendor(
        &art,
        &vendor_key,
        &[
            ("1.0.0", "2026-08-01T00:00:00Z"),
            ("1.1.0", "2026-09-02T20:00:00Z"),
        ],
    );
    write_config(&rig, &base, &vendor_key, "min_release_age = \"24h\"");

    // Debris from an interrupted, not-yet-indexed publish is replaced.
    let incomplete = rig
        .path()
        .join("store/tools/tool/1.0.0/tool-1.0.0-linux-x64.tar.gz");
    std::fs::create_dir_all(incomplete.parent().unwrap()).unwrap();
    std::fs::write(&incomplete, b"truncated").unwrap();

    let (code, out, err) = tc(&rig, &["publish", "--config", "tool/tool.toml"]);
    assert_eq!(code, 0, "{err}\n{out}");
    assert!(
        out.contains("published tool 1.0.0 to edge (evidence L2, 2 artifact(s); skipped 1.1.0"),
        "{out}"
    );
    assert!(out.contains("(sequence 1)"), "{out}");
    let idx = index(&rig);
    let entry = &idx.tools["tool"];
    assert_eq!(entry.project, "pkg:github/example/tool");
    assert!(
        entry.vendor_pubkey.contains(
            &vendor_key
                .public_key()
                .to_file()
                .lines()
                .last()
                .unwrap()
                .to_string()
        )
    );
    let v = &entry.versions["1.0.0"];
    assert_eq!(v.channels, vec!["edge"]);
    assert_eq!(v.published_at, "2026-08-01T00:00:00Z");
    let x64 = &v.artifacts["linux-x64"];
    assert_eq!(x64.name, "tool-1.0.0-linux-x64.tar.gz");
    assert_eq!(x64.path, "tools/tool/1.0.0/tool-1.0.0-linux-x64.tar.gz");
    let file = rig.path().join("store").join(&x64.path);
    assert_eq!(std::fs::read_to_string(&file).unwrap(), "x64 1.0.0");
    let (sha, size) = packslip::digest_file(&file).unwrap();
    assert_eq!((sha.as_str(), size), (x64.sha256.as_str(), x64.size));
    // The vendor sidecar verifies against the vendor key and the file.
    let sidecar: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(
            rig.path()
                .join("store/tools/tool/1.0.0/tool-1.0.0-linux-x64.tar.gz.vendor.json"),
        )
        .unwrap(),
    )
    .unwrap();
    packslip::verify::verify(
        sidecar["document"].as_str().unwrap().as_bytes(),
        sidecar["signature"].as_str().unwrap(),
        &vendor_key.public_key(),
        &[&file],
    )
    .unwrap();
    // The provenance envelope is signed by the channel key and names the digest.
    let envelope: packslip::dsse::Envelope = serde_json::from_str(
        &std::fs::read_to_string(
            rig.path()
                .join("store/tools/tool/1.0.0/tool-1.0.0-linux-x64.tar.gz.provenance.json"),
        )
        .unwrap(),
    )
    .unwrap();
    let payload = envelope.verify(&channel_key.public_key()).unwrap();
    let statement: serde_json::Value = serde_json::from_slice(&payload).unwrap();
    assert_eq!(statement["subject"][0]["digest"]["sha256"], x64.sha256);
    assert_eq!(
        statement["predicate"]["buildDefinition"]["externalParameters"]["pkgbase"],
        "tool"
    );
    assert_eq!(
        statement["predicate"]["buildDefinition"]["externalParameters"]["commit"],
        "1.0.0"
    );

    // Publishing the same version again is refused; versions are immutable.
    let (code, _, err) = tc(
        &rig,
        &[
            "publish",
            "--config",
            "tool/tool.toml",
            "--version",
            "1.0.0",
        ],
    );
    assert_ne!(code, 0);
    assert!(err.contains("already published"), "{err}");

    // The newer release once old enough.
    let (code, out, err) = rig.run_env(
        &[
            "tool-channel",
            "--store",
            "store",
            "--key",
            "channel.key",
            "publish",
            "--config",
            "tool/tool.toml",
        ],
        &[("OMAPAC_REPO_NOW", "2026-09-05T00:00:00Z")],
    );
    assert_eq!(code, 0, "{err}\n{out}");
    assert!(out.contains("published tool 1.1.0 to edge"), "{out}");
    assert_eq!(index(&rig).sequence, 2);

    // Promote, hold, unhold.
    let (code, out, _) = tc(
        &rig,
        &[
            "promote",
            "--tool",
            "tool",
            "--version",
            "1.0.0",
            "--channel",
            "stable",
        ],
    );
    assert_eq!(code, 0, "{out}");
    assert_eq!(
        index(&rig).tools["tool"].versions["1.0.0"].channels,
        vec!["edge", "stable"]
    );
    let (code, _, err) = tc(
        &rig,
        &[
            "promote",
            "--tool",
            "tool",
            "--version",
            "1.0.0",
            "--channel",
            "edge",
        ],
    );
    assert_ne!(code, 0);
    assert!(err.contains("must be rc or stable"), "{err}");
    let (code, _, err) = tc(
        &rig,
        &[
            "promote",
            "--tool",
            "tool",
            "--version",
            "9.9.9",
            "--channel",
            "rc",
        ],
    );
    assert_ne!(code, 0);
    assert!(err.contains("not in the tool index"), "{err}");
    let (code, out, _) = tc(
        &rig,
        &[
            "hold",
            "--tool",
            "tool",
            "--version",
            "1.1.0",
            "--reason",
            "regression",
        ],
    );
    assert_eq!(code, 0, "{out}");
    let idx = index(&rig);
    assert_eq!(
        idx.tools["tool"].versions["1.1.0"].held.as_deref(),
        Some("regression")
    );
    let listed: Vec<&str> = idx
        .versions("tool", None, false)
        .iter()
        .map(|(v, _)| *v)
        .collect();
    assert_eq!(listed, vec!["1.0.0"]);
    let (code, _, err) = tc(
        &rig,
        &[
            "promote",
            "--tool",
            "tool",
            "--version",
            "1.1.0",
            "--channel",
            "rc",
        ],
    );
    assert_ne!(code, 0);
    assert!(err.contains("is held: regression"), "{err}");
    let (code, out, _) = tc(&rig, &["status"]);
    assert_eq!(code, 0);
    assert!(
        out.contains("1.1.0  published 2026-09-02T20:00:00Z  L2  [edge]  HELD: regression"),
        "{out}"
    );
    let (code, _, _) = tc(&rig, &["unhold", "--tool", "tool", "--version", "1.1.0"]);
    assert_eq!(code, 0);
    assert!(index(&rig).tools["tool"].versions["1.1.0"].held.is_none());
    assert_eq!(index(&rig).sequence, 5, "failed promotions write nothing");
}

#[test]
fn a_block_verdict_keeps_a_version_out() {
    let rig = Rig::new();
    rig.keygen("channel", 11);
    let vendor_key = SecretKey::from_seed([9u8; 32]);
    let art = rig.path().join("artifacts");
    std::fs::create_dir_all(&art).unwrap();
    let base = vendor(&art, &vendor_key, &[("1.0.0", "2026-08-01T00:00:00Z")]);
    write_config(&rig, &base, &vendor_key, "");
    let (sha, _) = packslip::digest_file(&art.join("tool-1.0.0-linux-arm64.tar.gz")).unwrap();
    std::fs::create_dir_all(rig.path().join("store")).unwrap();
    let (code, _, err) = rig.run(&[
        "verdict",
        "--feed",
        "store/verdicts.json",
        "--key",
        "channel.key",
        "--sha256",
        &sha,
        "--kind",
        "av",
        "--reviewer",
        "clamav",
        "--verdict",
        "block",
        "--summary",
        "trojan",
    ]);
    assert_eq!(code, 0, "{err}");
    let (code, _, err) = tc(&rig, &["publish", "--config", "tool/tool.toml"]);
    assert_ne!(code, 0);
    assert!(
        err.contains("tool-1.0.0-linux-arm64.tar.gz has a block verdict; not publishing"),
        "{err}"
    );
    assert!(!rig.path().join("store/tools/index.json").exists());
    assert!(!rig.path().join("store/tools/tool").exists());
}

#[test]
fn config_needs_a_tool_name() {
    let rig = Rig::new();
    rig.keygen("channel", 11);
    let dir = rig.path().join("tool");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("tool.toml"),
        "[upstream]\nproject = \"p\"\nreleases = \"http://127.0.0.1:9/x\"\npubkey = \"RW\"\n",
    )
    .unwrap();
    let (code, _, err) = tc(&rig, &["publish", "--config", "tool/tool.toml"]);
    assert_ne!(code, 0);
    assert!(err.contains("no [tool] name"), "{err}");
}
