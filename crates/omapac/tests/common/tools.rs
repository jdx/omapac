//! A hand-built tool channel store served locally, shared by the tools
//! client tests and the mise plugin test.

use std::collections::BTreeMap;
use std::path::Path;

use omapac::trust::tools::{ToolArtifact, ToolEntry, ToolIndex, ToolVersion};
use packslip::create::{ArtifactInput, Request};
use packslip::minisign::SecretKey;

pub struct Store {
    pub base: String,
    pub channel_pub: std::path::PathBuf,
}

/// Three versions of `tool` for linux-x64: 1.0.0 stable, 1.1.0 held,
/// 1.2.0 edge. With `tamper`, the mirror serves wrong bytes for 1.2.0.
pub fn build_store(dir: &Path, tamper: bool) -> Store {
    let channel_key = SecretKey::from_seed([21u8; 32]);
    let vendor_key = SecretKey::from_seed([22u8; 32]);
    let channel_pub = dir.join("channel.pub");
    std::fs::write(&channel_pub, channel_key.public_key().to_file()).unwrap();
    let work = dir.join("work");
    std::fs::create_dir_all(&work).unwrap();
    let mut routes: Vec<(&'static str, Vec<u8>)> = Vec::new();
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
        // 1.2.0 is a real tarball with bin/tool inside a top-level
        // directory; the others are bare binaries.
        let (name, content) = if version == "1.2.0" {
            let name = format!("tool-{version}-linux-x64.tar.gz");
            let tree = work.join(format!("tool-{version}"));
            std::fs::create_dir_all(tree.join("bin")).unwrap();
            std::fs::create_dir_all(tree.join("lib")).unwrap();
            std::fs::create_dir_all(tree.join("tool")).unwrap();
            std::fs::write(tree.join("lib/tool-real"), format!("archived {version}")).unwrap();
            std::os::unix::fs::symlink("../lib/tool-real", tree.join("bin/tool")).unwrap();
            std::fs::write(tree.join("alternate"), format!("alternate {version}")).unwrap();
            let status = std::process::Command::new("tar")
                .args(["czf", &name, &format!("tool-{version}")])
                .current_dir(&work)
                .status()
                .unwrap();
            assert!(status.success(), "tar");
            let bytes = std::fs::read(work.join(&name)).unwrap();
            (name, bytes)
        } else {
            let name = format!("tool-{version}-linux-x64.bin");
            let content = format!("bytes of {version}").into_bytes();
            std::fs::write(work.join(&name), &content).unwrap();
            (name, content)
        };
        let path = work.join(&name);
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
            b"tampered".repeat(1024)
        } else {
            content.clone()
        };
        // Sidecars first: the test server matches by prefix.
        routes.push((
            Box::leak(format!("/{rel}.vendor.json").into_boxed_str()),
            sidecar.to_string().into_bytes(),
        ));
        routes.push((
            Box::leak(format!("/{rel}.provenance.json").into_boxed_str()),
            serde_json::to_vec(&envelope).unwrap(),
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
            .to_file()
            .into_bytes(),
    ));
    routes.push(("/tools/index.json", index_text.into_bytes()));
    let base = super::http::serve_bytes(routes);
    Store { base, channel_pub }
}
