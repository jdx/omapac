//! The signer gate: packages are signed with the repository key only when
//! their provenance verifies, with a fake gpg and a fake transparency log.

mod common;

use std::sync::Arc;

use base64::Engine as _;
use common::Rig;
use sha2::Digest as _;

/// The fake log's signing key, and its public key as SPKI PEM.
fn log_key() -> p256::ecdsa::SigningKey {
    p256::ecdsa::SigningKey::from_bytes(&[5u8; 32].into()).unwrap()
}

fn log_pubkey_pem() -> String {
    use p256::pkcs8::EncodePublicKey as _;
    log_key()
        .verifying_key()
        .to_public_key_pem(p256::pkcs8::LineEnding::LF)
        .unwrap()
}

/// A fake Rekor that accepts dsse entries and answers like the real one,
/// with a genuine single-leaf inclusion proof and a signed checkpoint.
fn fake_rekor() -> String {
    common::http::serve_with(Arc::new(|method, path, body| {
        if method != "POST" || path != "/api/v1/log/entries" {
            return (404, "{}".into());
        }
        let proposed: serde_json::Value = serde_json::from_slice(body).unwrap();
        assert_eq!(proposed["kind"], "dsse");
        let envelope_text = proposed["spec"]["proposedContent"]["envelope"]
            .as_str()
            .unwrap();
        let envelope: packslip::dsse::Envelope = serde_json::from_str(envelope_text).unwrap();
        let verifier = proposed["spec"]["proposedContent"]["verifiers"][0]
            .as_str()
            .unwrap();
        let pem = base64::engine::general_purpose::STANDARD
            .decode(verifier)
            .unwrap();
        assert!(String::from_utf8(pem).unwrap().contains("BEGIN PUBLIC KEY"));
        let payload = envelope.payload_bytes().unwrap();
        let hash: String = sha2::Sha256::digest(&payload)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let entry_body = serde_json::json!({
            "apiVersion": "0.0.1", "kind": "dsse",
            "spec": {"payloadHash": {"algorithm": "sha256", "value": hash}, "signatures": []}
        });
        // A one-leaf tree: the root is the leaf hash.
        let body_bytes = serde_json::to_vec(&entry_body).unwrap();
        let mut leaf = sha2::Sha256::new();
        leaf.update([0u8]);
        leaf.update(&body_bytes);
        let root: [u8; 32] = leaf.finalize().into();
        let root_hex: String = root.iter().map(|b| format!("{b:02x}")).collect();
        let note = format!(
            "rekor.example - 1\n1\n{}\n",
            base64::engine::general_purpose::STANDARD.encode(root)
        );
        use p256::ecdsa::signature::Signer as _;
        let sig: p256::ecdsa::Signature = log_key().sign(note.as_bytes());
        let mut sig_line = vec![0xde, 0xad, 0xbe, 0xef];
        sig_line.extend_from_slice(sig.to_der().as_bytes());
        let checkpoint = format!(
            "{note}\n\u{2014} rekor.example {}\n",
            base64::engine::general_purpose::STANDARD.encode(sig_line)
        );
        let response = serde_json::json!({
            "24296fb24b8ad77a": {
                "body": base64::engine::general_purpose::STANDARD.encode(&body_bytes),
                "integratedTime": 1_788_220_800,
                "logID": "c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d",
                "logIndex": 0,
                "verification": {
                    "inclusionProof": {"logIndex": 0, "rootHash": root_hex, "treeSize": 1, "hashes": [], "checkpoint": checkpoint},
                    "signedEntryTimestamp": "MEUCIQ=="
                }
            }
        });
        (201, response.to_string())
    }))
}

fn setup(rig: &Rig) {
    let repo = rig.path().join("repo");
    std::fs::create_dir_all(&repo).unwrap();
    std::fs::copy(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../alpm-db/fixtures/sync/omarchy.db"),
        repo.join("omarchy.db"),
    )
    .unwrap();
    rig.keygen("index", 1);
    rig.keygen("build", 2);
    rig.keygen("stranger", 3);
    for name in ["good", "stranger", "bare", "tampered"] {
        std::fs::write(
            repo.join(format!("{name}-1-1-x86_64.pkg.tar.zst")),
            format!("package {name}"),
        )
        .unwrap();
    }
}

#[test]
fn signs_only_packages_with_accepted_provenance() {
    let rig = Rig::new();
    setup(&rig);
    let (code, _, err) = rig.run(&[
        "attest",
        "--key",
        "build.key",
        "--pkgbase",
        "good",
        "--source",
        "s",
        "--commit",
        "c",
        "repo/good-1-1-x86_64.pkg.tar.zst",
        "repo/tampered-1-1-x86_64.pkg.tar.zst",
    ]);
    assert_eq!(code, 0, "{err}");
    let (code, _, err) = rig.run(&[
        "attest",
        "--key",
        "stranger.key",
        "--pkgbase",
        "stranger",
        "--source",
        "s",
        "--commit",
        "c",
        "repo/stranger-1-1-x86_64.pkg.tar.zst",
    ]);
    assert_eq!(code, 0, "{err}");
    // The tampered package changed after attestation.
    std::fs::write(
        rig.path().join("repo/tampered-1-1-x86_64.pkg.tar.zst"),
        "trojan",
    )
    .unwrap();

    let (code, out, err) = rig.run(&[
        "sign",
        "--dir",
        "repo",
        "--build-key",
        "build.pub",
        "--gpg-key",
        "40DFC571",
        "--dry-run",
    ]);
    assert_ne!(code, 0, "refusals exit non-zero: {out}");
    assert!(
        out.contains("would sign good-1-1-x86_64.pkg.tar.zst (provenance by"),
        "{out}"
    );
    assert!(
        out.contains("REFUSED  bare-1-1-x86_64.pkg.tar.zst: no provenance envelope"),
        "{out}"
    );
    assert!(out.contains("REFUSED  stranger-1-1-x86_64.pkg.tar.zst: provenance is not signed by an allowlisted build key"), "{out}");
    assert!(
        out.contains(
            "REFUSED  tampered-1-1-x86_64.pkg.tar.zst: provenance subject digest does not match"
        ),
        "{out}"
    );
    assert!(err.contains("3 package(s) refused"), "{err}");
    assert!(rig.gpg_log().is_empty(), "dry run must not call gpg");

    let (code, out, _) = rig.run(&[
        "sign",
        "--dir",
        "repo",
        "--package",
        "good-1-1-x86_64.pkg.tar.zst",
        "--build-key",
        "build.pub",
        "--gpg-key",
        "40DFC571",
        "--json",
    ]);
    assert_eq!(code, 0, "{out}");
    let json: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(json[0]["status"], "signed");
    let log = rig.gpg_log();
    assert_eq!(log.len(), 1);
    assert!(
        log[0].contains("--batch --yes --detach-sign --local-user 40DFC571 --output"),
        "{log:?}"
    );
    assert!(
        log[0].ends_with("repo/good-1-1-x86_64.pkg.tar.zst"),
        "{log:?}"
    );
    let sig =
        std::fs::read_to_string(rig.path().join("repo/good-1-1-x86_64.pkg.tar.zst.sig")).unwrap();
    assert!(sig.contains("fake signature of good-1-1-x86_64.pkg.tar.zst"));

    // Second run skips the signed one.
    let (code, out, _) = rig.run(&[
        "sign",
        "--dir",
        "repo",
        "--package",
        "good-1-1-x86_64.pkg.tar.zst",
        "--build-key",
        "build.pub",
        "--gpg-key",
        "40DFC571",
    ]);
    assert_eq!(code, 0);
    assert!(
        out.contains("skipped  good-1-1-x86_64.pkg.tar.zst (already signed)"),
        "{out}"
    );

    // A gpg failure is a refusal, not a silent success.
    std::fs::remove_file(rig.path().join("repo/good-1-1-x86_64.pkg.tar.zst.sig")).unwrap();
    let (code, out, _) = rig.run_env(
        &[
            "sign",
            "--dir",
            "repo",
            "--package",
            "good-1-1-x86_64.pkg.tar.zst",
            "--build-key",
            "build.pub",
            "--gpg-key",
            "k",
        ],
        &[("FAKE_GPG_FAIL", "1")],
    );
    assert_ne!(code, 0);
    assert!(
        out.contains("REFUSED  good-1-1-x86_64.pkg.tar.zst: gpg: exited with status 2"),
        "{out}"
    );
    assert!(
        !rig.path()
            .join("repo/good-1-1-x86_64.pkg.tar.zst.sig")
            .exists(),
        "a failed signer must not leave a skippable signature"
    );
}

#[test]
fn rekor_and_index_gates() {
    let rig = Rig::new();
    setup(&rig);
    let log = fake_rekor();
    let (code, out, err) = rig.run(&[
        "attest",
        "--key",
        "build.key",
        "--pkgbase",
        "good",
        "--source",
        "s",
        "--commit",
        "c",
        "--rekor",
        &log,
        "repo/good-1-1-x86_64.pkg.tar.zst",
    ]);
    assert_eq!(code, 0, "{err}");
    assert!(
        out.contains("logged repo/good-1-1-x86_64.pkg.tar.zst.rekor.json at"),
        "{out}"
    );
    assert!(out.contains("index 0"), "{out}");
    let entry: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(
            rig.path()
                .join("repo/good-1-1-x86_64.pkg.tar.zst.rekor.json"),
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(entry["uuid"], "24296fb24b8ad77a");
    assert_eq!(entry["log_index"], 0);
    assert!(entry["inclusion_proof"].is_object());

    // The index lists the rekor sidecar too.
    let (code, _, err) = rig.run(&[
        "index",
        "--repo",
        "omarchy",
        "--dir",
        "repo",
        "--key",
        "index.key",
        "--build-key",
        "build.pub",
    ]);
    assert_eq!(code, 0, "{err}");
    let index: serde_json::Value =
        serde_json::from_slice(&std::fs::read(rig.path().join("repo/pacvamp-index.json")).unwrap())
            .unwrap();
    let sidecars = index["packages"]["good-1-1-x86_64.pkg.tar.zst"]["sidecars"]
        .as_array()
        .unwrap();
    assert!(
        sidecars
            .iter()
            .any(|s| s == "good-1-1-x86_64.pkg.tar.zst.rekor.json"),
        "{sidecars:?}"
    );

    // With the entry present and the index consistent, the gate passes,
    // including the checkpoint signature against the log key.
    std::fs::write(rig.path().join("rekor.pub"), log_pubkey_pem()).unwrap();
    let (code, out, _) = rig.run(&[
        "sign",
        "--dir",
        "repo",
        "--package",
        "good-1-1-x86_64.pkg.tar.zst",
        "--build-key",
        "build.pub",
        "--gpg-key",
        "k",
        "--require-rekor",
        "--rekor-pubkey",
        "rekor.pub",
        "--index",
        "repo/pacvamp-index.json",
        "--dry-run",
    ]);
    assert_eq!(code, 0, "{out}");
    assert!(out.contains("would sign good"), "{out}");
    // Another log's key does not verify the checkpoint.
    use p256::pkcs8::EncodePublicKey as _;
    let other = p256::ecdsa::SigningKey::from_bytes(&[6u8; 32].into()).unwrap();
    std::fs::write(
        rig.path().join("other.pub"),
        other
            .verifying_key()
            .to_public_key_pem(p256::pkcs8::LineEnding::LF)
            .unwrap(),
    )
    .unwrap();
    let (code, out, _) = rig.run(&[
        "sign",
        "--dir",
        "repo",
        "--package",
        "good-1-1-x86_64.pkg.tar.zst",
        "--build-key",
        "build.pub",
        "--gpg-key",
        "k",
        "--require-rekor",
        "--rekor-pubkey",
        "other.pub",
        "--dry-run",
    ]);
    assert_ne!(code, 0);
    assert!(
        out.contains("no checkpoint signature verifies with the log key"),
        "{out}"
    );
    // A proof that does not reach its root is refused.
    let path = rig
        .path()
        .join("repo/good-1-1-x86_64.pkg.tar.zst.rekor.json");
    let mut stored: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    let good_entry = stored.clone();
    stored["inclusion_proof"]["rootHash"] = serde_json::Value::String("00".repeat(32));
    std::fs::write(&path, stored.to_string()).unwrap();
    let (code, out, _) = rig.run(&[
        "sign",
        "--dir",
        "repo",
        "--package",
        "good-1-1-x86_64.pkg.tar.zst",
        "--build-key",
        "build.pub",
        "--gpg-key",
        "k",
        "--require-rekor",
        "--dry-run",
    ]);
    assert_ne!(code, 0);
    assert!(out.contains("inclusion proof reaches root"), "{out}");
    std::fs::write(&path, good_entry.to_string()).unwrap();

    // A package the index does not know is refused.
    std::fs::write(rig.path().join("repo/new-1-1-x86_64.pkg.tar.zst"), "new").unwrap();
    let (code, _, _) = rig.run(&[
        "attest",
        "--key",
        "build.key",
        "--pkgbase",
        "new",
        "--source",
        "s",
        "--commit",
        "c",
        "repo/new-1-1-x86_64.pkg.tar.zst",
    ]);
    assert_eq!(code, 0);
    let (code, out, _) = rig.run(&[
        "sign",
        "--dir",
        "repo",
        "--package",
        "new-1-1-x86_64.pkg.tar.zst",
        "--build-key",
        "build.pub",
        "--gpg-key",
        "k",
        "--index",
        "repo/pacvamp-index.json",
        "--dry-run",
    ]);
    assert_ne!(code, 0);
    assert!(
        out.contains("REFUSED  new-1-1-x86_64.pkg.tar.zst: not listed in the index"),
        "{out}"
    );
    let (code, out, _) = rig.run(&[
        "sign",
        "--dir",
        "repo",
        "--package",
        "new-1-1-x86_64.pkg.tar.zst",
        "--build-key",
        "build.pub",
        "--gpg-key",
        "k",
        "--require-rekor",
        "--dry-run",
    ]);
    assert_ne!(code, 0);
    assert!(out.contains("no transparency log entry"), "{out}");

    // An entry about a different envelope is refused.
    std::fs::copy(
        rig.path()
            .join("repo/good-1-1-x86_64.pkg.tar.zst.rekor.json"),
        rig.path()
            .join("repo/new-1-1-x86_64.pkg.tar.zst.rekor.json"),
    )
    .unwrap();
    let (code, out, _) = rig.run(&[
        "sign",
        "--dir",
        "repo",
        "--package",
        "new-1-1-x86_64.pkg.tar.zst",
        "--build-key",
        "build.pub",
        "--gpg-key",
        "k",
        "--require-rekor",
        "--dry-run",
    ]);
    assert_ne!(code, 0);
    assert!(out.contains("entry payload hash"), "{out}");
}
