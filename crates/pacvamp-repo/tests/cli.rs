//! `pacvamp-repo attest` and `index` over a fake repository directory, with
//! the result verified the way a client would.

use std::path::Path;
use std::process::Command;

fn repo_cmd(cwd: &Path, args: &[&str]) -> (i32, String, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_pacvamp-repo"))
        .current_dir(cwd)
        .args(args)
        .output()
        .unwrap();
    (
        output.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

fn keygen(dir: &Path, name: &str) -> packslip::minisign::SecretKey {
    let mut seed = [0_u8; 32];
    for (index, byte) in name.bytes().enumerate() {
        seed[index % seed.len()] = seed[index % seed.len()]
            .wrapping_add(byte)
            .wrapping_add(index as u8);
    }
    let key = packslip::minisign::SecretKey::from_seed(seed);
    std::fs::write(dir.join(format!("{name}.key")), key.to_file()).unwrap();
    std::fs::write(dir.join(format!("{name}.pub")), key.public_key().to_file()).unwrap();
    key
}

#[test]
fn attest_then_index_round_trip() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let repo = d.join("repo");
    std::fs::create_dir_all(&repo).unwrap();
    let index_key = keygen(d, "index");
    let build_key = keygen(d, "build");
    let other_key = keygen(d, "stranger");
    assert_ne!(index_key.public_key().key_id, build_key.public_key().key_id);
    // A database and three packages: one attested by the build key, one by
    // a stranger, one not at all; plus a vendor sidecar on the third.
    std::fs::copy(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../alpm-db/fixtures/sync/omarchy.db"),
        repo.join("omarchy.db"),
    )
    .unwrap();
    for name in [
        "a-1-1-x86_64.pkg.tar.zst",
        "b-1-1-x86_64.pkg.tar.zst",
        "c-1-1-x86_64.pkg.tar.zst",
    ] {
        std::fs::write(repo.join(name), format!("package {name}")).unwrap();
    }
    std::fs::write(repo.join("a-1-1-x86_64.pkg.tar.zst.sig"), "gpg").unwrap();
    std::fs::write(
        repo.join("c-1-1-x86_64.pkg.tar.zst.vendor.json"),
        r#"{"bundle":"...","scheme":"sigstore-oidc","level":"l2","key_id":"https://github.com/o/r/.github/workflows/release.yml@refs/tags/v1","verified_at":"2026-09-03T00:00:00Z"}"#,
    )
    .unwrap();

    let (code, out, err) = repo_cmd(
        d,
        &[
            "attest",
            "--key",
            "build.key",
            "--pkgbase",
            "a",
            "--source",
            "https://github.com/omacom/omarchy-pkgs",
            "--commit",
            "abc123",
            "--dependency",
            "https://example.com/a.tar.gz=00ff",
            "repo/a-1-1-x86_64.pkg.tar.zst",
        ],
    );
    assert_eq!(code, 0, "{err}");
    assert!(
        out.contains("a-1-1-x86_64.pkg.tar.zst.provenance.json"),
        "{out}"
    );
    let (code, _, err) = repo_cmd(
        d,
        &[
            "attest",
            "--key",
            "stranger.key",
            "--pkgbase",
            "b",
            "--source",
            "x",
            "--commit",
            "y",
            "repo/b-1-1-x86_64.pkg.tar.zst",
        ],
    );
    assert_eq!(code, 0, "{err}");

    // The envelope verifies with the build key and carries the statement.
    let envelope: packslip::dsse::Envelope = serde_json::from_str(
        &std::fs::read_to_string(repo.join("a-1-1-x86_64.pkg.tar.zst.provenance.json")).unwrap(),
    )
    .unwrap();
    let payload = envelope.verify(&build_key.public_key()).unwrap();
    let statement: serde_json::Value = serde_json::from_slice(&payload).unwrap();
    assert_eq!(statement["predicateType"], "https://slsa.dev/provenance/v1");
    assert_eq!(
        statement["predicate"]["buildDefinition"]["externalParameters"]["commit"],
        "abc123"
    );
    assert_eq!(
        statement["predicate"]["buildDefinition"]["resolvedDependencies"][0]["digest"]["sha256"],
        "00ff"
    );
    assert!(envelope.verify(&other_key.public_key()).is_err());

    // First index.
    let (code, out, err) = repo_cmd(
        d,
        &[
            "index",
            "--repo",
            "omarchy",
            "--dir",
            "repo",
            "--key",
            "index.key",
            "--build-key",
            "build.pub",
        ],
    );
    assert_eq!(code, 0, "{err}");
    assert!(
        out.contains("sequence 1, 3 package(s), db omarchy.db"),
        "{out}"
    );
    assert!(
        err.contains("b-1-1-x86_64.pkg.tar.zst: provenance not accepted"),
        "{err}"
    );
    let index_bytes = std::fs::read(repo.join("pacvamp-index.json")).unwrap();
    let signature = std::fs::read_to_string(repo.join("pacvamp-index.json.minisig")).unwrap();
    let sig = packslip::minisign::Sig::parse(&signature).unwrap();
    index_key.public_key().verify(&index_bytes, &sig).unwrap();
    let index: serde_json::Value = serde_json::from_slice(&index_bytes).unwrap();
    assert_eq!(index["repo"], "omarchy");
    assert_eq!(index["sequence"], 1);
    let a = &index["packages"]["a-1-1-x86_64.pkg.tar.zst"];
    assert_eq!(a["evidence"]["build_provenance"], true);
    assert_eq!(a["sidecars"][0], "a-1-1-x86_64.pkg.tar.zst.sig");
    assert_eq!(a["sidecars"][1], "a-1-1-x86_64.pkg.tar.zst.provenance.json");
    let b = &index["packages"]["b-1-1-x86_64.pkg.tar.zst"];
    assert_eq!(
        b["evidence"]["build_provenance"], false,
        "stranger's key is not accepted"
    );
    let c = &index["packages"]["c-1-1-x86_64.pkg.tar.zst"];
    assert_eq!(c["evidence"]["vendor_manifest"], true);
    assert_eq!(index["build_keys"].as_array().unwrap().len(), 1);
    let (db_sha, _) = packslip::digest_file(&repo.join("omarchy.db")).unwrap();
    assert_eq!(index["db"]["sha256"], db_sha);
    let a_published = a["published_at"].as_str().unwrap().to_string();

    // The previous index is state, so it must be authenticated before its
    // sequence, publish times, or embedded build keys are reused.
    std::fs::write(
        repo.join("pacvamp-index.json"),
        String::from_utf8_lossy(&index_bytes).replace("\"sequence\": 1", "\"sequence\": 99"),
    )
    .unwrap();
    let (code, _, err) = repo_cmd(
        d,
        &[
            "index",
            "--repo",
            "omarchy",
            "--dir",
            "repo",
            "--key",
            "index.key",
        ],
    );
    assert_ne!(code, 0);
    assert!(err.contains("previous index signature"), "{err}");
    std::fs::write(repo.join("pacvamp-index.json"), &index_bytes).unwrap();

    // Second index: the sequence advances, publish times carry over for
    // unchanged files, a changed file gets a new time, a new file appears.
    std::fs::write(repo.join("b-1-1-x86_64.pkg.tar.zst"), "package b v2").unwrap();
    std::fs::write(repo.join("d-1-1-x86_64.pkg.tar.zst"), "package d").unwrap();
    std::thread::sleep(std::time::Duration::from_millis(1100));
    let (code, out, _) = repo_cmd(
        d,
        &[
            "index",
            "--repo",
            "omarchy",
            "--dir",
            "repo",
            "--key",
            "index.key",
        ],
    );
    assert_eq!(code, 0);
    assert!(out.contains("sequence 2, 4 package(s)"), "{out}");
    let index: serde_json::Value =
        serde_json::from_slice(&std::fs::read(repo.join("pacvamp-index.json")).unwrap()).unwrap();
    assert_eq!(
        index["packages"]["a-1-1-x86_64.pkg.tar.zst"]["published_at"],
        a_published
    );
    assert_ne!(
        index["packages"]["b-1-1-x86_64.pkg.tar.zst"]["published_at"],
        a_published
    );
    assert!(index["packages"]["d-1-1-x86_64.pkg.tar.zst"].is_object());
    assert_eq!(index["build_keys"].as_array().unwrap().len(), 1);
    assert_eq!(
        index["packages"]["a-1-1-x86_64.pkg.tar.zst"]["evidence"]["build_provenance"],
        true
    );

    // An explicit sequence must move forward.
    let (code, _, err) = repo_cmd(
        d,
        &[
            "index",
            "--repo",
            "omarchy",
            "--dir",
            "repo",
            "--key",
            "index.key",
            "--sequence",
            "2",
        ],
    );
    assert_ne!(code, 0);
    assert!(err.contains("is not above the previous index's 2"), "{err}");
    let (code, out, _) = repo_cmd(
        d,
        &[
            "index",
            "--repo",
            "omarchy",
            "--dir",
            "repo",
            "--key",
            "index.key",
            "--sequence",
            "10",
            "--stdout",
        ],
    );
    assert_eq!(code, 0);
    assert!(out.contains("\"sequence\": 10"), "{out}");

    // A directory without the database is refused.
    let (code, _, err) = repo_cmd(
        d,
        &[
            "index",
            "--repo",
            "nope",
            "--dir",
            "repo",
            "--key",
            "index.key",
        ],
    );
    assert_ne!(code, 0);
    assert!(err.contains("nope.db not found"), "{err}");
}
