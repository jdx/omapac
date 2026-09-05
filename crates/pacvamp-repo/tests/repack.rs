//! `pacvamp-repo repack`: a repository-signed packslip for a vendor whose
//! `.deb`s come from an apt pool, built from the PKGBUILD's own sources.

mod common;

use common::Rig;
use packslip::minisign::SecretKey;
use packslip::model::Attestor;
use packslip::{Options, Trust};

fn sha256(bytes: &[u8]) -> String {
    use sha2::Digest as _;
    format!("{:x}", sha2::Sha256::digest(bytes))
}

fn sha512(bytes: &[u8]) -> String {
    use sha2::Digest as _;
    format!("{:x}", sha2::Sha512::digest(bytes))
}

const PKGBUILD: &str = "pkgname=tool-bin\npkgver=26.8.4\npkgrel=1\narch=('x86_64' 'aarch64')\nsource=('tool-launcher.sh')\nsource_x86_64=(\"tool_${pkgver}_amd64.deb::https://packages.example.com/pool/main/t/tool/tool_${pkgver}_amd64.deb\")\nsource_aarch64=(\"tool_${pkgver}_arm64.deb::https://packages.example.com/pool/main/t/tool/tool_${pkgver}_arm64.deb\")\nsha256sums=('SKIP')\nsha256sums_x86_64=('x')\nsha256sums_aarch64=('y')\npackage() { :; }\n";

fn srcinfo(base: &str, amd64: &str, arm64: &str, amd64_sha512: Option<&str>) -> String {
    let mut text = format!(
        "pkgbase = tool-bin\n\tpkgver = 26.8.4\n\tpkgrel = 1\n\tarch = x86_64\n\tarch = aarch64\n\tsource = tool-launcher.sh\n\tsha256sums = SKIP\n\tsource_x86_64 = tool_26.8.4_amd64.deb::{base}/pool/main/t/tool/tool_26.8.4_amd64.deb\n\tsha256sums_x86_64 = {amd64}\n"
    );
    if let Some(s) = amd64_sha512 {
        text.push_str(&format!("\tsha512sums_x86_64 = {s}\n"));
    }
    text.push_str(&format!(
        "\tsource_aarch64 = tool_26.8.4_arm64.deb::{base}/pool/main/t/tool/tool_26.8.4_arm64.deb\n\tsha256sums_aarch64 = {arm64}\n\npkgname = tool-bin\n"
    ));
    text
}

#[test]
fn signs_a_repackager_packslip_from_the_pkgbuild_sources() {
    let amd64_deb = b"!<arch>\namd64 deb bytes".to_vec();
    let arm64_deb = b"!<arch>\narm64 deb bytes".to_vec();
    let base = common::http::serve(vec![
        (
            "/pool/main/t/tool/tool_26.8.4_amd64.deb".into(),
            String::from_utf8(amd64_deb.clone()).unwrap(),
        ),
        (
            "/pool/main/t/tool/tool_26.8.4_arm64.deb".into(),
            String::from_utf8(arm64_deb.clone()).unwrap(),
        ),
    ]);
    let rig = Rig::new();
    let key = rig.keygen("repack", 7);
    let pkgdir = rig.path().join("tool-bin");
    std::fs::create_dir_all(&pkgdir).unwrap();
    std::fs::write(pkgdir.join("PKGBUILD"), PKGBUILD).unwrap();
    std::fs::write(pkgdir.join("tool-launcher.sh"), "#!/bin/sh\n").unwrap();
    std::fs::write(
        pkgdir.join("vendor.toml"),
        "[upstream]\nproject = \"packages.example.com/tool\"\n[artifacts]\nx86_64 = { os = \"linux\", arch = \"x86_64\" }\n[attest]\nevidence = [{ kind = \"apt-release-gpg\", detail = \"3FEF9748469ADBE15DA7CA80AC2D62742012EA22\" }]\n",
    )
    .unwrap();
    std::fs::write(
        pkgdir.join(".SRCINFO"),
        srcinfo(
            &base,
            &sha256(&amd64_deb),
            &sha256(&arm64_deb),
            Some(&sha512(&amd64_deb)),
        ),
    )
    .unwrap();
    let env = [("PACVAMP_REPO_NOW", "2026-09-03T00:00:00Z")];

    let (code, out, err) = rig.run_env(
        &[
            "repack",
            "--pkgdir",
            "tool-bin",
            "--key",
            "repack.key",
            "--no-log",
        ],
        &env,
    );
    assert_eq!(code, 0, "{err}");
    assert!(
        out.contains("attested tool-bin 26.8.4 as repackager (evidence L1, key "),
        "{out}"
    );
    assert!(
        out.contains("x86_64: tool_26.8.4_amd64.deb sha256 "),
        "{out}"
    );

    // The sidecar holds a bundle the repackager key verifies, and says so.
    let sidecar: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(pkgdir.join("tool-bin.vendor.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(sidecar["attested_by"], "repackager");
    assert_eq!(sidecar["level"], "l1");
    assert_eq!(sidecar["evidence"][0]["kind"], "apt-release-gpg");
    assert_eq!(sidecar["evidence"][1]["kind"], "pkgbuild-checksums");
    let bundle = sidecar["bundle"].as_str().unwrap();
    let root = packslip::sigstore::trusted_root(None).unwrap();
    let verified = packslip::verify(
        bundle,
        &Trust::Key(&key.public_key()),
        Options {
            require_log: false,
            trusted_root: &root,
        },
        &[],
    )
    .unwrap();
    assert_eq!(verified.project, "packages.example.com/tool");
    assert_eq!(verified.version, "26.8.4");
    assert_eq!(verified.attested_by, Attestor::Repackager);
    let statement: serde_json::Value =
        serde_json::from_slice(&packslip::sigstore::peek_statement(bundle).unwrap()).unwrap();
    let arts = statement["predicate"]["artifacts"].as_array().unwrap();
    assert_eq!(arts.len(), 2);
    let amd64 = arts
        .iter()
        .find(|a| a["name"] == "tool_26.8.4_amd64.deb")
        .unwrap();
    assert_eq!(amd64["os"], "linux");
    assert_eq!(amd64["arch"], "x86_64");
    assert_eq!(amd64["format"], "deb");
    assert_eq!(amd64["size"], amd64_deb.len());
    assert_eq!(
        amd64["url"],
        format!("{base}/pool/main/t/tool/tool_26.8.4_amd64.deb")
    );
    let subject = statement["subject"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["name"] == "tool_26.8.4_amd64.deb")
        .unwrap();
    assert_eq!(subject["digest"]["sha256"], sha256(&amd64_deb));
    assert_eq!(subject["digest"]["sha512"], sha512(&amd64_deb));
    let lock = std::fs::read_to_string(pkgdir.join("vendor.lock")).unwrap();
    assert!(lock.contains("attested_by = \"repackager\""), "{lock}");
    assert!(lock.contains("level = \"l1\""), "{lock}");
    // A wrong key does not verify it.
    let other = SecretKey::from_seed([8u8; 32]).public_key();
    assert!(
        packslip::verify(
            bundle,
            &Trust::Key(&other),
            Options {
                require_log: false,
                trusted_root: &root,
            },
            &[],
        )
        .is_err()
    );

    // The signed index reports it as repackager evidence, not vendor.
    let repo = rig.path().join("repo");
    std::fs::create_dir_all(&repo).unwrap();
    std::fs::copy(
        concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../alpm-db/fixtures/sync/omarchy.db"
        ),
        repo.join("omarchy.db"),
    )
    .unwrap();
    std::fs::write(repo.join("tool-bin-26.8.4-1-x86_64.pkg.tar.zst"), b"pkg").unwrap();
    std::fs::copy(
        pkgdir.join("tool-bin.vendor.json"),
        repo.join("tool-bin-26.8.4-1-x86_64.pkg.tar.zst.vendor.json"),
    )
    .unwrap();
    rig.keygen("index", 1);
    rig.keygen("build", 2);
    let (code, out, err) = rig.run(&[
        "index",
        "--repo",
        "omarchy",
        "--dir",
        "repo",
        "--key",
        "index.key",
        "--build-key",
        "build.pub",
        "--repack-key",
        "repack.pub",
        "--stdout",
    ]);
    assert_eq!(code, 0, "{err}");
    let index: serde_json::Value = serde_json::from_str(&out).unwrap();
    let evidence = &index["packages"]["tool-bin-26.8.4-1-x86_64.pkg.tar.zst"]["evidence"];
    assert_eq!(evidence["vendor_manifest"], false);
    assert_eq!(evidence["repackager_manifest"], true);
    assert_eq!(evidence["vendor_attested_by"], "repackager");
    assert_eq!(index["repack_keys"].as_array().unwrap().len(), 1);

    // One real digest is sufficient even when another algorithm is SKIP.
    for (sha256_sum, sha512_sum) in [
        (sha256(&amd64_deb), "SKIP".into()),
        ("SKIP".into(), sha512(&amd64_deb)),
    ] {
        std::fs::write(
            pkgdir.join(".SRCINFO"),
            srcinfo(&base, &sha256_sum, &sha256(&arm64_deb), Some(&sha512_sum)),
        )
        .unwrap();
        let (code, _, err) = rig.run_env(
            &[
                "repack",
                "--pkgdir",
                "tool-bin",
                "--key",
                "repack.key",
                "--no-log",
            ],
            &env,
        );
        assert_eq!(code, 0, "{err}");
        let sidecar: serde_json::Value =
            serde_json::from_slice(&std::fs::read(pkgdir.join("tool-bin.vendor.json")).unwrap())
                .unwrap();
        assert!(
            !sidecar["evidence"]
                .as_array()
                .unwrap()
                .iter()
                .any(|e| e["kind"] == "none")
        );
    }

    // A PKGBUILD digest that disagrees with the download refuses, even if
    // a different algorithm was skipped.
    std::fs::remove_file(pkgdir.join("tool-bin.vendor.json")).unwrap();
    std::fs::write(
        pkgdir.join(".SRCINFO"),
        srcinfo(
            &base,
            &sha256(b"something else"),
            &sha256(&arm64_deb),
            Some("SKIP"),
        ),
    )
    .unwrap();
    let (code, _, err) = rig.run_env(
        &[
            "repack",
            "--pkgdir",
            "tool-bin",
            "--key",
            "repack.key",
            "--no-log",
        ],
        &env,
    );
    assert_ne!(code, 0);
    assert!(err.contains("the PKGBUILD says"), "{err}");
    assert!(!pkgdir.join("tool-bin.vendor.json").exists());

    // SKIP is refused unless the package says so.
    std::fs::write(
        pkgdir.join(".SRCINFO"),
        srcinfo(&base, "SKIP", &sha256(&arm64_deb), None),
    )
    .unwrap();
    let (code, _, err) = rig.run_env(
        &[
            "repack",
            "--pkgdir",
            "tool-bin",
            "--key",
            "repack.key",
            "--no-log",
        ],
        &env,
    );
    assert_ne!(code, 0);
    assert!(err.contains("allow_skip"), "{err}");
}
