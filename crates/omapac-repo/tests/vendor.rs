//! The vendor pipeline against a local server publishing a signed release
//! list and packslips.

mod common;

use std::path::Path;

use common::Rig;
use packslip::create::{ArtifactInput, Request};
use packslip::minisign::SecretKey;

const PKGBUILD: &str = "pkgname=tool-bin\npkgver=1.0.0\npkgrel=2\narch=('x86_64' 'aarch64')\nsource_x86_64=(\"https://dl.example/tool-${pkgver}-linux-x64.tar.gz\")\nsource_aarch64=(\"https://dl.example/tool-${pkgver}-linux-arm64.tar.gz\")\nsha256sums_x86_64=('old')\nsha256sums_aarch64=('old')\npackage() { :; }\n";

struct Vendor {
    key: SecretKey,
    routes: Vec<(String, String)>,
}

impl Vendor {
    fn new(seed: u8) -> Vendor {
        Vendor {
            key: SecretKey::from_seed([seed; 32]),
            routes: Vec::new(),
        }
    }

    /// Publish a release with artifacts for two platforms.
    fn release(&mut self, dir: &Path, version: &str, published_at: &str) {
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
            url_base: Some("https://dl.example/"),
            sbom: None,
            supersedes: None,
            key: &self.key,
        })
        .unwrap();
        self.routes.push((
            format!("/releases/{version}/packslip.json"),
            String::from_utf8(created.document).unwrap(),
        ));
        self.routes.push((
            format!("/releases/{version}/packslip.json.minisig"),
            created.signature,
        ));
    }
}

fn serve_pointing_at_self(mut vendor: Vendor) -> (String, SecretKey) {
    // Bind, build the list with the bound base, then serve.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    drop(listener);
    let versions: Vec<(String, String)> = vendor
        .routes
        .iter()
        .filter(|(p, _)| p.ends_with("/packslip.json"))
        .map(|(p, body)| {
            let statement: serde_json::Value = serde_json::from_str(body).unwrap();
            (
                p.trim_start_matches("/releases/")
                    .trim_end_matches("/packslip.json")
                    .to_string(),
                statement["predicate"]["published_at"]
                    .as_str()
                    .unwrap()
                    .to_string(),
            )
        })
        .collect();
    let list = serde_json::json!({
        "project": "pkg:github/example/tool",
        "releases": versions.iter().map(|(v, at)| serde_json::json!({
            "version": v, "published_at": at,
            "packslip": format!("{base}/releases/{v}/packslip.json"),
        })).collect::<Vec<_>>(),
    });
    let list_text = serde_json::to_string(&list).unwrap();
    let sig = vendor.key.sign(list_text.as_bytes(), "releases").to_file();
    vendor
        .routes
        .push(("/.well-known/packslip/tool.json".into(), list_text));
    vendor
        .routes
        .push(("/.well-known/packslip/tool.json.minisig".into(), sig));
    let served = common::http::serve_at(&base, vendor.routes);
    (served, vendor.key)
}

fn write_package(rig: &Rig, base: &str, key: &SecretKey, extra: &str) {
    let pkgdir = rig.path().join("tool-bin");
    std::fs::create_dir_all(&pkgdir).unwrap();
    std::fs::write(pkgdir.join("PKGBUILD"), PKGBUILD).unwrap();
    std::fs::write(pkgdir.join("vendor.pub"), key.public_key().to_file()).unwrap();
    std::fs::write(
        pkgdir.join("vendor.toml"),
        format!(
            "[upstream]\nproject = \"pkg:github/example/tool\"\nreleases = \"{base}/.well-known/packslip/tool.json\"\npubkey = \"vendor.pub\"\n{extra}\n[artifacts]\nx86_64 = {{ os = \"linux\", arch = \"x86_64\" }}\naarch64 = {{ os = \"linux\", arch = \"aarch64\" }}\n"
        ),
    )
    .unwrap();
}

const NOW: &str = "2026-09-03T00:00:00Z";

#[test]
fn generates_from_the_newest_eligible_release() {
    let rig = Rig::new();
    let art = rig.path().join("artifacts");
    std::fs::create_dir_all(&art).unwrap();
    let mut vendor = Vendor::new(9);
    vendor.release(&art, "1.5.0", "2026-08-20T00:00:00Z");
    vendor.release(&art, "2.0.0", "2026-09-02T20:00:00Z");
    let (base, key) = serve_pointing_at_self(vendor);
    write_package(&rig, &base, &key, "min_release_age = \"24h\"");

    let (code, out, err) = rig.run_env(
        &["vendor", "--pkgdir", "tool-bin"],
        &[("OMAPAC_REPO_NOW", NOW)],
    );
    assert_eq!(code, 0, "{err}");
    assert!(
        out.contains("would generate 1.5.0 (published 2026-08-20T00:00:00Z, evidence L2"),
        "{out}"
    );
    assert!(out.contains("skipped 2.0.0"), "{out}");
    let pkgbuild = std::fs::read_to_string(rig.path().join("tool-bin/PKGBUILD")).unwrap();
    assert_eq!(pkgbuild, PKGBUILD, "no --write, no change");

    let (code, out, err) = rig.run_env(
        &["vendor", "--pkgdir", "tool-bin", "--write", "--json"],
        &[("OMAPAC_REPO_NOW", NOW)],
    );
    assert_eq!(code, 0, "{err}");
    let report: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(report["version"], "1.5.0");
    assert_eq!(report["written"], true);
    let x64_sha = report["artifacts"]["x86_64"]["sha256"]
        .as_str()
        .unwrap()
        .to_string();
    assert_eq!(
        report["artifacts"]["x86_64"]["name"],
        "tool-1.5.0-linux-x64.tar.gz"
    );
    assert_eq!(
        report["artifacts"]["aarch64"]["name"],
        "tool-1.5.0-linux-arm64.tar.gz"
    );
    let (expected, _) = packslip::digest_file(&art.join("tool-1.5.0-linux-x64.tar.gz")).unwrap();
    assert_eq!(x64_sha, expected);
    let pkgbuild = std::fs::read_to_string(rig.path().join("tool-bin/PKGBUILD")).unwrap();
    assert!(pkgbuild.contains("pkgver=1.5.0\npkgrel=1\n"), "{pkgbuild}");
    assert!(
        pkgbuild.contains(&format!("sha256sums_x86_64=('{x64_sha}')")),
        "{pkgbuild}"
    );
    let sidecar: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(rig.path().join("tool-bin/tool-bin.vendor.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(sidecar["document"]["predicate"]["version"], "1.5.0");
    assert_eq!(sidecar["level"], "l2");
    assert!(
        sidecar["signature"]
            .as_str()
            .unwrap()
            .contains("untrusted comment")
    );
    let lock = std::fs::read_to_string(rig.path().join("tool-bin/vendor.lock")).unwrap();
    assert!(lock.contains("version = \"1.5.0\""), "{lock}");
    assert!(lock.contains("level = \"l2\""), "{lock}");

    // Once the new release is old enough it is picked; an explicit
    // version works regardless of age.
    let (code, out, _) = rig.run_env(
        &["vendor", "--pkgdir", "tool-bin"],
        &[("OMAPAC_REPO_NOW", "2026-09-05T00:00:00Z")],
    );
    assert_eq!(code, 0);
    assert!(out.contains("would generate 2.0.0"), "{out}");
    let (code, out, _) = rig.run_env(
        &["vendor", "--pkgdir", "tool-bin", "--version", "2.0.0"],
        &[("OMAPAC_REPO_NOW", NOW)],
    );
    assert_eq!(code, 0);
    assert!(out.contains("would generate 2.0.0"), "{out}");
}

#[test]
fn refuses_the_wrong_key_floor_and_project() {
    let rig = Rig::new();
    let art = rig.path().join("artifacts");
    std::fs::create_dir_all(&art).unwrap();
    let mut vendor = Vendor::new(9);
    vendor.release(&art, "1.0.0", "2026-08-01T00:00:00Z");
    let (base, key) = serve_pointing_at_self(vendor);

    // Pinned to a different key: the release list signature fails first.
    write_package(&rig, &base, &SecretKey::from_seed([4u8; 32]), "");
    let (code, _, err) = rig.run_env(
        &["vendor", "--pkgdir", "tool-bin"],
        &[("OMAPAC_REPO_NOW", NOW)],
    );
    assert_ne!(code, 0);
    assert!(err.contains("release list signature"), "{err}");

    // A floor above what a packslip alone provides.
    write_package(&rig, &base, &key, "provenance_floor = \"l3\"");
    let (code, _, err) = rig.run_env(
        &["vendor", "--pkgdir", "tool-bin"],
        &[("OMAPAC_REPO_NOW", NOW)],
    );
    assert_ne!(code, 0);
    assert!(
        err.contains("evidence level L2, below the floor L3"),
        "{err}"
    );

    // A lock recording a higher level refuses a downgrade unless allowed.
    write_package(&rig, &base, &key, "");
    std::fs::write(
        rig.path().join("tool-bin/vendor.lock"),
        format!(
            "version = \"0.9.0\"\nlevel = \"l3\"\npublished_at = \"2026-07-01T00:00:00Z\"\nkey_id = \"{}\"\ngenerated_at = \"2026-07-02T00:00:00Z\"\n",
            packslip::minisign::key_id_hex(&key.public_key().key_id)
        ),
    )
    .unwrap();
    let (code, _, err) = rig.run_env(
        &["vendor", "--pkgdir", "tool-bin"],
        &[("OMAPAC_REPO_NOW", NOW)],
    );
    assert_ne!(code, 0);
    assert!(err.contains("below the L3 recorded for 0.9.0"), "{err}");
    let (code, out, err) = rig.run_env(
        &["vendor", "--pkgdir", "tool-bin", "--allow-downgrade"],
        &[("OMAPAC_REPO_NOW", NOW)],
    );
    assert_eq!(code, 0, "{err}");
    assert!(out.contains("would generate 1.0.0"), "{out}");

    // The project in vendor.toml must match the list.
    write_package(&rig, &base, &key, "");
    let toml_path = rig.path().join("tool-bin/vendor.toml");
    let toml = std::fs::read_to_string(&toml_path)
        .unwrap()
        .replace("example/tool", "example/other");
    std::fs::write(&toml_path, toml).unwrap();
    let (code, _, err) = rig.run_env(
        &["vendor", "--pkgdir", "tool-bin"],
        &[("OMAPAC_REPO_NOW", NOW)],
    );
    assert_ne!(code, 0);
    assert!(
        err.contains(
            "release list is for pkg:github/example/tool, vendor.toml says pkg:github/example/other"
        ),
        "{err}"
    );
}
