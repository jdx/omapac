//! The vendor pipeline against a local server publishing a signed release
//! list and packslips, and against a fake GitHub API serving a real
//! keyless packslip.

mod common;

use std::path::Path;

use common::Rig;
use packslip::create::{ArtifactInput, ListRequest, ListedRelease, Request};
use packslip::minisign::SecretKey;
use packslip::sigstore::Signer;

const PKGBUILD: &str = "pkgname=tool-bin\npkgver=1.0.0\npkgrel=2\narch=('x86_64' 'aarch64')\nsource_x86_64=(\"https://dl.example/tool-${pkgver}-linux-x64.tar.gz\")\nsource_aarch64=(\"https://dl.example/tool-${pkgver}-linux-arm64.tar.gz\")\nsha256sums_x86_64=('old')\nsha256sums_aarch64=('old')\npackage() { :; }\n";

const PROJECT: &str = "example.com/tool";

struct Vendor {
    key: SecretKey,
    /// Local bundle files per version, for the release list.
    bundles: Vec<(String, std::path::PathBuf)>,
    routes: Vec<(String, String)>,
}

impl Vendor {
    fn new(seed: u8) -> Vendor {
        Vendor {
            key: SecretKey::from_seed([seed; 32]),
            bundles: Vec::new(),
            routes: Vec::new(),
        }
    }

    fn signer(&self) -> Signer {
        Signer::Key {
            key: self.key.clone(),
            log: false,
        }
    }

    /// Publish a release with artifacts for two platforms, signed with
    /// the vendor's key and, like an air-gapped release, unlogged.
    fn release(&mut self, dir: &Path, version: &str, published_at: &str) {
        let x64 = dir.join(format!("tool-{version}-linux-x64.tar.gz"));
        let arm = dir.join(format!("tool-{version}-linux-arm64.tar.gz"));
        std::fs::write(&x64, format!("x64 {version}")).unwrap();
        std::fs::write(&arm, format!("arm {version}")).unwrap();
        let input = |path| ArtifactInput {
            bin: vec![],
            ..ArtifactInput::new(path)
        };
        let created = packslip::create::create(&Request {
            published_at: Some(published_at),
            artifacts: vec![input(&x64), input(&arm)],
            url_base: Some("https://dl.example/"),
            read_executables: false,
            ..Request::new(PROJECT, version, self.signer().identity())
        })
        .unwrap();
        let bundle = packslip::sigstore::sign(self.signer(), &created.document).unwrap();
        let path = dir.join(format!("packslip-{version}.sigstore.json"));
        std::fs::write(&path, &bundle).unwrap();
        self.bundles.push((version.to_string(), path));
        self.routes.push((
            format!("/releases/{version}/packslip.sigstore.json"),
            bundle,
        ));
    }
}

/// Bind, build the signed list with the bound base, then serve.
fn serve_pointing_at_self(mut vendor: Vendor, sequence: u64) -> (String, SecretKey) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    drop(listener);
    // The list ranks releases under `source` ordering, so newest first.
    let urls: Vec<String> = vendor
        .bundles
        .iter()
        .rev()
        .map(|(v, _)| format!("{base}/releases/{v}/packslip.sigstore.json"))
        .collect();
    let releases = vendor
        .bundles
        .iter()
        .rev()
        .zip(&urls)
        .map(|((_, path), url)| ListedRelease {
            url,
            bundle_path: path,
            yanked: None,
            security: false,
            evidence: vec![],
        })
        .collect();
    let list = packslip::create::create_release_list(&ListRequest {
        project: PROJECT,
        generated_at: Some("2026-09-02T22:00:00Z"),
        valid_for: std::time::Duration::from_secs(30 * 86_400),
        sequence,
        latest: None,
        releases,
        identity: vendor.signer().identity(),
    })
    .unwrap();
    let list_bundle = packslip::sigstore::sign(vendor.signer(), &list.document).unwrap();
    vendor
        .routes
        .push(("/.well-known/packslip/tool.json".into(), list_bundle));
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
            "[upstream]\nproject = \"{PROJECT}\"\nreleases = \"{base}/.well-known/packslip/tool.json\"\npubkey = \"vendor.pub\"\nallow_unlogged = true\n{extra}\n[artifacts]\nx86_64 = {{ os = \"linux\", arch = \"x86_64\" }}\naarch64 = {{ os = \"linux\", arch = \"aarch64\" }}\n"
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
    let (base, key) = serve_pointing_at_self(vendor, 7);
    write_package(&rig, &base, &key, "min_release_age = \"24h\"");

    let (code, out, err) = rig.run_env(
        &["vendor", "--pkgdir", "tool-bin"],
        &[("PACVAMP_REPO_NOW", NOW)],
    );
    assert_eq!(code, 0, "{err}");
    assert!(
        out.contains("would generate 1.5.0 (published 2026-08-20T00:00:00Z, evidence L2, key "),
        "{out}"
    );
    assert!(out.contains("skipped 2.0.0"), "{out}");
    let pkgbuild = std::fs::read_to_string(rig.path().join("tool-bin/PKGBUILD")).unwrap();
    assert_eq!(pkgbuild, PKGBUILD, "no --write, no change");

    let (code, out, err) = rig.run_env(
        &["vendor", "--pkgdir", "tool-bin", "--write", "--json"],
        &[("PACVAMP_REPO_NOW", NOW)],
    );
    assert_eq!(code, 0, "{err}");
    let report: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(report["version"], "1.5.0");
    assert_eq!(report["written"], true);
    assert_eq!(report["scheme"], "sigstore-key");
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
    assert_eq!(sidecar["level"], "l2");
    assert_eq!(sidecar["scheme"], "sigstore-key");
    let statement: serde_json::Value = serde_json::from_slice(
        &packslip::sigstore::peek_statement(sidecar["bundle"].as_str().unwrap()).unwrap(),
    )
    .unwrap();
    assert_eq!(statement["predicate"]["version"], "1.5.0");
    let lock = std::fs::read_to_string(rig.path().join("tool-bin/vendor.lock")).unwrap();
    assert!(lock.contains("version = \"1.5.0\""), "{lock}");
    assert!(lock.contains("level = \"l2\""), "{lock}");
    assert!(lock.contains("list_sequence = 7"), "{lock}");

    // Once the new release is old enough it is picked. Explicit requests
    // still enforce the configured minimum age.
    let (code, out, _) = rig.run_env(
        &["vendor", "--pkgdir", "tool-bin"],
        &[("PACVAMP_REPO_NOW", "2026-09-05T00:00:00Z")],
    );
    assert_eq!(code, 0);
    assert!(out.contains("would generate 2.0.0"), "{out}");
    let (code, _, err) = rig.run_env(
        &["vendor", "--pkgdir", "tool-bin", "--version", "2.0.0"],
        &[("PACVAMP_REPO_NOW", NOW)],
    );
    assert_ne!(code, 0);
    assert!(err.contains("younger than"), "{err}");

    // A list older than the one recorded is a rollback.
    let lock_path = rig.path().join("tool-bin/vendor.lock");
    let lock = std::fs::read_to_string(&lock_path)
        .unwrap()
        .replace("list_sequence = 7", "list_sequence = 9");
    std::fs::write(&lock_path, lock).unwrap();
    let (code, _, err) = rig.run_env(
        &["vendor", "--pkgdir", "tool-bin"],
        &[("PACVAMP_REPO_NOW", NOW)],
    );
    assert_ne!(code, 0);
    assert!(err.contains("sequence 7 is below the 9"), "{err}");

    // An expired list is refused.
    let (code, _, err) = rig.run_env(
        &["vendor", "--pkgdir", "tool-bin", "--allow-downgrade"],
        &[("PACVAMP_REPO_NOW", "2026-12-01T00:00:00Z")],
    );
    assert_ne!(code, 0);
    assert!(err.contains("release list expired"), "{err}");
}

#[test]
fn refuses_the_wrong_key_floor_unlogged_and_project() {
    let rig = Rig::new();
    let art = rig.path().join("artifacts");
    std::fs::create_dir_all(&art).unwrap();
    let mut vendor = Vendor::new(9);
    vendor.release(&art, "1.0.0", "2026-08-01T00:00:00Z");
    let (base, key) = serve_pointing_at_self(vendor, 1);

    // Pinned to a different key: the release list fails first.
    write_package(&rig, &base, &SecretKey::from_seed([4u8; 32]), "");
    let (code, _, err) = rig.run_env(
        &["vendor", "--pkgdir", "tool-bin"],
        &[("PACVAMP_REPO_NOW", NOW)],
    );
    assert_ne!(code, 0);
    assert!(err.contains("verifying the release list"), "{err}");
    assert!(err.contains("does not verify with the pinned key"), "{err}");

    // Unlogged bundles need the package to say so.
    write_package(&rig, &base, &key, "");
    let toml_path = rig.path().join("tool-bin/vendor.toml");
    let strict = std::fs::read_to_string(&toml_path)
        .unwrap()
        .replace("allow_unlogged = true\n", "");
    std::fs::write(&toml_path, strict).unwrap();
    let (code, _, err) = rig.run_env(
        &["vendor", "--pkgdir", "tool-bin"],
        &[("PACVAMP_REPO_NOW", NOW)],
    );
    assert_ne!(code, 0);
    assert!(err.contains("no transparency log entry"), "{err}");

    // A floor above what a packslip without provenance provides.
    write_package(&rig, &base, &key, "provenance_floor = \"l3\"");
    let (code, _, err) = rig.run_env(
        &["vendor", "--pkgdir", "tool-bin"],
        &[("PACVAMP_REPO_NOW", NOW)],
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
        &[("PACVAMP_REPO_NOW", NOW)],
    );
    assert_ne!(code, 0);
    assert!(err.contains("below the L3 recorded for 0.9.0"), "{err}");
    let (code, out, err) = rig.run_env(
        &["vendor", "--pkgdir", "tool-bin", "--allow-downgrade"],
        &[("PACVAMP_REPO_NOW", NOW)],
    );
    assert_eq!(code, 0, "{err}");
    assert!(out.contains("would generate 1.0.0"), "{out}");

    // The project in vendor.toml must match the list.
    write_package(&rig, &base, &key, "");
    let toml = std::fs::read_to_string(&toml_path)
        .unwrap()
        .replace("example.com/tool", "example.com/other");
    std::fs::write(&toml_path, toml).unwrap();
    let (code, _, err) = rig.run_env(
        &["vendor", "--pkgdir", "tool-bin"],
        &[("PACVAMP_REPO_NOW", NOW)],
    );
    assert_ne!(code, 0);
    assert!(
        err.contains("release list is for example.com/tool, vendor.toml says example.com/other"),
        "{err}"
    );
}

#[test]
fn refuses_an_empty_artifact_map_before_rewriting() {
    let rig = Rig::new();
    let key = SecretKey::from_seed([9u8; 32]);
    write_package(&rig, "http://127.0.0.1:9", &key, "");
    let pkgdir = rig.path().join("tool-bin");
    let config = std::fs::read_to_string(pkgdir.join("vendor.toml")).unwrap();
    let config = config.split("[artifacts]").next().unwrap();
    std::fs::write(pkgdir.join("vendor.toml"), config).unwrap();
    let before = std::fs::read_to_string(pkgdir.join("PKGBUILD")).unwrap();
    let (code, _, err) = rig.run_env(
        &["vendor", "--write", "--pkgdir", "tool-bin"],
        &[("PACVAMP_REPO_NOW", NOW)],
    );
    assert_ne!(code, 0);
    assert!(err.contains("at least one [artifacts] selector"), "{err}");
    assert_eq!(
        std::fs::read_to_string(pkgdir.join("PKGBUILD")).unwrap(),
        before
    );
    assert!(!pkgdir.join("vendor.lock").exists());
}

/// A github.com project needs no release list and no pubkey: GitHub's API
/// lists the releases and the name implies the signer. The fixture is the
/// real packslip jdx/packslip published for its v0.1.0 release, signed
/// keylessly by its release workflow and logged to Rekor.
#[test]
fn lists_github_releases_and_verifies_a_keyless_packslip() {
    let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/packslip");
    let bundle = std::fs::read_to_string(fixtures.join("packslip.sigstore.json")).unwrap();
    let statement: serde_json::Value =
        serde_json::from_slice(&packslip::sigstore::peek_statement(&bundle).unwrap()).unwrap();
    let version = statement["predicate"]["version"]
        .as_str()
        .unwrap()
        .to_string();
    let published_at = statement["predicate"]["published_at"]
        .as_str()
        .unwrap()
        .to_string();

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    drop(listener);
    let api = serde_json::json!([
        { "tag_name": "v9.9.9-rc1", "published_at": "2026-09-09T00:00:00Z",
          "draft": false, "prerelease": true,
          "assets": [{ "name": "packslip.sigstore.json", "browser_download_url": format!("{base}/rc/packslip.sigstore.json") }] },
        { "tag_name": format!("v{version}"), "published_at": published_at,
          "draft": false, "prerelease": false,
          "assets": [
            { "name": "packslip-v0.1.0-linux-x64.tar.xz", "browser_download_url": format!("{base}/dl/x") },
            { "name": "packslip.sigstore.json", "browser_download_url": format!("{base}/dl/packslip.sigstore.json") }
          ] },
        { "tag_name": "v0.0.1", "published_at": "2026-01-01T00:00:00Z",
          "draft": false, "prerelease": false, "assets": [] }
    ]);
    let routes = vec![
        (
            "/repos/jdx/packslip/releases?per_page=50".to_string(),
            api.to_string(),
        ),
        ("/dl/packslip.sigstore.json".to_string(), bundle.clone()),
    ];
    let base = common::http::serve_at(&base, routes);

    let rig = Rig::new();
    let pkgdir = rig.path().join("packslip-bin");
    std::fs::create_dir_all(&pkgdir).unwrap();
    let pkgbuild = "pkgname=packslip-bin\npkgver=0.0.1\npkgrel=1\narch=('x86_64' 'aarch64')\nsha256sums_x86_64=('old')\nsha256sums_aarch64=('old')\npackage() { :; }\n";
    std::fs::write(pkgdir.join("PKGBUILD"), pkgbuild).unwrap();
    let write_toml = |extra: &str| {
        std::fs::write(
            pkgdir.join("vendor.toml"),
            format!(
                "[upstream]\nproject = \"github.com/jdx/packslip\"\n{extra}\n[artifacts]\nx86_64 = {{ os = \"linux\", arch = \"x86_64\" }}\naarch64 = {{ os = \"linux\", arch = \"aarch64\" }}\n"
            ),
        )
        .unwrap();
    };
    write_toml("");
    let env = [
        ("PACVAMP_REPO_NOW", "2026-12-01T00:00:00Z"),
        ("PACVAMP_REPO_GITHUB_API", base.as_str()),
    ];

    let (code, out, err) = rig.run_env(&["vendor", "--pkgdir", "packslip-bin"], &env);
    assert_eq!(code, 0, "{err}");
    assert!(
        out.contains(&format!("would generate {version} (published {published_at}, evidence L2, identity https://github.com/jdx/packslip/.github/workflows/release.yml@refs/tags/v{version})")),
        "{out}"
    );
    assert!(
        out.contains("x86_64: packslip-v0.1.0-linux-x64.tar.xz"),
        "{out}"
    );

    let (code, out, err) = rig.run_env(
        &["vendor", "--pkgdir", "packslip-bin", "--write", "--json"],
        &env,
    );
    assert_eq!(code, 0, "{err}");
    let report: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(report["scheme"], "sigstore-oidc");
    assert_eq!(report["version"], version);
    assert!(
        report["logged_at"]
            .as_str()
            .unwrap()
            .starts_with("2026-09-03T")
    );
    let lock = std::fs::read_to_string(pkgdir.join("vendor.lock")).unwrap();
    assert!(lock.contains("scheme = \"sigstore-oidc\""), "{lock}");
    let sidecar: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(pkgdir.join("packslip-bin.vendor.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(sidecar["scheme"], "sigstore-oidc");
    assert!(sidecar["bundle"].as_str().unwrap().contains("dsseEnvelope"));
    let rewritten = std::fs::read_to_string(pkgdir.join("PKGBUILD")).unwrap();
    assert!(
        rewritten.contains(&format!("pkgver={version}\n")),
        "{rewritten}"
    );

    // A new tag of the same workflow is the same signer for no-downgrade.
    let (code, _, err) = rig.run_env(&["vendor", "--pkgdir", "packslip-bin"], &env);
    assert_eq!(code, 0, "{err}");

    // Pinning another repository's workflows refuses this signer.
    write_toml("identity_prefix = \"https://github.com/someone/else/\"");
    let (code, _, err) = rig.run_env(&["vendor", "--pkgdir", "packslip-bin"], &env);
    assert_ne!(code, 0);
    assert!(err.contains("expected an identity starting with"), "{err}");

    // A name that is not a github.com project needs an explicit pin.
    std::fs::write(
        pkgdir.join("vendor.toml"),
        "[upstream]\nproject = \"tool.example.com\"\n[artifacts]\nx86_64 = { os = \"linux\" }\n",
    )
    .unwrap();
    let (code, _, err) = rig.run_env(&["vendor", "--pkgdir", "packslip-bin"], &env);
    assert_ne!(code, 0);
    assert!(err.contains("needs a pubkey"), "{err}");
}

/// One GitHub release carrying packslips for two tools of a monorepo,
/// plus a release-list bundle that must be ignored: the listing keeps the
/// bundle whose statement names the project, never trusting file names.
/// Signed with a pinned key, since a keyless bundle cannot be forged in a
/// test; the listing code is the same either way.
#[test]
fn lists_monorepo_tools_from_one_release() {
    let key = SecretKey::from_seed([5u8; 32]);
    let signer = || Signer::Key {
        key: key.clone(),
        log: false,
    };
    let rig = Rig::new();
    let art = rig.path().join("artifacts");
    std::fs::create_dir_all(&art).unwrap();
    let bundle_for = |project: &str, files: &[(&str, Option<&str>)]| -> String {
        let paths: Vec<std::path::PathBuf> = files
            .iter()
            .map(|(name, _)| {
                let p = art.join(name);
                std::fs::write(&p, name.as_bytes()).unwrap();
                p
            })
            .collect();
        let artifacts = paths
            .iter()
            .zip(files)
            .map(|(p, (_, variant))| ArtifactInput {
                variant: variant.map(str::to_string),
                bin: vec![],
                ..ArtifactInput::new(p)
            })
            .collect();
        let created = packslip::create::create(&Request {
            published_at: Some("2026-08-01T00:00:00Z"),
            artifacts,
            url_base: Some("https://dl.example/"),
            read_executables: false,
            ..Request::new(project, "1.0.0", signer().identity())
        })
        .unwrap();
        packslip::sigstore::sign(signer(), &created.document).unwrap()
    };
    let alpha = bundle_for(
        "github.com/acme/mono/alpha",
        &[
            ("alpha-1.0.0-linux-x64.tar.gz", None),
            ("alpha-fips-1.0.0-linux-x64.tar.gz", Some("fips")),
            ("alpha-1.0.0-linux-arm64.tar.gz", None),
        ],
    );
    let beta = bundle_for(
        "github.com/acme/mono/beta",
        &[
            ("beta-1.0.0-linux-x64.tar.gz", None),
            ("beta-1.0.0-linux-arm64.tar.gz", None),
        ],
    );
    // A release list also matches the packslip*.sigstore.json glob.
    let alpha_path = art.join("alpha.sigstore.json");
    std::fs::write(&alpha_path, &alpha).unwrap();
    let list = packslip::create::create_release_list(&ListRequest {
        project: "github.com/acme/mono/alpha",
        generated_at: Some("2026-08-01T00:00:00Z"),
        valid_for: std::time::Duration::from_secs(86_400 * 365),
        sequence: 1,
        latest: None,
        releases: vec![ListedRelease {
            url: "https://dl.example/alpha.sigstore.json",
            bundle_path: &alpha_path,
            yanked: None,
            security: false,
            evidence: vec![],
        }],
        identity: signer().identity(),
    })
    .unwrap();
    let list_bundle = packslip::sigstore::sign(signer(), &list.document).unwrap();

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    drop(listener);
    let api = serde_json::json!([{
        "tag_name": "v1.0.0", "published_at": "2026-08-01T00:00:00Z",
        "draft": false, "prerelease": false,
        "assets": [
            { "name": "packslip-releases.sigstore.json", "browser_download_url": format!("{base}/dl/packslip-releases.sigstore.json") },
            { "name": "packslip.alpha.sigstore.json", "browser_download_url": format!("{base}/dl/packslip.alpha.sigstore.json") },
            { "name": "packslip.beta.sigstore.json", "browser_download_url": format!("{base}/dl/packslip.beta.sigstore.json") }
        ]
    }]);
    let base = common::http::serve_at(
        &base,
        vec![
            (
                "/repos/acme/mono/releases?per_page=50".to_string(),
                api.to_string(),
            ),
            (
                "/dl/packslip-releases.sigstore.json".to_string(),
                list_bundle,
            ),
            ("/dl/packslip.alpha.sigstore.json".to_string(), alpha),
            ("/dl/packslip.beta.sigstore.json".to_string(), beta),
        ],
    );
    let env = [
        ("PACVAMP_REPO_NOW", "2026-09-01T00:00:00Z"),
        ("PACVAMP_REPO_GITHUB_API", base.as_str()),
    ];
    let package = |name: &str, project: &str, x64: &str| {
        let pkgdir = rig.path().join(name);
        std::fs::create_dir_all(&pkgdir).unwrap();
        std::fs::write(
            pkgdir.join("PKGBUILD"),
            format!("pkgname={name}\npkgver=0.1\npkgrel=1\narch=('x86_64' 'aarch64')\nsha256sums_x86_64=('old')\nsha256sums_aarch64=('old')\npackage() {{ :; }}\n"),
        )
        .unwrap();
        std::fs::write(pkgdir.join("vendor.pub"), key.public_key().to_file()).unwrap();
        std::fs::write(
            pkgdir.join("vendor.toml"),
            format!(
                "[upstream]\nproject = \"{project}\"\npubkey = \"vendor.pub\"\nallow_unlogged = true\n[artifacts]\nx86_64 = {{ {x64} }}\naarch64 = {{ os = \"linux\", arch = \"aarch64\" }}\n"
            ),
        )
        .unwrap();
    };

    package(
        "beta-bin",
        "github.com/acme/mono/beta",
        "os = \"linux\", arch = \"x86_64\"",
    );
    let (code, out, err) = rig.run_env(&["vendor", "--pkgdir", "beta-bin"], &env);
    assert_eq!(code, 0, "{err}");
    assert!(out.contains("would generate 1.0.0"), "{out}");
    assert!(out.contains("x86_64: beta-1.0.0-linux-x64.tar.gz"), "{out}");

    // Packslip v1 defaults to the unlabelled build; named variants are opt-in.
    package(
        "alpha-bin",
        "github.com/acme/mono/alpha",
        "os = \"linux\", arch = \"x86_64\"",
    );
    let (code, out, err) = rig.run_env(&["vendor", "--pkgdir", "alpha-bin"], &env);
    assert_eq!(code, 0, "{err}");
    assert!(
        out.contains("x86_64: alpha-1.0.0-linux-x64.tar.gz"),
        "{out}"
    );
    package(
        "alpha-bin",
        "github.com/acme/mono/alpha",
        "os = \"linux\", arch = \"x86_64\", variant = \"fips\"",
    );
    let (code, out, err) = rig.run_env(&["vendor", "--pkgdir", "alpha-bin"], &env);
    assert_eq!(code, 0, "{err}");
    assert!(
        out.contains("x86_64: alpha-fips-1.0.0-linux-x64.tar.gz"),
        "{out}"
    );

    // A tool the release does not carry has nothing to install.
    package(
        "gamma-bin",
        "github.com/acme/mono/gamma",
        "os = \"linux\", arch = \"x86_64\"",
    );
    let (code, _, err) = rig.run_env(&["vendor", "--pkgdir", "gamma-bin"], &env);
    assert_ne!(code, 0);
    assert!(err.contains("no release with a packslip for it"), "{err}");
}
#[test]
fn a_later_write_failure_still_leaves_the_protective_lock() {
    let rig = Rig::new();
    let art = rig.path().join("artifacts");
    std::fs::create_dir_all(&art).unwrap();
    let mut vendor = Vendor::new(9);
    vendor.release(&art, "1.5.0", "2026-08-20T00:00:00Z");
    let (base, key) = serve_pointing_at_self(vendor, 7);
    write_package(&rig, &base, &key, "");
    std::fs::create_dir(rig.path().join("tool-bin/tool-bin.vendor.json")).unwrap();

    let (code, _, err) = rig.run_env(
        &["vendor", "--pkgdir", "tool-bin", "--write"],
        &[("PACVAMP_REPO_NOW", NOW)],
    );
    assert_ne!(code, 0);
    assert!(err.contains("tool-bin.vendor.json"), "{err}");
    let lock = std::fs::read_to_string(rig.path().join("tool-bin/vendor.lock")).unwrap();
    assert!(lock.contains("version = \"1.5.0\""), "{lock}");
    assert_eq!(
        std::fs::read_to_string(rig.path().join("tool-bin/PKGBUILD")).unwrap(),
        PKGBUILD
    );
}
