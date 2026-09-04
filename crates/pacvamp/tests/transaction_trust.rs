//! Transaction gates bind the pacman plan to signed repository evidence
//! before install, manifest apply, or update may change the machine.

#![cfg(feature = "test-pacman")]

mod common;

use common::Rig;
use packslip::minisign::SecretKey;

struct TrustRig {
    rig: Rig,
    index_key: SecretKey,
    build_key: SecretKey,
    filename: String,
    package: Vec<u8>,
    db_sha: String,
}

impl TrustRig {
    fn new() -> TrustRig {
        let rig = Rig::new();
        let index_key = SecretKey::from_seed([42; 32]);
        let build_key = SecretKey::from_seed([77; 32]);
        rig.write_root(
            "/etc/pacvamp/keys/pacvamp.pub",
            &index_key.public_key().to_file(),
        );
        let db_path = rig.root.join("var/lib/pacman/sync/omarchy.db");
        let db = alpm_db::SyncDb::read(&db_path, "omarchy").unwrap();
        let filename = db.package("yay").unwrap().filename.clone();
        let package = b"transaction package".to_vec();
        let cache = rig.root.join("var/cache/pacman/pkg");
        std::fs::create_dir_all(&cache).unwrap();
        std::fs::write(cache.join(&filename), &package).unwrap();
        let db_sha = pacvamp::trust::sha256_file(&db_path).unwrap();
        TrustRig {
            rig,
            index_key,
            build_key,
            filename,
            package,
            db_sha,
        }
    }

    fn serve(&self, sequence: u64, digest: &str, provenance: bool) -> String {
        self.serve_with_subject(sequence, digest, provenance.then_some(digest))
    }

    fn serve_with_subject(
        &self,
        sequence: u64,
        digest: &str,
        provenance_subject: Option<&str>,
    ) -> String {
        let mut sidecars = Vec::new();
        let mut routes = Vec::new();
        if let Some(provenance_subject) = provenance_subject {
            sidecars.push(format!("{}.provenance.json", self.filename));
            let statement = serde_json::json!({
                "_type": "https://in-toto.io/Statement/v1",
                "subject": [{"name": self.filename, "digest": {"sha256": provenance_subject}}],
                "predicateType": "https://slsa.dev/provenance/v1",
                "predicate": {"buildDefinition": {"externalParameters": {
                    "pkgbase": "yay", "source": "https://github.com/example/packages", "commit": "abc123"
                }}}
            });
            let envelope = packslip::dsse::Envelope::sign(
                packslip::dsse::IN_TOTO_PAYLOAD_TYPE,
                &serde_json::to_vec(&statement).unwrap(),
                &self.build_key,
            );
            routes.push((
                Box::leak(
                    format!("/stable/x86_64/{}.provenance.json", self.filename).into_boxed_str(),
                ) as &'static str,
                serde_json::to_vec(&envelope).unwrap(),
            ));
        }
        let index = serde_json::json!({
            "version": 1,
            "repo": "omarchy",
            "sequence": sequence,
            "generated_at": "2026-09-03T00:00:00Z",
            "db": {"file": "omarchy.db", "sha256": self.db_sha},
            "packages": {&self.filename: {
                "sha256": digest,
                "size": self.package.len(),
                "sidecars": sidecars,
                "evidence": {"build_provenance": provenance_subject.is_some()}
            }},
            "build_keys": [self.build_key.public_key().to_file()]
        })
        .to_string();
        let signature = self.index_key.sign(index.as_bytes(), "index").to_file();
        routes.push((
            "/stable/x86_64/pacvamp-index.json.minisig",
            signature.into_bytes(),
        ));
        routes.push(("/stable/x86_64/pacvamp-index.json", index.into_bytes()));
        common::http::serve_bytes(routes)
    }

    fn configure(&self, base: &str, manifest: &str) {
        let conf = common::DEFAULT_CONF.replace(
            "https://pkgs.omarchy.org/stable/$arch",
            &format!("{base}/stable/$arch"),
        );
        self.rig.write_root("/etc/pacman.conf", &conf);
        std::fs::create_dir_all(self.rig.user_manifest().parent().unwrap()).unwrap();
        std::fs::write(self.rig.user_manifest(), manifest).unwrap();
    }

    fn plan(&self, base: &str) -> String {
        format!(
            "yay\\t13.0.1-1\\tomarchy\\t{base}/stable/x86_64/{}\\t{}\\n",
            self.filename,
            self.package.len()
        )
    }
}

fn digest(bytes: &[u8]) -> String {
    pacvamp::trust::sha256_bytes(bytes)
}

fn applied(log: &[String]) -> bool {
    log.iter().any(|line| {
        (line.contains("-S --noconfirm") || line.contains("-Su --noconfirm"))
            && !line.contains("--print")
            && !line.contains("-Sw")
            && !line.contains("-Suw")
    })
}

#[test]
fn paranoid_install_verifies_and_records_the_exact_package() {
    let s = TrustRig::new();
    let base = s.serve(7, &digest(&s.package), true);
    s.configure(&base, "[policy]\nparanoid = true\n");
    let (code, out, err) = s.rig.run(
        &["install", "-y", "--reinstall", "omarchy/yay"],
        &s.plan(&base),
        0,
    );
    assert_eq!(code, 0, "{err}\n{out}");
    let log = s.rig.log();
    assert!(
        log.iter().any(|line| line.contains("-Sw --noconfirm")),
        "{log:?}"
    );
    assert!(applied(&log), "{log:?}");
    let ledger: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(s.rig.root.join("var/lib/pacvamp/state.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(ledger["index_sequences"]["omarchy"], 7);
    assert_eq!(ledger["packages"]["yay"]["verification"]["level"], "l3");
    assert_eq!(
        ledger["packages"]["yay"]["verification"]["sha256"],
        digest(&s.package)
    );
}

#[test]
fn required_evidence_and_bad_digests_fail_before_install() {
    let s = TrustRig::new();
    let base = s.serve(1, &digest(&s.package), true);
    s.configure(&base, "[policy]\nparanoid = true\n");
    std::fs::remove_file(s.rig.root.join("etc/pacvamp/keys/pacvamp.pub")).unwrap();
    let (code, _, err) = s
        .rig
        .run(&["install", "-y", "--reinstall", "yay"], &s.plan(&base), 0);
    assert_ne!(code, 0);
    assert!(
        err.contains("required transaction evidence unavailable"),
        "{err}"
    );
    assert!(!applied(&s.rig.log()));

    let s = TrustRig::new();
    let base = s.serve(1, &"0".repeat(64), true);
    s.configure(&base, "[policy]\nparanoid = true\n");
    let (code, _, err) = s
        .rig
        .run(&["install", "-y", "--reinstall", "yay"], &s.plan(&base), 0);
    assert_ne!(code, 0);
    assert!(err.contains("cached package does not match"), "{err}");
    assert!(!applied(&s.rig.log()));

    let s = TrustRig::new();
    let base = s.serve_with_subject(1, &digest(&s.package), Some(&"f".repeat(64)));
    s.configure(&base, "[policy]\nparanoid = true\n");
    let (code, _, err) = s
        .rig
        .run(&["install", "-y", "--reinstall", "yay"], &s.plan(&base), 0);
    assert_ne!(code, 0);
    assert!(
        err.contains("provenance failed: statement does not name the package digest"),
        "{err}"
    );
    assert!(!applied(&s.rig.log()));
}

#[test]
fn ordinary_mode_warns_when_keys_are_missing() {
    let s = TrustRig::new();
    let base = s.serve(1, &digest(&s.package), true);
    s.configure(&base, "");
    std::fs::remove_file(s.rig.root.join("etc/pacvamp/keys/pacvamp.pub")).unwrap();
    let (code, out, err) = s
        .rig
        .run(&["install", "-y", "--reinstall", "yay"], &s.plan(&base), 0);
    assert_eq!(code, 0, "{err}\n{out}");
    assert!(
        err.contains("transaction index could not be verified"),
        "{err}"
    );
    assert!(applied(&s.rig.log()));
    assert!(
        s.rig.log().iter().all(|line| !line.contains("-Sw")),
        "no evidence means there is nothing for the pre-download verifier to bind"
    );
}

#[test]
fn stale_indexes_and_evidence_downgrades_are_refused() {
    let s = TrustRig::new();
    let base = s.serve(4, &digest(&s.package), true);
    s.configure(&base, "[policy]\nparanoid = true\n");
    s.rig.write_root(
        "/var/lib/pacvamp/state.json",
        r#"{"schema":1,"packages":{},"index_sequences":{"omarchy":5}}"#,
    );
    let (code, _, err) = s
        .rig
        .run(&["install", "-y", "--reinstall", "yay"], &s.plan(&base), 0);
    assert_ne!(code, 0);
    assert!(err.contains("older than the 5"), "{err}");
    assert!(!applied(&s.rig.log()));

    let s = TrustRig::new();
    let base = s.serve(6, &digest(&s.package), false);
    s.configure(&base, "");
    s.rig.write_root(
        "/var/lib/pacvamp/state.json",
        &format!(r#"{{"schema":1,"packages":{{"yay":{{"version":"13.0.0-1","tier":{{"tier":"opr"}},"repo":"omarchy","verification":{{"index_sequence":5,"index_key":"old","sha256":"{}","level":"l3"}},"explicit":true,"by":"install","at":1}}}},"index_sequences":{{"omarchy":5}}}}"#, digest(&s.package)),
    );
    let (code, _, err) = s
        .rig
        .run(&["install", "-y", "--reinstall", "yay"], &s.plan(&base), 0);
    assert_ne!(code, 0);
    assert!(
        err.contains("evidence would downgrade from L3 to L2"),
        "{err}"
    );
    assert!(!applied(&s.rig.log()));
}

#[test]
fn manifest_apply_and_update_use_the_same_gate() {
    let s = TrustRig::new();
    let base = s.serve(9, &digest(&s.package), true);
    s.configure(
        &base,
        "[policy]\nparanoid = true\n[packages]\nyay = { repo = \"omarchy\" }\n",
    );
    let local = s.rig.root.join("var/lib/pacman/local");
    for entry in std::fs::read_dir(&local).unwrap().filter_map(Result::ok) {
        if entry.file_name().to_string_lossy().starts_with("yay-") {
            std::fs::remove_dir_all(entry.path()).unwrap();
        }
    }
    let (code, out, err) = s.rig.run(&["apply", "-y"], &s.plan(&base), 0);
    assert_eq!(code, 0, "{err}\n{out}");
    assert!(applied(&s.rig.log()));

    let s = TrustRig::new();
    let base = s.serve(10, &digest(&s.package), true);
    s.configure(&base, "[policy]\nparanoid = true\n");
    let (code, out, err) = s.rig.run(
        &["update", "-y", "--no-refresh", "--no-aur"],
        &s.plan(&base),
        0,
    );
    assert_eq!(code, 0, "{err}\n{out}");
    assert!(applied(&s.rig.log()));
}
