//! The trust feeds: signed index fetched from a local server, verified
//! with a key under the sysroot, rollback protection, and `verify`.

mod common;

use std::process::Command;

use common::Rig;
use packslip::minisign::SecretKey;

/// A signed feed body plus its signature, served at two routes.
fn signed(key: &SecretKey, body: &str) -> (String, String) {
    let sig = key.sign(body.as_bytes(), "feed").to_file();
    (body.to_string(), sig)
}

struct Setup {
    rig: Rig,
    key: SecretKey,
}

fn setup() -> Setup {
    let rig = Rig::new();
    let key = SecretKey::from_seed([42u8; 32]);
    rig.write_root("/etc/omapac/keys/omarchy.pub", &key.public_key().to_file());
    Setup { rig, key }
}

fn serve(s: &Setup, index: &str) -> String {
    let (index_body, index_sig) = signed(&s.key, index);
    common::http::serve(vec![
        ("/stable/x86_64/omapac-index.json.minisig", index_sig),
        ("/stable/x86_64/omapac-index.json", index_body),
    ])
}

fn run(s: &Setup, base: &str, args: &[&str]) -> (i32, String, String) {
    // Point [omarchy] at the local server.
    let conf = common::DEFAULT_CONF.replace(
        "Server = https://pkgs.omarchy.org/stable/$arch",
        &format!("Server = {base}/stable/$arch"),
    );
    s.rig.write_root("/etc/pacman.conf", &conf);
    let output = Command::new(env!("CARGO_BIN_EXE_omapac"))
        .env("HOME", &s.rig.home)
        .env_remove("XDG_CONFIG_HOME")
        .env("XDG_CACHE_HOME", s.rig.dir.path().join("cache"))
        .current_dir(&s.rig.home)
        .arg("--sysroot")
        .arg(&s.rig.root)
        .args(args)
        .output()
        .unwrap();
    (
        output.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

/// An index describing the fixture omarchy.db and its yay package.
fn index(sequence: u64, db_sha: &str, yay_sha: &str) -> String {
    format!(
        r#"{{"version":1,"repo":"omarchy","sequence":{sequence},"generated_at":"2026-09-03T00:00:00Z",
           "db":{{"file":"omarchy.db","sha256":"{db_sha}"}},
           "packages":{{"yay-13.0.1-1-x86_64.pkg.tar.zst":{{"sha256":"{yay_sha}","size":9,"published_at":"2026-08-01T00:00:00Z",
             "sidecars":["yay-13.0.1-1-x86_64.pkg.tar.zst.sig","yay-13.0.1-1-x86_64.pkg.tar.zst.sigstore.json"],
             "evidence":{{"build_provenance":true,"verdicts":1}}}}}}}}"#
    )
}

fn yay_filename(s: &Setup) -> String {
    // The fixture omarchy.db's yay entry names the real file.
    let db = alpm_db::SyncDb::read(
        &s.rig.root.join("var/lib/pacman/sync/omarchy.db"),
        "omarchy",
    )
    .unwrap();
    db.package("yay").unwrap().filename.clone()
}

#[test]
fn verify_checks_the_cached_file_and_the_database_against_the_index() {
    let s = setup();
    let filename = yay_filename(&s);
    // Put a package file in pacman's cache and describe it in the index.
    let cache = s.rig.root.join("var/cache/pacman/pkg");
    std::fs::create_dir_all(&cache).unwrap();
    std::fs::write(cache.join(&filename), b"fake pkg!").unwrap();
    let (yay_sha, _) = packslip::digest_file(&cache.join(&filename)).unwrap();
    let (db_sha, _) =
        packslip::digest_file(&s.rig.root.join("var/lib/pacman/sync/omarchy.db")).unwrap();
    let body = index(5, &db_sha, &yay_sha).replace("yay-13.0.1-1-x86_64.pkg.tar.zst", &filename);
    let base = serve(&s, &body);

    // A same-named file in the current directory does not turn a bare
    // package name into a file target.
    std::fs::write(s.rig.home.join("yay"), b"unrelated").unwrap();
    let (code, out, err) = run(&s, &base, &["verify", "yay"]);
    assert_eq!(code, 0, "{err}\n{out}");
    assert!(out.contains("yay from [omarchy] as "), "{out}");
    assert!(out.contains("index sequence 5, signed by "), "{out}");
    assert!(out.contains("digest: ok"), "{out}");
    assert!(out.contains("sigstore.json"), "{out}");
    assert!(
        out.contains(
            "evidence: build provenance yes, vendor manifest no, 1 verdict(s), reproducible unknown"
        ),
        "{out}"
    );
    assert!(out.contains("database: matches the index"), "{out}");

    // The sequence is now recorded; an older network index is ignored in
    // favor of the newer verified cache.
    let ledger = std::fs::read_to_string(s.rig.root.join("var/lib/omapac/state.json")).unwrap();
    assert!(
        ledger.contains("\"index_sequences\": {\n    \"omarchy\": 5"),
        "{ledger}"
    );
    // A verified cache hit repairs a missing sequence record too.
    std::fs::remove_file(s.rig.root.join("var/lib/omapac/state.json")).unwrap();
    let (code, _, err) = run(&s, "http://127.0.0.1:9", &["verify", "--offline", "yay"]);
    assert_eq!(code, 0, "{err}");
    let ledger = std::fs::read_to_string(s.rig.root.join("var/lib/omapac/state.json")).unwrap();
    assert!(
        ledger.contains("\"index_sequences\": {\n    \"omarchy\": 5"),
        "{ledger}"
    );
    let older = serve(
        &s,
        &index(4, &db_sha, &yay_sha).replace("yay-13.0.1-1-x86_64.pkg.tar.zst", &filename),
    );
    let (code, out, err) = run(&s, &older, &["verify", "yay"]);
    assert_eq!(code, 0, "{err}\n{out}");
    assert!(
        err.contains("index sequence 4 is older than the 5 this machine has seen")
            && err.contains("using the cached copy"),
        "{err}"
    );

    // A tampered package file fails; JSON says why.
    std::fs::write(cache.join(&filename), b"tampered!").unwrap();
    let (code, out, _) = run(&s, &base, &["verify", "--json", "yay"]);
    assert_eq!(code, 1);
    let json: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(json["digest_ok"], false);
    assert_eq!(json["db_ok"], true);

    // Offline uses the cache.
    std::fs::write(cache.join(&filename), b"fake pkg!").unwrap();
    let (code, out, err) = run(&s, "http://127.0.0.1:9", &["verify", "--offline", "yay"]);
    assert_eq!(code, 0, "{err}\n{out}");
}

#[test]
fn verified_network_feed_survives_an_unwritable_cache() {
    let s = setup();
    let filename = yay_filename(&s);
    let package_cache = s.rig.root.join("var/cache/pacman/pkg");
    std::fs::create_dir_all(&package_cache).unwrap();
    std::fs::write(package_cache.join(&filename), b"fake pkg!").unwrap();
    let (yay_sha, _) = packslip::digest_file(&package_cache.join(&filename)).unwrap();
    let (db_sha, _) =
        packslip::digest_file(&s.rig.root.join("var/lib/pacman/sync/omarchy.db")).unwrap();
    let body = index(1, &db_sha, &yay_sha).replace("yay-13.0.1-1-x86_64.pkg.tar.zst", &filename);
    let base = serve(&s, &body);

    // A file at XDG_CACHE_HOME makes cache directory creation fail. The
    // already verified network response remains usable for this invocation.
    std::fs::write(s.rig.dir.path().join("cache"), b"not a directory").unwrap();
    let (code, out, err) = run(&s, &base, &["verify", "yay"]);
    assert_eq!(code, 0, "{err}\n{out}");
    assert!(err.contains("verified feed could not be cached"), "{err}");
    assert!(out.contains("index sequence 1"), "{out}");
}

#[test]
fn bad_signatures_and_missing_keys_are_refused() {
    let s = setup();
    let filename = yay_filename(&s);
    let body = index(1, "00", "11").replace("yay-13.0.1-1-x86_64.pkg.tar.zst", &filename);
    // Signed by a key the machine does not hold.
    let other = SecretKey::from_seed([7u8; 32]);
    let (index_body, index_sig) = signed(&other, &body);
    let base = common::http::serve(vec![
        ("/stable/x86_64/omapac-index.json.minisig", index_sig),
        ("/stable/x86_64/omapac-index.json", index_body),
    ]);
    let (code, _, err) = run(&s, &base, &["verify", "yay"]);
    assert_ne!(code, 0);
    assert!(err.contains("which no key under"), "{err}");

    // A tampered body with a valid signature file.
    let (_, index_sig) = signed(&s.key, &body);
    let base = common::http::serve(vec![
        ("/stable/x86_64/omapac-index.json.minisig", index_sig),
        (
            "/stable/x86_64/omapac-index.json",
            body.replace("\"sequence\":1", "\"sequence\":99"),
        ),
    ]);
    let (code, _, err) = run(&s, &base, &["verify", "yay"]);
    assert_ne!(code, 0);
    assert!(err.contains("does not verify"), "{err}");

    // No keys at all.
    std::fs::remove_file(s.rig.root.join("etc/omapac/keys/omarchy.pub")).unwrap();
    let (code, _, err) = run(&s, &base, &["verify", "yay"]);
    assert_ne!(code, 0);
    assert!(err.contains("no trust keys"), "{err}");

    // Arch packages have no omapac index.
    let (code, _, err) = run(&s, &base, &["verify", "pacman"]);
    assert_ne!(code, 0);
    assert!(err.contains("publishes no omapac index"), "{err}");

    let core =
        alpm_db::SyncDb::read(&s.rig.root.join("var/lib/pacman/sync/core.db"), "core").unwrap();
    let file = s.rig.home.join(&core.package("pacman").unwrap().filename);
    std::fs::write(&file, b"fake arch package").unwrap();
    let (code, _, err) = run(&s, &base, &["verify", file.to_str().unwrap()]);
    assert_ne!(code, 0);
    assert!(err.contains("publishes no omapac index"), "{err}");
}

/// The index lists a provenance envelope and a log entry beside the
/// package; verify fetches and checks both against the build keys the
/// index publishes.
#[test]
fn verify_checks_the_provenance_sidecar_and_the_log_entry() {
    use base64::Engine as _;
    let s = setup();
    let filename = yay_filename(&s);
    let cache = s.rig.root.join("var/cache/pacman/pkg");
    std::fs::create_dir_all(&cache).unwrap();
    std::fs::write(cache.join(&filename), b"fake pkg!").unwrap();
    let (yay_sha, _) = packslip::digest_file(&cache.join(&filename)).unwrap();
    let (db_sha, _) =
        packslip::digest_file(&s.rig.root.join("var/lib/pacman/sync/omarchy.db")).unwrap();
    let build_key = SecretKey::from_seed([77u8; 32]);
    let stranger = SecretKey::from_seed([78u8; 32]);
    let statement = |sha: &str| {
        serde_json::json!({
            "_type": "https://in-toto.io/Statement/v1",
            "subject": [{"name": filename, "digest": {"sha256": sha}}],
            "predicateType": "https://slsa.dev/provenance/v1",
            "predicate": {"buildDefinition": {"externalParameters": {
                "pkgbase": "yay", "source": "https://github.com/omacom/omarchy-pkgs", "commit": "abc123"}}}
        })
    };
    let envelope = |key: &SecretKey, sha: &str| {
        packslip::dsse::Envelope::sign(
            packslip::dsse::IN_TOTO_PAYLOAD_TYPE,
            &serde_json::to_vec(&statement(sha)).unwrap(),
            key,
        )
    };
    let good = envelope(&build_key, &yay_sha);
    let payload_hash: String = {
        use sha2::Digest as _;
        sha2::Sha256::digest(good.payload_bytes().unwrap())
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    };
    let body = serde_json::json!({"apiVersion": "0.0.1", "kind": "dsse",
        "spec": {"payloadHash": {"algorithm": "sha256", "value": payload_hash}}});
    let entry = serde_json::json!({
        "log_url": "https://rekor.example", "uuid": "u", "log_index": 4242, "log_id": "l",
        "integrated_time": 1, "body": base64::engine::general_purpose::STANDARD.encode(serde_json::to_vec(&body).unwrap()),
        "inclusion_proof": {"logIndex": 4242}
    });
    let index = serde_json::json!({
        "version": 1, "repo": "omarchy", "sequence": 7, "generated_at": "2026-09-03T00:00:00Z",
        "db": {"file": "omarchy.db", "sha256": db_sha},
        "packages": {&filename: {"sha256": yay_sha, "size": 9, "published_at": "2026-08-01T00:00:00Z",
            "sidecars": [format!("{filename}.provenance.json"), format!("{filename}.rekor.json")],
            "evidence": {"build_provenance": true}}},
        "build_keys": [build_key.public_key().to_file()]
    })
    .to_string();
    let serve_with = |envelope: &packslip::dsse::Envelope| {
        let (index_body, index_sig) = signed(&s.key, &index);
        common::http::serve(vec![
            ("/stable/x86_64/omapac-index.json.minisig", index_sig),
            ("/stable/x86_64/omapac-index.json", index_body),
            (
                Box::leak(format!("/stable/x86_64/{filename}.provenance.json").into_boxed_str()),
                serde_json::to_string(envelope).unwrap(),
            ),
            (
                Box::leak(format!("/stable/x86_64/{filename}.rekor.json").into_boxed_str()),
                entry.to_string(),
            ),
        ])
    };

    let base = serve_with(&good);
    let (code, out, err) = run(&s, &base, &["verify", "yay"]);
    assert_eq!(code, 0, "{err}\n{out}");
    assert!(
        out.contains("provenance: verified (build key")
            && out.contains("yay at abc123 from https://github.com/omacom/omarchy-pkgs"),
        "{out}"
    );
    assert!(
        out.contains("transparency: entry 4242 at https://rekor.example"),
        "{out}"
    );
    let (_, out, _) = run(&s, &base, &["verify", "--json", "yay"]);
    let json: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(json["provenance"]["verified"], true);
    assert_eq!(json["transparency"]["ok"], true);

    // A stranger's envelope fails, and so does the exit status.
    let base = serve_with(&envelope(&stranger, &yay_sha));
    let (code, out, _) = run(&s, &base, &["verify", "yay"]);
    assert_eq!(code, 1);
    assert!(
        out.contains("provenance: FAILED: not signed by any build key the index publishes"),
        "{out}"
    );
    // An envelope about another digest fails too.
    let base = serve_with(&envelope(&build_key, &"0".repeat(64)));
    let (code, out, _) = run(&s, &base, &["verify", "yay"]);
    assert_eq!(code, 1);
    assert!(
        out.contains("provenance: FAILED: statement does not name the package digest"),
        "{out}"
    );
    assert!(
        out.contains("transparency: FAILED: entry is not about the provenance envelope"),
        "{out}"
    );
}
