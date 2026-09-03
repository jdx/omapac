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
        .env("XDG_CACHE_HOME", s.rig.dir.path().join("cache"))
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

    // The sequence is now recorded; an older index is refused.
    let ledger = std::fs::read_to_string(s.rig.root.join("var/lib/omapac/state.json")).unwrap();
    assert!(ledger.contains("\"index_sequence\": 5"), "{ledger}");
    let older = serve(
        &s,
        &index(4, &db_sha, &yay_sha).replace("yay-13.0.1-1-x86_64.pkg.tar.zst", &filename),
    );
    let (code, _, err) = run(&s, &older, &["verify", "yay"]);
    assert_ne!(code, 0);
    assert!(
        err.contains("older than the 5 this machine has seen"),
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
}
