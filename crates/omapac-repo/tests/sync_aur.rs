//! The sync gate and feed commands against a fake AUR (bare git
//! repositories plus a replayed RPC) and the fixture sysroot.

mod common;

use std::path::Path;
use std::sync::Arc;

use common::Rig;
use common::aur::{EVIL_INSTALL, EVIL_PKGBUILD, EVIL_SRCINFO, FakeAur, YAY_PKGBUILD, YAY_SRCINFO};

fn fixtures() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../alpm-db/fixtures")
}

/// A sysroot with the fixture pacman.conf and sync databases.
fn sysroot(rig: &Rig) -> std::path::PathBuf {
    let root = rig.path().join("root");
    std::fs::create_dir_all(root.join("etc")).unwrap();
    std::fs::create_dir_all(root.join("var/lib/pacman/sync")).unwrap();
    std::fs::create_dir_all(root.join("var/lib/pacman/local")).unwrap();
    std::fs::write(
        root.join("etc/pacman.conf"),
        "[options]\nArchitecture = x86_64\nSigLevel = Required DatabaseOptional\n[core]\nServer = https://m/$repo/os/$arch\n[omarchy]\nServer = https://pkgs.omarchy.org/stable/$arch\n",
    )
    .unwrap();
    for db in ["core.db", "omarchy.db"] {
        std::fs::copy(
            fixtures().join("sync").join(db),
            root.join("var/lib/pacman/sync").join(db),
        )
        .unwrap();
    }
    root
}

/// Replay the AUR RPC fixture for any info query.
fn rpc() -> String {
    let info = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../omapac/fixtures/aur/info.json"),
    )
    .unwrap();
    common::http::serve_with(Arc::new(move |_m, path, _b| {
        if path.starts_with("/rpc/v5/info") {
            (200, info.clone())
        } else {
            (404, "{}".into())
        }
    }))
}

const YAY_BUMP_PKGBUILD: &str = "# Maintainer: jguer\npkgname=yay\npkgver=13.0.2\npkgrel=1\nsource=(\"yay-13.0.2.tar.gz::https://github.com/Jguer/yay/archive/v13.0.2.tar.gz\")\nsha256sums=('0000000000000000000000000000000000000000000000000000000000000000')\nbuild() {\n  make build\n}\npackage() {\n  make DESTDIR=\"$pkgdir\" install\n}\n";
const YAY_BUMP_SRCINFO: &str = "pkgbase = yay\n\tpkgver = 13.0.2\n\tpkgrel = 1\n\tarch = x86_64\n\tsource = yay-13.0.2.tar.gz::https://github.com/Jguer/yay/archive/v13.0.2.tar.gz\n\tsha256sums = 0000000000000000000000000000000000000000000000000000000000000000\n\npkgname = yay\n";

struct Gate {
    rig: Rig,
    aur: FakeAur,
    rpc: String,
    root: std::path::PathBuf,
}

impl Gate {
    fn new() -> Gate {
        let rig = Rig::new();
        let aur = FakeAur::new(rig.path());
        let rpc = rpc();
        let root = sysroot(&rig);
        rig.keygen("feed", 5);
        Gate {
            rig,
            aur,
            rpc,
            root,
        }
    }

    fn run(&self, extra: &[&str]) -> (i32, String, String) {
        let mut args = vec![
            "sync-aur",
            "--state",
            "state.json",
            "--cache",
            "cache",
            "--sysroot",
        ];
        let root = self.root.to_str().unwrap().to_string();
        args.push(&root);
        args.extend_from_slice(extra);
        self.rig.run_env(
            &args,
            &[
                ("OMAPAC_AUR_RPC_BASE", &self.rpc),
                ("OMAPAC_AUR_GIT_BASE", &self.aur.base()),
                ("OMAPAC_REPO_NOW", "2026-09-03T00:00:00Z"),
            ],
        )
    }

    fn state(&self) -> serde_json::Value {
        serde_json::from_str(&std::fs::read_to_string(self.rig.path().join("state.json")).unwrap())
            .unwrap()
    }

    fn write_state(&self, package: &str, commit: &str, pkgver: &str) {
        std::fs::write(
            self.rig.path().join("state.json"),
            serde_json::json!({"packages": {package: {"commit": commit, "pkgver": pkgver, "synced_at": "2026-01-01T00:00:00Z", "maintainer": "jguer"}}}).to_string(),
        )
        .unwrap();
    }
}

#[test]
fn clean_bump_by_trusted_maintainer_auto_merges() {
    let g = Gate::new();
    g.aur.create(
        "yay",
        &[("PKGBUILD", YAY_PKGBUILD), (".SRCINFO", YAY_SRCINFO)],
        "2024-01-01T00:00:00Z",
    );
    let first = g.aur.head("yay");
    g.write_state("yay", &first, "13.0.1-1");

    // Nothing new: unchanged.
    let (code, out, err) = g.run(&["--trusted-maintainer", "jguer"]);
    assert_eq!(code, 0, "{err}\n{out}");
    assert!(out.contains("unchanged    yay"), "{out}");

    // State written before maintainer tracking was added must bootstrap the
    // current maintainer rather than treating the first later bump as a takeover.
    std::fs::write(
        g.rig.path().join("state.json"),
        serde_json::json!({"packages": {"yay": {
            "commit": first,
            "pkgver": "13.0.1-1",
            "synced_at": "2026-01-01T00:00:00Z"
        }}})
        .to_string(),
    )
    .unwrap();

    g.aur.commit(
        "yay",
        &[
            ("PKGBUILD", YAY_BUMP_PKGBUILD),
            (".SRCINFO", YAY_BUMP_SRCINFO),
        ],
        "bump",
        "2024-02-01T00:00:00Z",
    );
    let second = g.aur.head("yay");

    // Untrusted maintainer: clean, but a human merges.
    let (code, out, err) = g.run(&[]);
    assert_eq!(code, 0, "{err}\n{out}");
    assert!(out.contains("needs-review yay"), "{out}");
    assert!(
        out.contains("maintainer jguer is not on the trusted list"),
        "{out}"
    );
    assert_eq!(
        g.state()["packages"]["yay"]["commit"],
        first,
        "no --write, no change"
    );

    // Trusted: auto-merge, recorded, with a pass verdict on the feed.
    let (code, out, err) = g.run(&[
        "--trusted-maintainer",
        "jguer",
        "--write",
        "--verdicts",
        "verdicts.json",
        "--key",
        "feed.key",
        "--json",
    ]);
    assert_eq!(code, 0, "{err}\n{out}");
    let results: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(results[0]["outcome"], "auto-merge");
    assert_eq!(results[0]["from"], first);
    assert_eq!(results[0]["to"], second);
    assert_eq!(results[0]["pkgver"], "13.0.2-1");
    assert_eq!(results[0]["findings"].as_array().unwrap().len(), 0);
    assert_eq!(g.state()["packages"]["yay"]["commit"], second);
    assert_eq!(g.state()["packages"]["yay"]["pkgver"], "13.0.2-1");
    assert_eq!(g.state()["packages"]["yay"]["maintainer"], "jguer");
    let feed_bytes = std::fs::read(g.rig.path().join("verdicts.json")).unwrap();
    let sig = packslip::minisign::Sig::parse(
        &std::fs::read_to_string(g.rig.path().join("verdicts.json.minisig")).unwrap(),
    )
    .unwrap();
    packslip::minisign::SecretKey::from_seed([5u8; 32])
        .public_key()
        .verify(&feed_bytes, &sig)
        .unwrap();
    let feed: omapac::trust::feeds::Verdicts = serde_json::from_slice(&feed_bytes).unwrap();
    assert_eq!(feed.sequence, 1);
    let verdict = feed
        .for_commit("yay", &second)
        .into_iter()
        .next()
        .expect("a verdict for the commit");
    assert_eq!(verdict.reviewer.kind, "static");
    assert_eq!(verdict.verdict, omapac::trust::feeds::VerdictKind::Pass);

    // Unchanged again, and no new verdict.
    let (code, out, _) = g.run(&[
        "--trusted-maintainer",
        "jguer",
        "--verdicts",
        "verdicts.json",
        "--key",
        "feed.key",
    ]);
    assert_eq!(code, 0);
    assert!(out.contains("unchanged    yay"), "{out}");
    let feed: omapac::trust::feeds::Verdicts =
        serde_json::from_slice(&std::fs::read(g.rig.path().join("verdicts.json")).unwrap())
            .unwrap();
    assert_eq!(feed.sequence, 1);
}

#[test]
fn hostile_takeover_is_blocked_with_a_block_verdict() {
    let g = Gate::new();
    g.aur.create(
        "yay",
        &[("PKGBUILD", YAY_PKGBUILD), (".SRCINFO", YAY_SRCINFO)],
        "2024-01-01T00:00:00Z",
    );
    let first = g.aur.head("yay");
    g.write_state("yay", &first, "13.0.1-1");
    g.aur.commit(
        "yay",
        &[
            ("PKGBUILD", EVIL_PKGBUILD),
            (".SRCINFO", EVIL_SRCINFO),
            ("yay.install", EVIL_INSTALL),
        ],
        "update",
        "2024-02-01T00:00:00Z",
    );
    let evil = g.aur.head("yay");
    let (code, out, err) = g.run(&[
        "--trusted-maintainer",
        "jguer",
        "--write",
        "--verdicts",
        "verdicts.json",
        "--key",
        "feed.key",
    ]);
    assert_ne!(code, 0);
    assert!(out.contains("BLOCKED      yay"), "{out}");
    assert!(out.contains("install-script"), "{out}");
    assert!(out.contains("checksum-skip"), "{out}");
    assert!(err.contains("1 package(s) blocked or failed"), "{err}");
    assert_eq!(
        g.state()["packages"]["yay"]["commit"],
        first,
        "blocked commits are never recorded"
    );
    let feed: omapac::trust::feeds::Verdicts =
        serde_json::from_slice(&std::fs::read(g.rig.path().join("verdicts.json")).unwrap())
            .unwrap();
    let verdict = feed.for_commit("yay", &evil).into_iter().next().unwrap();
    assert_eq!(verdict.verdict, omapac::trust::feeds::VerdictKind::Block);
    assert!(
        verdict.findings.iter().any(|f| f == "install-script"),
        "{:?}",
        verdict.findings
    );
}

#[test]
fn new_packages_and_unknown_ones() {
    let g = Gate::new();
    g.aur.create(
        "yay",
        &[("PKGBUILD", YAY_PKGBUILD), (".SRCINFO", YAY_SRCINFO)],
        "2024-01-01T00:00:00Z",
    );
    let (code, out, _) = g.run(&["--package", "yay", "--trusted-maintainer", "jguer"]);
    assert_eq!(code, 0, "{out}");
    assert!(out.contains("needs-review yay new at"), "{out}");
    assert!(
        out.contains("new package: a human must approve the first commit"),
        "{out}"
    );
    let (code, out, err) = g.run(&["--package", "nonexistent"]);
    assert_ne!(code, 0);
    assert!(out.contains("error        nonexistent"), "{out}\n{err}");
    let (code, _, err) = g.run(&[]);
    assert_ne!(code, 0);
    assert!(err.contains("no packages"), "{err}");
}

#[test]
fn verdict_and_advisory_feeds() {
    let rig = Rig::new();
    rig.keygen("feed", 5);
    let (code, out, err) = rig.run(&[
        "verdict",
        "--feed",
        "verdicts.json",
        "--key",
        "feed.key",
        "--pkgbase",
        "helix-bin",
        "--commit",
        "3f9c1a2b",
        "--kind",
        "human",
        "--reviewer",
        "jdx",
        "--verdict",
        "pass",
        "--summary",
        "read the diff",
    ]);
    assert_eq!(code, 0, "{err}\n{out}");
    assert!(out.contains("sequence 1, 1 verdict(s), 1 added"), "{out}");
    std::fs::write(
        rig.path().join("batch.json"),
        r#"[{"subject":{"sha256":"abcd"},"reviewer":{"kind":"av","id":"clamav","version":"1.4.2"},"verdict":"pass","issued_at":"2026-09-03T00:00:00Z"}]"#,
    )
    .unwrap();
    let (code, out, err) = rig.run(&[
        "verdict",
        "--feed",
        "verdicts.json",
        "--key",
        "feed.key",
        "--from",
        "batch.json",
    ]);
    assert_eq!(code, 0, "{err}\n{out}");
    assert!(out.contains("sequence 2, 2 verdict(s), 1 added"), "{out}");
    let feed: omapac::trust::feeds::Verdicts =
        serde_json::from_slice(&std::fs::read(rig.path().join("verdicts.json")).unwrap()).unwrap();
    assert_eq!(feed.verdicts[0].reviewer.id, "jdx");
    assert_eq!(feed.for_digest("abcd").len(), 1);
    let (code, _, err) = rig.run(&[
        "verdict",
        "--feed",
        "v.json",
        "--key",
        "feed.key",
        "--pkgbase",
        "x",
        "--kind",
        "human",
        "--reviewer",
        "r",
        "--verdict",
        "pass",
    ]);
    assert_ne!(code, 0);
    assert!(
        err.contains("give --pkgbase with --commit, or --sha256"),
        "{err}"
    );

    let (code, out, err) = rig.run(&[
        "advisories",
        "--feed",
        "advisories.json",
        "--key",
        "feed.key",
        "add",
        "--id",
        "OPR-2026-0007",
        "--pkgbase",
        "helix-bin",
        "--commit",
        "3f9c1a2b",
        "--tier",
        "aur",
        "--action",
        "block",
        "--reason",
        "maintainer account compromised",
        "--url",
        "https://pkgs.omarchy.org/advisories/OPR-2026-0007",
    ]);
    assert_eq!(code, 0, "{err}\n{out}");
    assert!(out.contains("added OPR-2026-0007"), "{out}");
    assert!(out.contains("sequence 1, 1 advisory"), "{out}");
    let (code, _, err) = rig.run(&[
        "advisories",
        "--feed",
        "advisories.json",
        "--key",
        "feed.key",
        "add",
        "--id",
        "OPR-2026-0007",
        "--pkgbase",
        "x",
        "--action",
        "hold",
        "--reason",
        "dup",
    ]);
    assert_ne!(code, 0);
    assert!(err.contains("already exists"), "{err}");
    let feed_bytes = std::fs::read(rig.path().join("advisories.json")).unwrap();
    let sig = packslip::minisign::Sig::parse(
        &std::fs::read_to_string(rig.path().join("advisories.json.minisig")).unwrap(),
    )
    .unwrap();
    packslip::minisign::SecretKey::from_seed([5u8; 32])
        .public_key()
        .verify(&feed_bytes, &sig)
        .unwrap();
    let feed: omapac::trust::feeds::Advisories = serde_json::from_slice(&feed_bytes).unwrap();
    assert_eq!(feed.advisories[0].commits, vec!["3f9c1a2b"]);
    assert_eq!(
        feed.advisories[0].action,
        omapac::trust::feeds::AdvisoryAction::Block
    );
    let (code, out, _) = rig.run(&[
        "advisories",
        "--feed",
        "advisories.json",
        "--key",
        "feed.key",
        "remove",
        "--id",
        "OPR-2026-0007",
    ]);
    assert_eq!(code, 0);
    assert!(out.contains("removed OPR-2026-0007"), "{out}");
    assert!(out.contains("sequence 2, 0 advisories"), "{out}");
    let (code, _, err) = rig.run(&[
        "advisories",
        "--feed",
        "advisories.json",
        "--key",
        "feed.key",
        "remove",
        "--id",
        "nope",
    ]);
    assert_ne!(code, 0);
    assert!(err.contains("no advisory nope"), "{err}");
}
