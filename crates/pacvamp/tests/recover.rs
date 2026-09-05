mod common;
use common::Rig;
use pacvamp::ledger::{Entry, Ledger, Patch, Pending, Verification};
use pacvamp::resolve::Tier;
use std::process::Command;

#[test]
fn recovery_keeps_original_evidence_and_never_promotes_uncertain_operations() {
    let rig = Rig::new();
    let mut patch = Patch::default();
    patch.upsert.insert(
        "yay".into(),
        Entry {
            version: "13.0.1-1".into(),
            tier: Tier::Opr,
            repo: Some("omarchy".into()),
            aur_commit: None,
            verification: Some(Verification {
                index_sequence: 7,
                index_key: "accepted-key".into(),
                sha256: "accepted-digest".into(),
                level: pacvamp_policy::Level::L2,
                build_key: None,
            }),
            explicit: true,
            by: "install".into(),
            at: 1,
        },
    );
    let mut ledger = Ledger::default();
    ledger.pending.insert(
        "completed".into(),
        Pending {
            at: 1,
            completed: true,
            patch: Box::new(patch.clone()),
        },
    );
    ledger.pending.insert(
        "uncertain".into(),
        Pending {
            at: 1,
            completed: false,
            patch: Box::new(patch.clone()),
        },
    );
    patch.upsert.get_mut("yay").unwrap().version = "99-1".into();
    ledger.pending.insert(
        "mismatch".into(),
        Pending {
            at: 1,
            completed: true,
            patch: Box::new(patch),
        },
    );
    let path = rig.root.join("var/lib/pacvamp/state.json");
    ledger.save(&path).unwrap();
    let run = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_pacvamp"))
            .env("HOME", &rig.home)
            .env_remove("XDG_CONFIG_HOME")
            .arg("--sysroot")
            .arg(&rig.root)
            .arg("recover")
            .args(args)
            .output()
            .unwrap()
    };
    let preview = run(&["--json"]);
    assert!(preview.status.success());
    assert_eq!(Ledger::load(&path).unwrap(), ledger);
    let result = run(&["--write"]);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let restored = Ledger::load(&path).unwrap();
    assert_eq!(
        restored.packages["yay"]
            .verification
            .as_ref()
            .unwrap()
            .sha256,
        "accepted-digest"
    );
    assert!(restored.packages["yay"].explicit);
    assert!(!restored.pending.contains_key("completed"));
    assert!(restored.pending.contains_key("uncertain"));
    assert!(restored.pending.contains_key("mismatch"));
    assert!(run(&["--write"]).status.success());
    assert_eq!(Ledger::load(&path).unwrap(), restored);
}
