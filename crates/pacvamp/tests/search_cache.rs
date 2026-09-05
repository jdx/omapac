mod common;
use common::Rig;

fn search(rig: &Rig) -> String {
    let (code, out, err) = rig.run(&["search", "--json", "pacman"], "", 0);
    assert_eq!(code, 0, "{err}");
    out
}

fn caches(rig: &Rig) -> Vec<std::path::PathBuf> {
    std::fs::read_dir(rig.home.join(".cache/pacvamp/search-v1"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect()
}

#[test]
fn reuse_corruption_and_schema_fallback_preserve_results() {
    let rig = Rig::new();
    let first = search(&rig);
    let files = caches(&rig);
    assert_eq!(files.len(), 2);
    let timestamps: Vec<_> = files
        .iter()
        .map(|p| p.metadata().unwrap().modified().unwrap())
        .collect();
    assert_eq!(search(&rig), first);
    assert_eq!(
        files
            .iter()
            .map(|p| p.metadata().unwrap().modified().unwrap())
            .collect::<Vec<_>>(),
        timestamps
    );
    for path in &files {
        std::fs::write(path, "truncated").unwrap();
    }
    assert_eq!(search(&rig), first);
    for path in &files {
        let mut json: serde_json::Value =
            serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        json["schema"] = 0.into();
        json["packages"] = serde_json::json!([]);
        std::fs::write(path, serde_json::to_vec(&json).unwrap()).unwrap();
    }
    assert_eq!(search(&rig), first);
}

#[test]
fn replacing_database_with_preserved_mtime_invalidates_and_removal_drops_results() {
    let rig = Rig::new();
    let original = search(&rig);
    assert!(original.contains("pacman"));
    let db = rig.root.join("var/lib/pacman/sync/core.db");
    let modified = db.metadata().unwrap().modified().unwrap();
    let replacement = db.with_extension("new");
    std::fs::copy(common::fixtures().join("sync/omarchy.db"), &replacement).unwrap();
    std::fs::File::options()
        .write(true)
        .open(&replacement)
        .unwrap()
        .set_modified(modified)
        .unwrap();
    std::fs::rename(replacement, &db).unwrap();
    assert!(!search(&rig).contains("pacman"));
    std::fs::copy(common::fixtures().join("sync/core.db"), &db).unwrap();
    assert_eq!(search(&rig), original);
    std::fs::remove_file(db).unwrap();
    assert!(!search(&rig).contains("pacman"));
}

#[test]
fn unavailable_cache_and_concurrent_writers_do_not_break_search() {
    let rig = Rig::new();
    std::fs::write(rig.home.join(".cache"), "not a directory").unwrap();
    let expected = search(&rig);
    std::fs::remove_file(rig.home.join(".cache")).unwrap();
    std::thread::scope(|scope| {
        let workers: Vec<_> = (0..4).map(|_| scope.spawn(|| search(&rig))).collect();
        for worker in workers {
            assert_eq!(worker.join().unwrap(), expected);
        }
    });
    assert_eq!(search(&rig), expected);
}

#[test]
fn same_size_atomic_replacement_and_live_installed_versions_are_detected() {
    let rig = Rig::new();
    let original = search(&rig);
    let db = rig.root.join("var/lib/pacman/sync/core.db");
    let modified = db.metadata().unwrap().modified().unwrap();
    for path in caches(&rig) {
        let mut json: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        if json["packages"]
            .as_array()
            .unwrap()
            .iter()
            .any(|p| p["name"] == "pacman")
        {
            json["packages"] = serde_json::json!([]);
        }
        std::fs::write(path, serde_json::to_vec(&json).unwrap()).unwrap();
    }
    let replacement = db.with_extension("new");
    std::fs::copy(&db, &replacement).unwrap();
    std::fs::File::options()
        .write(true)
        .open(&replacement)
        .unwrap()
        .set_modified(modified)
        .unwrap();
    std::fs::rename(replacement, db).unwrap();
    assert_eq!(
        search(&rig),
        original,
        "new inode must invalidate even with identical size and mtime"
    );
    let desc = rig.root.join("var/lib/pacman/local/pacman-7.1.0-2/desc");
    let text = std::fs::read_to_string(&desc)
        .unwrap()
        .replace("7.1.0-2", "9.0-1");
    std::fs::write(desc, text).unwrap();
    let hits: serde_json::Value = serde_json::from_str(&search(&rig)).unwrap();
    assert_eq!(hits[0]["installed"], "9.0-1");
}
