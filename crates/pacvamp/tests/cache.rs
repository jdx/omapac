use pacvamp::aur::cache::{inventory, lease};
use std::{
    collections::BTreeSet,
    fs,
    time::{Duration, SystemTime},
};
#[test]
fn retention_protects_active_recent_and_referenced_runs() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join(".pacvamp-build/runs");
    for name in ["old", "installed", "recent"] {
        let run = root.join(name);
        fs::create_dir_all(&run).unwrap();
        fs::write(run.join("receipt.json"), b"receipt").unwrap();
        if name != "recent" {
            fs::File::open(&run)
                .unwrap()
                .set_modified(SystemTime::now() - Duration::from_secs(86400 * 40))
                .unwrap();
        }
    }
    let active = lease(dir.path(), false).unwrap();
    assert!(lease(dir.path(), true).is_err());
    assert!(lease(dir.path(), false).is_ok());
    drop(active);
    let _prune = lease(dir.path(), true).unwrap();
    let protected = BTreeSet::from([root.join("installed/receipt.json").canonicalize().unwrap()]);
    let runs = inventory(dir.path(), &protected, 30, Some(0)).unwrap();
    assert_eq!(
        runs.iter()
            .filter(|r| r.prune)
            .map(|r| r.path.file_name().unwrap().to_str().unwrap())
            .collect::<Vec<_>>(),
        ["old"]
    );
}

#[test]
fn live_estimates_tolerate_directory_removal() {
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };
    let dir = tempfile::tempdir().unwrap();
    let run = dir.path().join(".pacvamp-build/runs/live");
    fs::create_dir_all(&run).unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let done = stop.clone();
    let writer = std::thread::spawn(move || {
        while !done.load(Ordering::Relaxed) {
            fs::create_dir_all(run.join("builddir/subdir")).unwrap();
            fs::write(run.join("builddir/subdir/file"), b"building").unwrap();
            fs::remove_dir_all(run.join("builddir")).unwrap();
        }
    });
    let results = (0..500)
        .map(|_| inventory(dir.path(), &BTreeSet::new(), 30, None))
        .collect::<Vec<_>>();
    stop.store(true, Ordering::Relaxed);
    writer.join().unwrap();
    for result in results {
        result.unwrap();
    }
}
