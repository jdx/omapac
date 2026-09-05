use pacvamp::{
    build_process::{BuildSpec, Limits, ManagedChild},
    jail::Spec,
};
use std::{
    os::unix::process::CommandExt as _,
    path::Path,
    process::{Command, Stdio},
};

fn spawn(dir: &Path, script: &str, limits: Limits) -> ManagedChild {
    let mut child = Command::new(env!("CARGO_BIN_EXE_pacvamp"))
        .arg("__build")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .process_group(0)
        .spawn()
        .unwrap();
    let spec = BuildSpec {
        cgroup_path: None,
        limits,
        jail: false,
        spec: Spec {
            readable: vec![],
            writable: vec![dir.to_path_buf()],
            network: false,
            program: "/bin/bash".into(),
            args: vec!["-c".into(), script.into()],
            cwd: dir.to_path_buf(),
        },
    };
    serde_json::to_writer(child.stdin.take().unwrap(), &spec).unwrap();
    ManagedChild::new(child).unwrap()
}

#[test]
fn timeout_kills_background_descendants_and_prevents_group_escape() {
    let dir = tempfile::tempdir().unwrap();
    let limits = Limits {
        wall_seconds: 1,
        ..Default::default()
    };
    let mut child = spawn(
        dir.path(),
        "(sleep 2; touch escaped) & setsid sh -c 'sleep 2; touch escaped-session'; wait",
        limits.clone(),
    );
    assert!(
        child
            .wait(&limits, dir.path())
            .unwrap_err()
            .to_string()
            .contains("wall-clock")
    );
    drop(child);
    std::thread::sleep(std::time::Duration::from_secs(2));
    assert!(!dir.path().join("escaped").exists());
    assert!(!dir.path().join("escaped-session").exists());
}

#[test]
fn file_limit_is_kernel_enforced_and_disk_budget_stops_small_file_growth() {
    let dir = tempfile::tempdir().unwrap();
    let limits = Limits {
        file_mb: 1,
        ..Default::default()
    };
    let mut child = spawn(
        dir.path(),
        "dd if=/dev/zero of=large bs=1M count=2",
        limits.clone(),
    );
    assert!(!child.wait(&limits, dir.path()).unwrap().success());
    drop(child);
    assert!(std::fs::metadata(dir.path().join("large")).unwrap().len() <= 1024 * 1024);

    let limits = Limits {
        disk_mb: 1,
        ..Default::default()
    };
    let mut child = spawn(
        dir.path(),
        "dd if=/dev/zero of=small bs=1M count=1; sleep 10",
        limits.clone(),
    );
    assert!(
        child
            .wait(&limits, dir.path())
            .unwrap_err()
            .to_string()
            .contains("disk budget")
    );
}

#[test]
fn managed_limits_can_only_tighten_user_limits() {
    let mut limits = Limits {
        wall_seconds: 20,
        ..Default::default()
    };
    limits.merge(
        &pacvamp::build_process::LimitsToml {
            wall_seconds: Some(40),
            ..Default::default()
        },
        true,
    );
    assert_eq!(limits.wall_seconds, 20);
    limits.merge(
        &pacvamp::build_process::LimitsToml {
            wall_seconds: Some(5),
            ..Default::default()
        },
        true,
    );
    assert_eq!(limits.wall_seconds, 5);
}

#[test]
fn fast_exit_cannot_skip_the_disk_budget() {
    let dir = tempfile::tempdir().unwrap();
    let limits = Limits {
        disk_mb: 1,
        file_mb: 1,
        ..Default::default()
    };
    let mut child = spawn(
        dir.path(),
        "dd if=/dev/zero of=a bs=768K count=1; dd if=/dev/zero of=b bs=768K count=1",
        limits.clone(),
    );
    assert!(
        child
            .wait(&limits, dir.path())
            .unwrap_err()
            .to_string()
            .contains("disk budget")
    );
}

#[test]
fn lower_inherited_limits_are_preserved_without_privilege() {
    let dir = tempfile::tempdir().unwrap();
    let limits = Limits::default();
    let mut child = Command::new("prlimit")
        .args(["--nproc=128:128", "--"])
        .arg(env!("CARGO_BIN_EXE_pacvamp"))
        .arg("__build")
        .stdin(Stdio::piped())
        .process_group(0)
        .spawn()
        .unwrap();
    let spec = BuildSpec {
        cgroup_path: None,
        limits: limits.clone(),
        jail: false,
        spec: Spec {
            readable: vec![],
            writable: vec![],
            network: false,
            program: "/bin/bash".into(),
            args: vec!["-c".into(), "ulimit -u > inherited-limit".into()],
            cwd: dir.path().into(),
        },
    };
    serde_json::to_writer(child.stdin.take().unwrap(), &spec).unwrap();
    assert!(
        ManagedChild::new(child)
            .unwrap()
            .wait(&limits, dir.path())
            .unwrap()
            .success()
    );
    assert!(
        std::fs::read_to_string(dir.path().join("inherited-limit"))
            .unwrap()
            .trim()
            .parse::<u64>()
            .unwrap()
            <= 128
    );
}

#[test]
fn signals_cancel_active_builds_and_terminate_after_supervision() {
    use std::os::unix::process::ExitStatusExt as _;
    for signal in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP] {
        for phase in ["active", "after"] {
            let status = Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "signal_lifecycle_probe", "--ignored"])
                .env("PACVAMP_TEST_SIGNAL", signal.to_string())
                .env("PACVAMP_TEST_SIGNAL_PHASE", phase)
                .process_group(0)
                .status()
                .unwrap();
            if phase == "active" {
                assert!(status.success(), "active cancellation failed for {signal}");
            } else {
                assert_eq!(status.signal(), Some(signal), "signal ignored after build");
            }
        }
    }
}

#[test]
#[ignore = "subprocess probe invoked by signals_cancel_active_builds_and_terminate_after_supervision"]
fn signal_lifecycle_probe() {
    use nix::{
        sys::signal::{Signal, kill},
        unistd::getpid,
    };
    let signal = Signal::try_from(
        std::env::var("PACVAMP_TEST_SIGNAL")
            .unwrap()
            .parse::<i32>()
            .unwrap(),
    )
    .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let limits = Limits::default();
    // Repeated scopes must re-enable cancellation without losing default actions.
    for _ in 0..2 {
        let mut child = spawn(dir.path(), "true", limits.clone());
        assert!(child.wait(&limits, dir.path()).unwrap().success());
    }
    if std::env::var("PACVAMP_TEST_SIGNAL_PHASE").unwrap() == "active" {
        let other = spawn(dir.path(), "sleep 30", limits.clone());
        let mut child = spawn(dir.path(), "sleep 30", limits.clone());
        drop(other);
        kill(getpid(), signal).unwrap();
        assert!(
            child
                .wait(&limits, dir.path())
                .unwrap_err()
                .to_string()
                .contains("cancelled")
        );
    } else {
        kill(getpid(), signal).unwrap();
        panic!("termination signal was ignored after supervision");
    }
}

#[test]
fn preallocated_storage_counts_even_when_logical_length_is_zero() {
    use std::os::unix::fs::MetadataExt as _;
    let dir = tempfile::tempdir().unwrap();
    let limits = Limits {
        disk_mb: 1,
        file_mb: 4,
        ..Default::default()
    };
    let mut child = spawn(
        dir.path(),
        "touch reserved && fallocate --keep-size --length 2M reserved",
        limits.clone(),
    );
    let err = child.wait(&limits, dir.path()).unwrap_err();
    assert!(err.to_string().contains("disk budget"), "{err:#}");
    let metadata = std::fs::metadata(dir.path().join("reserved")).unwrap();
    assert_eq!(metadata.len(), 0);
    assert!(metadata.blocks() * 512 > 1024 * 1024);
}
