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
