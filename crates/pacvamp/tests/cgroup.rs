use pacvamp::{
    build_process::{BuildSpec, Limits},
    cgroup::{Group, controls},
    jail::Spec,
};
use std::{
    path::PathBuf,
    process::{Command, Stdio},
};
#[test]
fn aggregate_control_values_and_invalid_delegation() {
    let limits = Limits {
        memory_mb: 64,
        cpu_percent: 150,
        processes: 128,
        ..Default::default()
    };
    let values = controls(&limits).unwrap();
    assert!(values.contains(&("memory.max", "67108864".into())));
    assert!(values.contains(&("cpu.max", "150000 100000".into())));
    assert!(
        Group::create(
            tempfile::tempdir().unwrap().path(),
            &limits,
            std::path::Path::new(env!("CARGO_BIN_EXE_pacvamp"))
        )
        .is_err()
    );
}
#[test]
fn delegated_group_enforces_memory_and_cleans_descendants() {
    let Some(root) = std::env::var_os("PACVAMP_TEST_CGROUP_ROOT") else {
        return;
    };
    let limits = Limits {
        memory_mb: 128,
        ..Default::default()
    };
    let group = Group::create(
        &PathBuf::from(root),
        &limits,
        std::path::Path::new(env!("CARGO_BIN_EXE_pacvamp")),
    )
    .unwrap();
    let path = group.path.clone();
    let mut child = Command::new(env!("CARGO_BIN_EXE_pacvamp"))
        .arg("__build")
        .stdin(Stdio::piped())
        .spawn()
        .unwrap();
    let spec = BuildSpec { cgroup_path: Some(path.clone()), limits, jail: false,
        spec: Spec { readable: vec![], writable: vec![], network: false, program: "/usr/bin/python3".into(), args: vec!["-c".into(), "import os,time\nfor _ in range(4):\n if os.fork()==0:\n  x=bytearray(50*1024*1024);time.sleep(10);os._exit(0)\ntime.sleep(2)".into()], cwd: std::env::temp_dir() } };
    serde_json::to_writer(child.stdin.take().unwrap(), &spec).unwrap();
    child.wait().unwrap();
    let events = std::fs::read_to_string(path.join("memory.events")).unwrap();
    assert!(
        events.lines().any(|l| l
            .strip_prefix("oom_kill ")
            .is_some_and(|v| v.parse::<u64>().unwrap() > 0)),
        "{events}"
    );
    drop(group);
    assert!(!path.exists());
}

#[test]
fn watcher_cleans_after_supervisor_sigkill() {
    let Some(root) = std::env::var_os("PACVAMP_TEST_CGROUP_ROOT") else {
        return;
    };
    let temp = tempfile::tempdir().unwrap();
    let marker = temp.path().join("group");
    let mut supervisor = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "supervisor_probe", "--ignored"])
        .env("PACVAMP_TEST_CGROUP_ROOT", root)
        .env("PACVAMP_GROUP_MARKER", &marker)
        .spawn()
        .unwrap();
    let start = std::time::Instant::now();
    while !marker.exists() {
        assert!(start.elapsed().as_secs() < 10, "supervisor did not start");
        assert!(
            supervisor.try_wait().unwrap().is_none(),
            "supervisor failed"
        );
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    let path = PathBuf::from(std::fs::read_to_string(marker).unwrap());
    supervisor.kill().unwrap();
    supervisor.wait().unwrap();
    while path.exists() {
        assert!(
            start.elapsed().as_secs() < 15,
            "watcher left cgroup populated"
        );
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
}
#[test]
#[ignore = "subprocess probe for watcher_cleans_after_supervisor_sigkill"]
fn supervisor_probe() {
    let root = PathBuf::from(std::env::var_os("PACVAMP_TEST_CGROUP_ROOT").unwrap());
    let group = Group::create(
        &root,
        &Limits::default(),
        std::path::Path::new(env!("CARGO_BIN_EXE_pacvamp")),
    )
    .unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_pacvamp"))
        .arg("__build")
        .stdin(Stdio::piped())
        .spawn()
        .unwrap();
    let spec = BuildSpec {
        cgroup_path: Some(group.path.clone()),
        limits: Limits::default(),
        jail: false,
        spec: Spec {
            readable: vec![],
            writable: vec![],
            network: false,
            program: "/bin/bash".into(),
            args: vec!["-c".into(), "sleep 60 & wait".into()],
            cwd: std::env::temp_dir(),
        },
    };
    serde_json::to_writer(child.stdin.take().unwrap(), &spec).unwrap();
    // Wait until the helper has joined, making the SIGKILL test meaningful.
    while std::fs::read_to_string(group.path.join("cgroup.procs"))
        .unwrap()
        .trim()
        .is_empty()
    {
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    std::fs::write(
        std::env::var_os("PACVAMP_GROUP_MARKER").unwrap(),
        group.path.to_str().unwrap(),
    )
    .unwrap();
    child.wait().unwrap();
}
