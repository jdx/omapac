//! The `__jail` helper against the real kernel: filesystem writes are
//! confined and inet sockets are refused. Skips when Landlock is not
//! available, which CI's kernels do provide.

use std::io::Write as _;
use std::path::Path;
use std::process::{Command, Stdio};

mod common;

fn jail(spec: &serde_json::Value) -> (i32, String) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_pacvamp"))
        .arg("__jail")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(spec.to_string().as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    (
        output.status.code().unwrap_or(-1),
        format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ),
    )
}

fn spec(writable: &[&Path], network: bool, script: &str, cwd: &Path) -> serde_json::Value {
    serde_json::json!({
        "writable": writable,
        "network": network,
        "program": "/bin/bash",
        "args": ["-c", script],
        "cwd": cwd,
    })
}

fn landlock_available() -> bool {
    let dir = tempfile::tempdir().unwrap();
    let (code, out) = jail(&spec(&[dir.path()], true, "true", dir.path()));
    if code != 0 && out.contains("this kernel cannot enforce") {
        eprintln!("skipping: {out}");
        return false;
    }
    assert_eq!(code, 0, "jail rules are invalid: {out}");
    true
}

#[test]
fn writes_are_confined_to_the_allowed_directories() {
    if !landlock_available() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let allowed = dir.path().join("build");
    let forbidden = dir.path().join("elsewhere");
    std::fs::create_dir_all(&allowed).unwrap();
    std::fs::create_dir_all(&forbidden).unwrap();

    let (code, out) = jail(&spec(&[&allowed], true, "echo ok > out.txt", &allowed));
    assert_eq!(code, 0, "{out}");
    assert_eq!(
        std::fs::read_to_string(allowed.join("out.txt")).unwrap(),
        "ok\n"
    );

    let script = format!("echo no > {}/out.txt", forbidden.display());
    let (code, _) = jail(&spec(&[&allowed], true, &script, &allowed));
    assert_ne!(code, 0, "writing outside the jail must fail");
    assert!(!forbidden.join("out.txt").exists());

    // System compiler/runtime paths remain readable.
    let (code, out) = jail(&spec(
        &[&allowed],
        true,
        "cat /etc/passwd >/dev/null && : >/dev/null",
        &allowed,
    ));
    assert_eq!(code, 0, "{out}");
}

#[test]
fn network_is_refused_unless_granted() {
    if !landlock_available() {
        return;
    }
    let base = common::http::serve(vec![("/", "{}".to_string())]);
    let port = base.rsplit(':').next().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let script = format!("exec 3<>/dev/tcp/127.0.0.1/{port}");
    let (code, out) = jail(&spec(&[dir.path()], false, &script, dir.path()));
    assert_ne!(
        code, 0,
        "a TCP connect must fail with network denied: {out}"
    );
    let (code, out) = jail(&spec(&[dir.path()], true, &script, dir.path()));
    assert_eq!(code, 0, "granted network works: {out}");
}

#[test]
fn credentials_and_shared_scratch_are_inaccessible_even_with_network() {
    if !landlock_available() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let build = dir.path().join("build");
    let secret = dir.path().join("credentials");
    std::fs::create_dir(&build).unwrap();
    std::fs::write(&secret, "fake credential").unwrap();
    std::os::unix::fs::symlink(&secret, build.join("link")).unwrap();
    for network in [false, true] {
        for path in [&secret, &build.join("link")] {
            let (code, out) = jail(&spec(
                &[&build],
                network,
                &format!("cat '{}'", path.display()),
                &build,
            ));
            assert_ne!(code, 0, "credential read succeeded: {out}");
            assert!(!out.contains("fake credential"));
        }
        let target = dir.path().join("another-build");
        let (code, out) = jail(&spec(
            &[&build],
            network,
            &format!("echo poisoned > '{}'", target.display()),
            &build,
        ));
        assert_ne!(code, 0, "shared scratch write succeeded: {out}");
        assert!(!target.exists());
    }
}

#[test]
fn declared_sources_are_readable_but_not_writable() {
    if !landlock_available() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let build = dir.path().join("build");
    let source = dir.path().join("source");
    std::fs::create_dir(&build).unwrap();
    std::fs::write(&source, "verified source").unwrap();
    let mut request = spec(
        &[&build],
        false,
        &format!(
            "cat '{}' && ! echo poisoned > '{}'",
            source.display(),
            source.display()
        ),
        &build,
    );
    request["readable"] = serde_json::json!([source]);
    let (code, out) = jail(&request);
    assert_eq!(code, 0, "{out}");
    assert!(out.contains("verified source"));
    assert_eq!(std::fs::read_to_string(source).unwrap(), "verified source");
}

#[test]
fn the_helper_is_hidden_and_validates_its_spec() {
    let help = Command::new(env!("CARGO_BIN_EXE_pacvamp"))
        .arg("--help")
        .output()
        .unwrap();
    assert!(!String::from_utf8_lossy(&help.stdout).contains("__jail"));
    let (code, out) = jail(&serde_json::json!({"nonsense": true}));
    assert_ne!(code, 0);
    assert!(out.contains("parsing the jail spec"), "{out}");
}
