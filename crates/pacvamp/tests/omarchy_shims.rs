//! Exercise the shipped adoption helpers with real CLI dispatch and fixture pacman.
mod common;

use common::Rig;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Stdio};

const CURL: &str = "curl\\t8.16.0-1\\tcore\\thttps://m/curl.pkg.tar.zst\\t42\\n";
const REMOVE: &str = "yay\\t13.0.1-1\\tlocal\\t(null)\\t0\\n";

fn setup() -> Rig {
    let rig = Rig::new();
    std::fs::rename(rig.bin.join("pacman"), rig.bin.join("fake-pacman")).unwrap();
    for (name, script) in [
        (
            "pacvamp",
            "#!/bin/bash\nexec \"$TEST_PACVAMP\" --sysroot \"$TEST_ROOT\" \"$@\"\n",
        ),
        (
            "pacman",
            r#"#!/bin/bash
set -euo pipefail
if [[ ${1:-} == -Qq ]]; then
  for desc in "$TEST_ROOT"/var/lib/pacman/local/*/desc; do
    awk '/^%NAME%$/ { getline; print; exit }' "$desc"
  done
  exit
fi
if [[ ${1:-} == -Q ]]; then
  for desc in "$TEST_ROOT"/var/lib/pacman/local/*/desc; do
    if [[ $(awk '/^%NAME%$/ { getline; print; exit }' "$desc") == "$2" ]]; then exit 0; fi
  done
  exit 1
fi
"$(dirname "$0")/fake-pacman" "$@"
for arg in "$@"; do [[ $arg != --print ]] || exit 0; done
if [[ ${TEST_REGISTER_PACKAGE:-1} == 1 && " $* " == *' -S '* ]]; then
  mkdir -p "$TEST_ROOT/var/lib/pacman/local/curl-8.16.0-1"
  printf '%%NAME%%\ncurl\n\n%%VERSION%%\n8.16.0-1\n\n%%REASON%%\n0\n' > "$TEST_ROOT/var/lib/pacman/local/curl-8.16.0-1/desc"
fi
"#,
        ),
    ] {
        let path = rig.bin.join(name);
        std::fs::write(&path, script).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    rig.write_root(
        "/etc/pacvamp/conf.d/10-omarchy.toml",
        "[packages]\nyay = {}\n",
    );
    std::fs::create_dir_all(rig.user_manifest().parent().unwrap()).unwrap();
    std::fs::write(
        rig.user_manifest(),
        "# user-owned\n[packages]\npacman = {}\n",
    )
    .unwrap();
    rig
}

fn run(
    rig: &Rig,
    helper: &str,
    packages: &[&str],
    plan: &str,
    status: i32,
    register: bool,
) -> (i32, String) {
    let output = Command::new("bash")
        .arg(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../docs/adoption/omarchy")
                .join(helper),
        )
        .args(packages)
        .env("PATH", format!("{}:/usr/bin:/bin", rig.bin.display()))
        .env("TEST_PACVAMP", env!("CARGO_BIN_EXE_pacvamp"))
        .env("TEST_ROOT", &rig.root)
        .env(
            "PACVAMP_AUR_RPC_BASE",
            std::fs::read_to_string(rig.dir.path().join("rpc-url"))
                .unwrap_or_else(|_| "http://127.0.0.1:1".into()),
        )
        .env(
            "PACVAMP_AUR_GIT_BASE",
            format!("file://{}", rig.dir.path().join("aur").display()),
        )
        .env("TEST_REGISTER_PACKAGE", if register { "1" } else { "0" })
        .env("PACVAMP_TEST_PACMAN", rig.bin.join("pacman"))
        .env("HOME", &rig.home)
        .env_remove("XDG_CONFIG_HOME")
        .env_remove("PACVAMP_MANAGED_CONFIG_PATH")
        .env("FAKE_PACMAN_LOG", &rig.log)
        .env("FAKE_PACMAN_PRINT", plan)
        .env("FAKE_PACMAN_STATUS", status.to_string())
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_eq!(
        std::fs::read_to_string(rig.user_manifest()).unwrap(),
        "# user-owned\n[packages]\npacman = {}\n"
    );
    assert_eq!(
        std::fs::read_to_string(rig.root.join("etc/pacvamp/conf.d/10-omarchy.toml")).unwrap(),
        "[packages]\nyay = {}\n"
    );
    (
        output.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

#[test]
fn installer_and_hardware_add_mixed_present_and_missing_packages_without_declarations() {
    let rig = setup();
    let (code, err) = run(&rig, "omarchy-pkg-add", &["pacman", "curl"], CURL, 0, true);
    assert_eq!(code, 0, "{err}");
    assert!(
        rig.log()
            .last()
            .unwrap()
            .contains("-S --noconfirm --needed -- pacman curl")
    );
}

#[test]
fn migrations_drop_exact_installed_names_once_even_when_declared_by_the_distro() {
    let rig = setup();
    let (code, err) = run(
        &rig,
        "omarchy-pkg-drop",
        &["absent", "yay", "yay"],
        REMOVE,
        0,
        true,
    );
    assert_eq!(code, 0, "{err}");
    let log = rig.log();
    assert!(
        log.last().unwrap().contains("-R --noconfirm -s -n -- yay"),
        "{log:?}"
    );
    assert_eq!(run(&rig, "omarchy-pkg-drop", &["absent"], "", 0, true).0, 0);
    assert_eq!(rig.log(), log);
}

#[test]
fn script_failures_and_unregistered_installs_propagate_without_a_prompt() {
    for (status, register) in [(7, true), (0, false)] {
        let rig = setup();
        assert_ne!(
            run(&rig, "omarchy-pkg-add", &["curl"], CURL, status, register).0,
            0
        );
    }
    let rig = setup();
    let (code, err) = run(
        &rig,
        "omarchy-pkg-add",
        &["curl"],
        "curl\\t1\\tchaotic-aur\\thttps://m/curl.pkg.tar.zst\\t1\\n",
        0,
        true,
    );
    assert_ne!(code, 0);
    assert!(err.contains("unattended"), "{err}");
    assert!(rig.log().iter().all(|line| line.contains("--print")));
}

#[test]
fn aur_setup_does_not_rebuild_an_installed_package() {
    let rig = setup();
    assert_eq!(run(&rig, "omarchy-pkg-aur-add", &["yay"], "", 0, true).0, 0);
    assert!(rig.log().is_empty());
}

#[test]
fn unattended_system_update_preserves_declarations_and_stops_on_transaction_failure() {
    for status in [0, 7] {
        let rig = setup();
        let (code, err) = run(
            &rig,
            "omarchy-update-system-pkgs",
            &["--no-refresh"],
            CURL,
            status,
            true,
        );
        assert_eq!(code == 0, status == 0, "{err}");
        assert!(rig.log().last().unwrap().contains("--noconfirm"));
    }
}

#[test]
fn unattended_aur_update_preserves_skipped_package_reports_and_declarations() {
    use common::aur::{EVIL_INSTALL, EVIL_PKGBUILD, EVIL_SRCINFO, FakeAur};
    let rig = setup();
    let aur = FakeAur::new(rig.dir.path());
    aur.create(
        "yay",
        &[
            ("PKGBUILD", EVIL_PKGBUILD),
            (".SRCINFO", EVIL_SRCINFO),
            ("yay.install", EVIL_INSTALL),
        ],
        "2026-01-01T00:00:00Z",
    );
    let rpc = common::http::serve(vec![(
        "/rpc/v5/info",
        include_str!("../fixtures/aur/info.json")
            .replace("\"Version\":\"13.0.1-1\"", "\"Version\":\"13.0.2-1\""),
    )]);
    std::fs::write(rig.dir.path().join("rpc-url"), rpc).unwrap();
    std::fs::remove_file(rig.root.join("var/lib/pacman/sync/omarchy.db")).unwrap();
    let (code, err) = run(&rig, "omarchy-update-aur-pkgs", &[], "", 0, true);
    assert_eq!(code, 0, "{err}");
    assert!(
        err.contains("skipped yay") && err.contains("remains: 13.0.1-1"),
        "{err}"
    );
    assert!(
        rig.log().is_empty(),
        "a denied recipe must never build or install"
    );
}
