//! `plan`, `apply`, `status`, `add`, and `drop` against layered manifests
//! under the fixture sysroot, with the fake pacman.

mod common;

use common::Rig;

const HELIX_PLAN: &str = "helix\\t26.03-1\\textra\\thttps://m/extra/os/x86_64/helix-26.03-1-x86_64.pkg.tar.zst\\t12000000\\n";
const YAY_REMOVE: &str = "yay\\t13.0.1-1\\tlocal\\tyay-13.0.1-1\\t(null)\\n";

fn declare(rig: &Rig) {
    // Distro layer: pacman and yay present, libreoffice-fresh present.
    rig.write_root(
        "/etc/omapac/conf.d/10-omarchy.toml",
        "[packages]\npacman = {}\nyay = {}\nlibreoffice-fresh = {}\n[update]\noverwrite = [\"/usr/share/omarchy/*\"]\nignore_group = [\"legacy\"]\n",
    );
    // User layer: drop libreoffice, add curl from core, an AUR one.
    std::fs::create_dir_all(rig.user_manifest().parent().unwrap()).unwrap();
    std::fs::write(
        rig.user_manifest(),
        "[packages]\nlibreoffice-fresh = { state = \"absent\" }\ncurl = { repo = \"core\" }\ngoogle-chrome = { source = \"aur\" }\nnot-anywhere = {}\n",
    )
    .unwrap();
}

#[test]
fn plan_shows_the_diff_with_provenance() {
    let rig = Rig::new();
    declare(&rig);
    let (code, out, err) = rig.run(&["plan"], "", 0);
    assert_eq!(code, 0, "{err}");
    insta::assert_snapshot!(rig.redact(&out));
    assert!(rig.log().is_empty(), "plan never runs pacman");

    let (code, detailed, _) = rig.run(&["plan", "--detailed-exitcode"], "", 0);
    assert_eq!(code, 2);
    assert_eq!(detailed, out);

    let (_, out, _) = rig.run(&["plan", "--json"], "", 0);
    let diff: serde_json::Value = serde_json::from_str(&out).unwrap();
    let steps = diff["steps"].as_array().unwrap();
    assert_eq!(steps.len(), 6);
    assert_eq!(steps[3]["action"], "install");
    assert_eq!(steps[3]["repo"], "core");
    assert_eq!(steps[4]["action"], "needs-aur");
    assert_eq!(steps[5]["action"], "unavailable");
}

#[test]
fn status_lists_layers() {
    let rig = Rig::new();
    declare(&rig);
    rig.write_root("/etc/omapac/managed.toml", "[policy]\naur.jail = true\n");
    let (code, out, _) = rig.run(&["status"], "", 0);
    assert_eq!(code, 0);
    assert!(out.contains("layers: "), "{out}");
    assert!(out.contains("10-omarchy.toml, "), "{out}");
    assert!(out.contains("managed: "), "{out}");
    let (_, out, _) = rig.run(&["status", "--missing"], "", 0);
    assert!(!out.contains("installed 7.1.0-2"), "{out}");
    assert!(
        !out.contains("libreoffice-fresh"),
        "absent and not installed is a match: {out}"
    );
    assert!(out.contains("not-anywhere"), "{out}");
}

#[test]
fn apply_refuses_unavailable_then_installs_and_removes() {
    let rig = Rig::new();
    declare(&rig);
    let (code, _, err) = rig.run(&["apply", "-y"], HELIX_PLAN, 0);
    assert_ne!(code, 0);
    assert!(
        err.contains("declared but in no repository: not-anywhere"),
        "{err}"
    );
    assert!(rig.log().is_empty());

    // Drop the impossible one; libreoffice is not installed in the fixture,
    // so the only change is the curl install.
    let (_, _, _) = rig.run(&["drop", "not-anywhere"], "", 0);
    let (code, out, err) = rig.run(&["apply", "-y"], HELIX_PLAN, 0);
    assert_eq!(code, 0, "{err}");
    assert!(out.contains("+ curl"), "{out}");
    assert!(
        err.contains("skipped AUR package(s) google-chrome"),
        "{err}"
    );
    let log = rig.log();
    assert!(log[0].contains("-S --noconfirm --print"), "{log:?}");
    assert!(
        log[0].contains("--ignoregroup legacy --overwrite /usr/share/omarchy/* -- core/curl"),
        "the distro layer's ignore-group and overwrite rules apply: {log:?}"
    );
    assert!(log.last().unwrap().ends_with("-- core/curl"), "{log:?}");
}

#[test]
fn apply_and_add_refuse_a_lone_unavailable_package() {
    let rig = Rig::new();
    std::fs::create_dir_all(rig.user_manifest().parent().unwrap()).unwrap();
    std::fs::write(rig.user_manifest(), "[packages]\nnot-anywhere = {}\n").unwrap();

    let (code, _, err) = rig.run(&["apply", "-y"], "", 0);
    assert_ne!(code, 0);
    assert!(
        err.contains("declared but in no repository: not-anywhere"),
        "{err}"
    );

    let rig = Rig::new();
    let (code, _, err) = rig.run(&["add", "-y", "not-anywhere"], "", 0);
    assert_ne!(code, 0);
    assert!(
        err.contains("declared but in no repository: not-anywhere"),
        "{err}"
    );
}

#[test]
fn hold_does_not_skip_an_initial_install() {
    let rig = Rig::new();
    let (code, _, err) = rig.run(&["add", "-y", "--hold", "curl"], HELIX_PLAN, 0);
    assert_eq!(code, 0, "{err}");
    assert!(
        !rig.log().last().unwrap().contains("--ignore curl"),
        "{:?}",
        rig.log()
    );
}

#[test]
fn add_writes_the_user_manifest_and_converges_only_those() {
    let rig = Rig::new();
    let (code, out, err) = rig.run(&["add", "-y", "core/pacman", "curl"], HELIX_PLAN, 0);
    assert_eq!(code, 0, "{err}");
    let manifest = std::fs::read_to_string(rig.user_manifest()).unwrap();
    assert_eq!(
        manifest,
        "[packages]\npacman = { repo = \"core\" }\ncurl = {}\n"
    );
    assert!(out.contains("declared pacman"), "{out}");
    let log = rig.log();
    assert!(
        log.last().unwrap().ends_with("-- curl"),
        "pacman is installed already: {log:?}"
    );

    let (code, out, _) = rig.run(&["add", "-n", "--absent", "yay"], YAY_REMOVE, 0);
    assert_eq!(code, 0);
    assert!(out.contains("- yay"), "{out}");
    assert!(out.contains("would run:"), "{out}");
    let manifest = std::fs::read_to_string(rig.user_manifest()).unwrap();
    assert!(
        manifest.contains("yay = { state = \"absent\" }"),
        "{manifest}"
    );

    let (code, _, err) = rig.run(&["add", "--aur", "extra/thing"], "", 0);
    assert_ne!(code, 0);
    assert!(err.contains("repo/name does not apply with --aur"), "{err}");
}

#[test]
fn drop_keeps_what_a_lower_layer_declares() {
    let rig = Rig::new();
    rig.write_root(
        "/etc/omapac/conf.d/10-omarchy.toml",
        "[packages]\nyay = {}\n",
    );
    std::fs::create_dir_all(rig.user_manifest().parent().unwrap()).unwrap();
    std::fs::write(
        rig.user_manifest(),
        "[packages]\nyay = { hold = true }\nglibc = {}\n",
    )
    .unwrap();
    let (code, out, err) = rig.run(
        &["drop", "-n", "yay", "core/glibc", "never-there", "glibc"],
        YAY_REMOVE,
        0,
    );
    assert_eq!(code, 0, "{err}");
    assert!(out.contains("removed yay from"), "{out}");
    assert!(out.contains("never-there was not declared"), "{out}");
    // yay stays because the distro layer declares it; glibc goes.
    let log = rig.log();
    assert!(
        log[0].ends_with("-R --noconfirm --print --print-format %n\t%v\t%r\t%l\t%s -- glibc"),
        "{log:?}"
    );
    assert!(
        out.contains("would run:") && !out.contains("would run: /usr/bin/pacman -R --noconfirm"),
        "{out}"
    );
    let manifest = std::fs::read_to_string(rig.user_manifest()).unwrap();
    assert!(
        !manifest.contains("yay") && !manifest.contains("glibc"),
        "{manifest}"
    );
}

#[test]
fn missing_status_distinguishes_a_matching_manifest() {
    let rig = Rig::new();
    std::fs::create_dir_all(rig.user_manifest().parent().unwrap()).unwrap();
    std::fs::write(rig.user_manifest(), "[packages]\npacman = {}\n").unwrap();
    let (code, out, err) = rig.run(&["status", "--missing"], "", 0);
    assert_eq!(code, 0, "{err}");
    assert!(out.contains("nothing missing"), "{out}");
    assert!(!out.contains("nothing declared"), "{out}");
}
