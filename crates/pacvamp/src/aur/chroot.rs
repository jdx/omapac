//! An opt-in immutable Arch build image, provisioned with devtools.
use crate::host::{Host, HostPaths};
use eyre::{Context as _, Result, bail};
use std::path::{Path, PathBuf};
use std::process::Command;

pub fn host(root: &Path) -> Result<Host> {
    if !root.is_absolute() || root == Path::new("/") {
        bail!("aur.chroot_root must be an absolute build image path other than /");
    }
    let canonical = root.canonicalize().wrap_err("opening clean chroot image")?;
    if canonical == Path::new("/") {
        bail!("the host root cannot be used as a clean chroot");
    }
    for path in [
        "usr/bin/makepkg",
        "usr/bin/bash",
        "etc/pacman.conf",
        "var/lib/pacman/local",
    ] {
        if !root.join(path).exists() {
            bail!(
                "incomplete clean chroot: missing {path}; provision aur.chroot_root with mkarchroot and the recipe's build dependencies"
            );
        }
    }
    for part in ["usr", "etc", "var/lib/pacman"] {
        if !root.join(part).canonicalize()?.starts_with(&canonical) {
            bail!("clean chroot {part} escapes the image");
        }
    }
    Host::load(HostPaths {
        config: None,
        sysroot: Some(root.into()),
    })
}

pub fn command(root: &Path, run: &Path, helper: &Path, network: bool) -> Result<Command> {
    host(root)?;
    let bubblewrap = which::which("bwrap")
        .wrap_err("aur.chroot requires bubblewrap; install it before building")?;
    let mut cmd = Command::new(bubblewrap);
    cmd.args([
        "--die-with-parent",
        "--unshare-user",
        "--unshare-pid",
        "--unshare-ipc",
        "--unshare-uts",
        "--disable-userns",
        "--cap-drop",
        "ALL",
    ]);
    if !network {
        cmd.arg("--unshare-net");
    }
    for name in ["usr", "etc"] {
        cmd.arg("--ro-bind")
            .arg(root.join(name))
            .arg(format!("/{name}"));
    }
    cmd.args([
        "--symlink",
        "usr/bin",
        "/bin",
        "--symlink",
        "usr/bin",
        "/sbin",
        "--symlink",
        "usr/lib",
        "/lib",
        "--symlink",
        "usr/lib",
        "/lib64",
        "--dev",
        "/dev",
        "--proc",
        "/proc",
        "--dir",
        "/tmp",
        "--dir",
        "/run",
    ]);
    cmd.arg("--ro-bind")
        .arg(root.join("var/lib/pacman"))
        .arg("/var/lib/pacman");
    cmd.arg("--bind").arg(run).arg(run);
    cmd.arg("--ro-bind").arg(helper).arg("/pacvamp-helper");
    cmd.args(["--", "/pacvamp-helper", "__build"]);
    Ok(cmd)
}

pub fn root(settings: &crate::manifest::Settings) -> Option<PathBuf> {
    settings
        .aur_chroot
        .then(|| settings.aur_chroot_root.clone())
}
