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

pub fn command(
    root: &Path,
    run: &Path,
    helper: &Path,
    network: bool,
    cgroup: Option<&Path>,
) -> Result<Command> {
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
    for entry in std::fs::read_dir(root)? {
        let entry = entry?;
        let name = entry.file_name();
        if [
            "dev",
            "proc",
            "sys",
            "run",
            "tmp",
            "build",
            "pacvamp-helper",
            "pacvamp-cgroup",
        ]
        .iter()
        .any(|reserved| name == *reserved)
        {
            continue;
        }
        let destination = Path::new("/").join(&name);
        if entry.file_type()?.is_symlink() {
            cmd.arg("--symlink")
                .arg(std::fs::read_link(entry.path())?)
                .arg(destination);
        } else {
            cmd.arg("--ro-bind").arg(entry.path()).arg(destination);
        }
    }
    cmd.args([
        "--dev", "/dev", "--proc", "/proc", "--dir", "/sys", "--dir", "/tmp", "--dir", "/run",
    ]);
    if network {
        cmd.arg("--ro-bind")
            .arg("/etc/resolv.conf")
            .arg(resolver_destination(root)?);
    }
    if let Some(group) = cgroup {
        cmd.arg("--bind").arg(group).arg("/pacvamp-cgroup");
    }
    cmd.arg("--bind").arg(run).arg("/build");
    cmd.arg("--ro-bind").arg(helper).arg("/pacvamp-helper");
    cmd.args(["--chdir", "/build", "--", "/pacvamp-helper", "__build"]);
    Ok(cmd)
}

pub fn root(settings: &crate::manifest::Settings) -> Option<PathBuf> {
    settings
        .aur_chroot
        .then(|| settings.aur_chroot_root.clone())
}

pub fn inside(path: &Path, run: &Path) -> PathBuf {
    path.strip_prefix(run).map_or_else(
        |_| path.to_path_buf(),
        |relative| Path::new("/build").join(relative),
    )
}

// Resolve image symlinks lexically inside the future namespace, never against
// the host's /run. The destination can be absent in a fresh runtime mount.
fn resolver_destination(root: &Path) -> Result<PathBuf> {
    use std::path::Component;
    let mut destination = PathBuf::from("/etc/resolv.conf");
    for _ in 0..16 {
        let path = root.join(destination.strip_prefix("/")?);
        let target = match std::fs::read_link(path) {
            Ok(target) => target,
            Err(err)
                if matches!(
                    err.kind(),
                    std::io::ErrorKind::NotFound | std::io::ErrorKind::InvalidInput
                ) =>
            {
                return Ok(destination);
            }
            Err(err) => return Err(err).wrap_err("reading image resolver link"),
        };
        let path = if target.is_absolute() {
            target
        } else {
            destination.parent().unwrap_or(Path::new("/")).join(target)
        };
        let mut normalized = PathBuf::from("/");
        for component in path.components() {
            match component {
                Component::Normal(name) => normalized.push(name),
                Component::ParentDir => {
                    normalized.pop();
                }
                _ => {}
            }
        }
        destination = normalized;
    }
    bail!("image resolver symlink chain is too deep")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn resolver_links_stay_inside_the_namespace() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("etc")).unwrap();
        let link = dir.path().join("etc/resolv.conf");
        std::os::unix::fs::symlink("../run/systemd/resolve/stub-resolv.conf", &link).unwrap();
        assert_eq!(
            resolver_destination(dir.path()).unwrap(),
            Path::new("/run/systemd/resolve/stub-resolv.conf")
        );
        std::fs::remove_file(&link).unwrap();
        std::os::unix::fs::symlink("/run/resolv.conf", &link).unwrap();
        assert_eq!(
            resolver_destination(dir.path()).unwrap(),
            Path::new("/run/resolv.conf")
        );
    }
}
