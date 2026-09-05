//! Building an approved AUR commit with makepkg, in two phases so the jail
//! can differ: sources are fetched with network, then the build runs with
//! writes limited to the build directory and, unless granted, no network.
//! See `PLAN.md`, "Jailed builds".

use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::{fs, os::unix::fs::PermissionsExt as _};

use alpm_db::Dependency;
use eyre::{Context as _, Result, bail};

use super::review::Reviewed;
use crate::host::Host;
use crate::jail::Spec;
use crate::manifest::Settings;

/// How to build.
#[derive(Debug, Clone)]
pub struct BuildOpts {
    pub cgroup_root: Option<PathBuf>,
    pub cache_lease: std::sync::Arc<nix::fcntl::Flock<std::fs::File>>,
    /// Apply the Landlock and seccomp jail to the build phase.
    pub jail: bool,
    pub chroot: Option<PathBuf>,
    pub limits: crate::build_process::Limits,
    pub dependencies: std::collections::BTreeMap<String, String>,
    /// Allow network during the build phase.
    pub network: bool,
    /// Where built packages go.
    pub pkgdest: PathBuf,
    pub srcdest: PathBuf,
    pub builddir: PathBuf,
    pub logdest: PathBuf,
    /// The makepkg binary.
    pub makepkg: PathBuf,
}

impl BuildOpts {
    /// Options from settings for one pkgbase.
    pub fn from_settings(
        settings: &Settings,
        pkgbase: &str,
        cache_dir: &Path,
        host: &Host,
    ) -> Result<BuildOpts> {
        let cache_lease = std::sync::Arc::new(super::cache::lease(cache_dir, false)?);
        settings.aur_limits.validate()?;
        let chroot = super::chroot::root(settings);
        let image_host = chroot.as_deref().map(super::chroot::host).transpose()?;
        let host = image_host.as_ref().unwrap_or(host);
        let makepkg = if chroot.is_some() {
            PathBuf::from("/usr/bin/makepkg")
        } else {
            which::which("makepkg")
                .map_err(|_| eyre::eyre!("makepkg is not on PATH; install base-devel"))?
        };
        let artifacts = cache_dir.join(".pacvamp-build");
        let runs = artifacts.join("runs");
        fs::create_dir_all(&runs)?;
        let run = tempfile::Builder::new()
            .prefix(&format!("{pkgbase}-"))
            .tempdir_in(runs)?
            .keep();
        if settings.aur_cgroup_root.is_some() && !settings.aur_jail {
            bail!("cgroup builds require the filesystem jail");
        }
        Ok(BuildOpts {
            cgroup_root: settings.aur_cgroup_root.clone(),
            cache_lease,
            jail: settings.aur_jail,
            chroot,
            limits: settings.aur_limits.clone(),
            dependencies: host
                .installed()?
                .iter()
                .map(|p| (p.name.clone(), p.version.clone()))
                .collect(),
            network: settings
                .aur_allow_network_build
                .iter()
                .any(|p| p == pkgbase),
            pkgdest: run.join("pkgs"),
            srcdest: run.join("sources"),
            builddir: run.join("build"),
            logdest: run.join("logs"),
            makepkg,
        })
    }
}

/// Dependencies the build needs that the machine lacks, split by where
/// they can come from.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct MissingDeps {
    /// Satisfiable from a sync database, as `repo/name` targets.
    pub repo: Vec<crate::engine::Target>,
    /// Not in any sync database; presumably AUR.
    pub other: Vec<alpm_db::dep::Dependency>,
}

/// Work out which of the recipe's dependencies are missing.
pub fn missing_deps(host: &Host, reviewed: &Reviewed, arch: &str) -> Result<MissingDeps> {
    let mut deps: Vec<Dependency> = reviewed.srcinfo.makedepends(arch);
    deps.extend(reviewed.srcinfo.checkdepends(arch));
    for pkgname in reviewed.srcinfo.pkgnames() {
        deps.extend(reviewed.srcinfo.depends(pkgname, arch));
    }
    let mut missing = MissingDeps::default();
    for dep in deps {
        let version = reviewed.srcinfo.version();
        let sibling_satisfies = reviewed.srcinfo.pkgnames().iter().any(|pkgname| {
            let provides = reviewed.srcinfo.provides(pkgname, arch);
            dep.satisfied_by(pkgname, &version, &provides)
        });
        if sibling_satisfies {
            continue;
        }
        if host.is_satisfied(&dep)? {
            continue;
        }
        match host.sync_providers(&dep)?.first() {
            Some((source, package)) => {
                let target = crate::engine::Target {
                    repo: Some(source.name.clone()),
                    name: package.name.clone(),
                };
                if !missing.repo.contains(&target) {
                    missing.repo.push(target);
                }
            }
            None => missing.other.push(dep),
        }
    }
    Ok(missing)
}

/// Build `reviewed` at its target commit. Returns the package files.
pub fn build(reviewed: &Reviewed, opts: &BuildOpts) -> Result<Vec<PathBuf>> {
    build_with_options(reviewed, opts, false)
}

/// Bootstrap a reviewed split pkgbase whose sibling closes a dependency
/// cycle. `--nodeps` skips makepkg's preflight only; the normal build is run
/// again after the dependency chain has been installed.
pub fn build_without_dependency_checks(
    reviewed: &Reviewed,
    opts: &BuildOpts,
) -> Result<Vec<PathBuf>> {
    build_with_options(reviewed, opts, true)
}

fn build_with_options(
    reviewed: &Reviewed,
    opts: &BuildOpts,
    without_dependency_checks: bool,
) -> Result<Vec<PathBuf>> {
    let checkout = &reviewed.checkout;
    let cache = checkout
        .dir
        .parent()
        .ok_or_else(|| eyre::eyre!("checkout has no parent"))?;
    let _lock = super::locking::acquire(cache, &reviewed.pkgbase)?;
    if opts.pkgdest.exists() {
        std::fs::remove_dir_all(&opts.pkgdest).wrap_err("clearing stale package outputs")?;
    }
    std::fs::create_dir_all(&opts.pkgdest)
        .wrap_err_with(|| format!("creating {}", opts.pkgdest.display()))?;
    let verifydir = path_with_suffix(&opts.builddir, ".verify");
    for dir in [&verifydir, &opts.builddir] {
        if dir.exists() {
            std::fs::remove_dir_all(dir).wrap_err_with(|| format!("clearing {}", dir.display()))?;
        }
    }
    for dir in [&opts.srcdest, &opts.builddir, &opts.logdest, &verifydir] {
        std::fs::create_dir_all(dir).wrap_err_with(|| format!("creating {}", dir.display()))?;
    }
    checkout.export(&reviewed.target, &verifydir.join("worktree"))?;
    checkout.export(&reviewed.target, &opts.builddir.join("worktree"))?;

    // Phase 1 only downloads and verifies sources. Unlike --nobuild,
    // --verifysource does not run prepare() or pkgver() outside the jail.
    let verify_args = ["--verifysource", "--noconfirm", "--force"];
    let status = run_makepkg(opts, &verify_args, true, true, &verifydir)
        .wrap_err("running makepkg --verifysource")?;
    if !status.success() {
        bail!(
            "makepkg --verifysource failed for {} with status {}",
            reviewed.pkgbase,
            status.code().unwrap_or(-1)
        );
    }
    std::fs::remove_dir_all(&verifydir)
        .wrap_err_with(|| format!("removing {}", verifydir.display()))?;

    let sources = super::receipt::inputs(&opts.srcdest)?;
    let refs = super::receipt::vcs_refs(&opts.srcdest)?;
    // Phase 2 extracts, prepares, builds, and packages inside the jail.
    // --holdver prevents makepkg from updating VCS sources a second time;
    // phase 1 already fetched and verified the exact source state.
    let mut args = vec!["--noconfirm", "--force", "--holdver"];
    if without_dependency_checks {
        args.push("--nodeps");
    }
    let status = run_makepkg(opts, &args, opts.network, false, &opts.builddir)
        .wrap_err("running makepkg")?;
    if !status.success() {
        bail!(
            "makepkg failed for {} with status {}",
            reviewed.pkgbase,
            status.code().unwrap_or(-1)
        );
    }

    // What was built: makepkg knows the file names.
    let output = run_makepkg_output(opts, &["--packagelist"], false, false, &opts.builddir)
        .wrap_err("running makepkg --packagelist")?;
    if !output.status.success() {
        bail!("makepkg --packagelist failed for {}", reviewed.pkgbase);
    }
    let destination = opts.pkgdest.canonicalize()?;
    let mut files = Vec::new();
    for line in std::str::from_utf8(&output.stdout)?.lines() {
        let path = PathBuf::from(line);
        let path = if opts.chroot.is_some() {
            path.strip_prefix("/build").map_or_else(
                |_| path.clone(),
                |relative| {
                    opts.builddir
                        .parent()
                        .unwrap_or(&opts.builddir)
                        .join(relative)
                },
            )
        } else {
            path
        };
        let metadata = match std::fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            // makepkg --packagelist includes optional debug packages even
            // when no debug symbols were produced. Only existing outputs
            // can be returned; a build with no outputs still fails below.
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => continue,
            Err(err) => {
                return Err(err)
                    .wrap_err_with(|| format!("reading package output {}", path.display()));
            }
        };
        if !metadata.file_type().is_file() || !path.canonicalize()?.starts_with(&destination) {
            bail!(
                "unexpected package output outside the package directory or not a regular file: {}",
                path.display()
            );
        }
        files.push(path);
    }
    if files.is_empty() {
        bail!(
            "makepkg reported no package files in {}",
            opts.pkgdest.display()
        );
    }
    if super::receipt::inputs(&opts.srcdest)? != sources {
        bail!("source inputs changed during the build; refusing a misleading receipt");
    }
    super::receipt::write(reviewed, opts, sources, refs, &files)?;
    Ok(files)
}

fn run_makepkg(
    opts: &BuildOpts,
    args: &[&str],
    network: bool,
    source_writable: bool,
    builddir: &Path,
) -> Result<std::process::ExitStatus> {
    let mut child = spawn_makepkg(opts, args, network, source_writable, builddir, false)?;
    child.wait(&opts.limits, opts.builddir.parent().unwrap_or(builddir))
}

fn run_makepkg_output(
    opts: &BuildOpts,
    args: &[&str],
    network: bool,
    source_writable: bool,
    builddir: &Path,
) -> Result<std::process::Output> {
    let mut child = spawn_makepkg(opts, args, network, source_writable, builddir, true)?;
    let stdout = child
        .child
        .stdout
        .take()
        .ok_or_else(|| eyre::eyre!("missing build stdout"))?;
    let stderr = child
        .child
        .stderr
        .take()
        .ok_or_else(|| eyre::eyre!("missing build stderr"))?;
    let out = std::thread::spawn(move || bounded_output(stdout));
    let err = std::thread::spawn(move || bounded_output(stderr));
    let status = child.wait(&opts.limits, opts.builddir.parent().unwrap_or(builddir));
    drop(child); // close pipes held by lingering descendants before joining readers
    let stdout = out
        .join()
        .map_err(|_| eyre::eyre!("stdout reader panicked"))??;
    let stderr = err
        .join()
        .map_err(|_| eyre::eyre!("stderr reader panicked"))??;
    Ok(std::process::Output {
        status: status?,
        stdout,
        stderr,
    })
}

fn bounded_output(mut reader: impl std::io::Read) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    let mut chunk = [0u8; 8192];
    let mut overflow = false;
    loop {
        let n = reader.read(&mut chunk)?;
        if n == 0 {
            break;
        }
        if bytes.len() + n <= 1024 * 1024 {
            bytes.extend_from_slice(&chunk[..n]);
        } else {
            overflow = true;
        }
    }
    if overflow {
        bail!("makepkg metadata output exceeded 1 MiB");
    }
    Ok(bytes)
}

fn spawn_makepkg(
    opts: &BuildOpts,
    args: &[&str],
    network: bool,
    source_writable: bool,
    builddir: &Path,
    capture_output: bool,
) -> Result<crate::build_process::ManagedChild> {
    let scratch = builddir.join("tmp");
    std::fs::create_dir_all(&scratch).wrap_err("creating private build scratch directory")?;
    // makepkg checks PKGDEST before source verification too. Give that phase
    // its own writable destination, destroyed with the verification workspace,
    // so recipe code cannot plant outputs in the real package directory.
    let pkgdest = if source_writable {
        let path = builddir.join("pkgs");
        std::fs::create_dir_all(&path).wrap_err("creating verification package directory")?;
        path
    } else {
        opts.pkgdest.clone()
    };
    let mut writable = vec![builddir.to_path_buf(), opts.logdest.clone()];
    if !source_writable {
        writable.push(opts.pkgdest.clone());
    }
    if source_writable {
        writable.push(opts.srcdest.clone());
    }
    let mut spec = Spec {
        readable: vec![opts.srcdest.clone(), opts.makepkg.clone()],
        writable,
        network,
        program: opts.makepkg.clone(),
        args: args.iter().map(|arg| (*arg).to_string()).collect(),
        cwd: builddir.join("worktree"),
    };
    if opts.chroot.is_some() {
        let run = opts
            .builddir
            .parent()
            .ok_or_else(|| eyre::eyre!("missing run directory"))?;
        spec.cwd = super::chroot::inside(&spec.cwd, run);
        spec.readable = spec
            .readable
            .iter()
            .map(|p| super::chroot::inside(p, run))
            .collect();
        // The full readable root is the isolated image, never the host root.
        spec.readable.push(PathBuf::from("/"));
        spec.writable = spec
            .writable
            .iter()
            .map(|p| super::chroot::inside(p, run))
            .collect();
    }
    let helper = std::env::current_exe()?;
    let cgroup = opts
        .cgroup_root
        .as_ref()
        .map(|root| crate::cgroup::Group::create(root, &opts.limits, &helper))
        .transpose()?;
    let mut command = if let Some(root) = &opts.chroot {
        super::chroot::command(
            root,
            opts.builddir
                .parent()
                .ok_or_else(|| eyre::eyre!("missing run directory"))?,
            &helper,
            network,
            cgroup.as_ref().map(|group| group.path.as_path()),
        )?
    } else {
        let mut cmd = Command::new(&helper);
        cmd.arg("__build");
        cmd
    };
    command
        .env_clear()
        .envs(crate::jail::scrubbed_env())
        .stdin(Stdio::piped())
        .process_group(0);
    command
        .env("PKGDEST", &pkgdest)
        .env("SRCDEST", &opts.srcdest)
        .env("BUILDDIR", builddir)
        .env("LOGDEST", &opts.logdest)
        .env("TMPDIR", &scratch)
        .env("TMP", &scratch)
        .env("TEMP", &scratch);
    if opts.chroot.is_some() {
        command.env("PATH", "/usr/bin:/bin");
    }
    set_private_home(&mut command, builddir)?;
    if opts.chroot.is_some() {
        let run = opts
            .builddir
            .parent()
            .ok_or_else(|| eyre::eyre!("missing run directory"))?;
        let env: Vec<_> = command
            .get_envs()
            .filter_map(|(key, value)| {
                let value = value?;
                let path = Path::new(value);
                path.starts_with(run)
                    .then(|| (key.to_os_string(), super::chroot::inside(path, run)))
            })
            .collect();
        for (key, value) in env {
            command.env(key, value);
        }
    }

    if capture_output {
        command.stdout(Stdio::piped()).stderr(Stdio::piped());
    }
    let mut child =
        crate::build_process::ManagedChild::new(command.spawn().wrap_err("starting makepkg")?)?;
    child.cgroup = cgroup;
    {
        serde_json::to_writer(
            child
                .child
                .stdin
                .take()
                .ok_or_else(|| eyre::eyre!("jail helper stdin is not piped"))?,
            &crate::build_process::BuildSpec {
                cgroup_path: child.cgroup.as_ref().map(|group| {
                    if opts.chroot.is_some() {
                        PathBuf::from("/pacvamp-cgroup")
                    } else {
                        group.path.clone()
                    }
                }),
                spec,
                jail: opts.jail,
                limits: opts.limits.clone(),
            },
        )
        .wrap_err("sending the jail spec")?;
    }
    Ok(child)
}

fn set_private_home(command: &mut Command, builddir: &Path) -> Result<()> {
    let home = builddir.join("home");
    let cache = home.join(".cache");
    let gnupg = home.join(".gnupg");
    std::fs::create_dir_all(&cache)
        .wrap_err_with(|| format!("creating private build home {}", home.display()))?;
    seed_public_keyring(&gnupg)?;
    command
        .env("HOME", &home)
        .env("GNUPGHOME", &gnupg)
        .env("XDG_CACHE_HOME", &cache)
        .env("CARGO_HOME", home.join(".cargo"))
        .env("GOCACHE", cache.join("go-build"))
        .env("GOMODCACHE", cache.join("go-mod"))
        .env("npm_config_cache", cache.join("npm"))
        .env("TMPDIR", builddir.join("tmp"));
    std::fs::create_dir_all(builddir.join("tmp"))?;
    Ok(())
}

fn seed_public_keyring(to: &Path) -> Result<()> {
    let source = std::env::var_os("GNUPGHOME").map_or_else(
        || std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".gnupg")),
        |home| Some(PathBuf::from(home)),
    );
    seed_public_keyring_from(source.as_deref(), to)
}

fn seed_public_keyring_from(source: Option<&Path>, to: &Path) -> Result<()> {
    fs::create_dir_all(to)?;
    fs::set_permissions(to, fs::Permissions::from_mode(0o700))?;
    for name in ["pubring.kbx", "pubring.gpg", "trustdb.gpg", "public-keys.d"] {
        if let Some(from) = source.map(|source| source.join(name))
            && from.exists()
        {
            copy_tree(&from, &to.join(name))?;
        }
    }
    Ok(())
}

fn path_with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(suffix);
    path.with_file_name(name)
}

fn copy_tree(from: &Path, to: &Path) -> Result<()> {
    let metadata = std::fs::symlink_metadata(from)?;
    if metadata.is_dir() {
        std::fs::create_dir_all(to)?;
        for entry in std::fs::read_dir(from)? {
            let entry = entry?;
            copy_tree(&entry.path(), &to.join(entry.file_name()))?;
        }
    } else if metadata.is_file() {
        if let Some(parent) = to.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::copy(from, to)?;
    } else if metadata.file_type().is_symlink() {
        if let Some(parent) = to.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::os::unix::fs::symlink(std::fs::read_link(from)?, to)?;
    }
    Ok(())
}

/// Identity recorded inside a built package archive.
pub struct BuiltPackage {
    pub name: String,
    pub version: String,
}

/// Read the authoritative package names and versions emitted by makepkg.
pub fn built_packages(files: &[PathBuf]) -> Result<Vec<BuiltPackage>> {
    files
        .iter()
        .map(|file| {
            let output = Command::new("bsdtar")
                .args(["-xOf"])
                .arg(file)
                .arg(".PKGINFO")
                .output()
                .wrap_err_with(|| format!("reading metadata from {}", file.display()))?;
            if !output.status.success() {
                bail!("cannot read .PKGINFO from {}", file.display());
            }
            let text = String::from_utf8_lossy(&output.stdout);
            let value = |key: &str| {
                text.lines().find_map(|line| {
                    line.split_once(" = ")
                        .filter(|(k, _)| *k == key)
                        .map(|(_, v)| v)
                })
            };
            Ok(BuiltPackage {
                name: value("pkgname")
                    .ok_or_else(|| eyre::eyre!("{} has no pkgname", file.display()))?
                    .to_string(),
                version: value("pkgver")
                    .ok_or_else(|| eyre::eyre!("{} has no pkgver", file.display()))?
                    .to_string(),
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verification_directory_appends_to_dotted_pkgbase() {
        assert_eq!(
            path_with_suffix(Path::new("/cache/build/foo.bar"), ".verify"),
            Path::new("/cache/build/foo.bar.verify")
        );
    }

    #[test]
    fn private_gnupg_home_copies_only_public_key_material() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("source");
        let target = dir.path().join("target");
        fs::create_dir_all(source.join("private-keys-v1.d")).unwrap();
        fs::write(source.join("pubring.kbx"), b"public").unwrap();
        fs::write(source.join("private-keys-v1.d/secret.key"), b"secret").unwrap();

        seed_public_keyring_from(Some(&source), &target).unwrap();

        assert_eq!(fs::read(target.join("pubring.kbx")).unwrap(), b"public");
        assert!(!target.join("private-keys-v1.d").exists());
        assert_eq!(
            fs::metadata(&target).unwrap().permissions().mode() & 0o777,
            0o700
        );
    }
}
