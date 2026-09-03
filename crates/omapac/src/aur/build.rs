//! Building an approved AUR commit with makepkg, in two phases so the jail
//! can differ: sources are fetched with network, then the build runs with
//! writes limited to the build directory and, unless granted, no network.
//! See `PLAN.md`, "Jailed builds".

use std::path::{Path, PathBuf};
use std::process::Command;

use alpm_db::Dependency;
use eyre::{Context as _, Result, bail};

use super::review::Reviewed;
use crate::host::Host;
use crate::jail::Spec;
use crate::manifest::Settings;

/// How to build.
#[derive(Debug, Clone)]
pub struct BuildOpts {
    /// Apply the Landlock and seccomp jail to the build phase.
    pub jail: bool,
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
    ) -> Result<BuildOpts> {
        let makepkg = which::which("makepkg")
            .map_err(|_| eyre::eyre!("makepkg is not on PATH; install base-devel"))?;
        let artifacts = cache_dir.join(".omapac-build");
        Ok(BuildOpts {
            jail: settings.aur_jail,
            network: settings
                .aur_allow_network_build
                .iter()
                .any(|p| p == pkgbase),
            pkgdest: artifacts.join("pkgs").join(pkgbase),
            srcdest: artifacts.join("sources").join(pkgbase),
            builddir: artifacts.join("build").join(pkgbase),
            logdest: artifacts.join("logs").join(pkgbase),
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
    pub other: Vec<String>,
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
            None => missing.other.push(dep.to_string()),
        }
    }
    Ok(missing)
}

/// Build `reviewed` at its target commit. Returns the package files.
pub fn build(reviewed: &Reviewed, opts: &BuildOpts) -> Result<Vec<PathBuf>> {
    let checkout = &reviewed.checkout;
    checkout.checkout(&reviewed.target)?;
    std::fs::create_dir_all(&opts.pkgdest)
        .wrap_err_with(|| format!("creating {}", opts.pkgdest.display()))?;
    let verifydir = opts.builddir.with_extension("verify");
    for dir in [&verifydir, &opts.builddir] {
        if dir.exists() {
            std::fs::remove_dir_all(dir).wrap_err_with(|| format!("clearing {}", dir.display()))?;
        }
    }
    for dir in [&opts.srcdest, &opts.builddir, &opts.logdest, &verifydir] {
        std::fs::create_dir_all(dir).wrap_err_with(|| format!("creating {}", dir.display()))?;
    }
    copy_tree(&checkout.dir, &verifydir.join("worktree"))?;
    copy_tree(&checkout.dir, &opts.builddir.join("worktree"))?;

    // Phase 1 only downloads and verifies sources. Unlike --nobuild,
    // --verifysource does not run prepare() or pkgver() outside the jail.
    let verify_args = ["--verifysource", "--noconfirm", "--force"];
    let status = run_makepkg(opts, &verify_args, true, &verifydir)
        .wrap_err("running makepkg --verifysource")?;
    std::fs::remove_dir_all(&verifydir)
        .wrap_err_with(|| format!("removing {}", verifydir.display()))?;
    if !status.success() {
        bail!(
            "makepkg --verifysource failed for {} with status {}",
            reviewed.pkgbase,
            status.code().unwrap_or(-1)
        );
    }

    // Phase 2 extracts, prepares, builds, and packages inside the jail.
    // --holdver prevents makepkg from updating VCS sources a second time;
    // phase 1 already fetched and verified the exact source state.
    let vcs = reviewed
        .evidence
        .recipe
        .sources
        .iter()
        .any(|source| source.is_vcs);
    let mut args = vec!["--noconfirm", "--force"];
    if !vcs {
        args.push("--holdver");
    }
    // VCS pkgver() must observe the freshly fetched checkout. makepkg cannot
    // update it separately from the build, so approved VCS recipes retain
    // network for this invocation; their VCS finding makes that risk explicit.
    let status = run_makepkg(opts, &args, opts.network || vcs, &opts.builddir)
        .wrap_err("running makepkg")?;
    if !status.success() {
        bail!(
            "makepkg failed for {} with status {}",
            reviewed.pkgbase,
            status.code().unwrap_or(-1)
        );
    }

    // What was built: makepkg knows the file names.
    let output = run_makepkg_output(opts, &["--packagelist"], false, &opts.builddir)
        .wrap_err("running makepkg --packagelist")?;
    let files: Vec<PathBuf> = String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(PathBuf::from)
        .filter(|p| p.exists())
        .collect();
    if files.is_empty() {
        bail!(
            "makepkg reported no package files in {}",
            opts.pkgdest.display()
        );
    }
    Ok(files)
}

fn run_makepkg(
    opts: &BuildOpts,
    args: &[&str],
    network: bool,
    builddir: &Path,
) -> Result<std::process::ExitStatus> {
    if !opts.jail {
        let mut command = Command::new(&opts.makepkg);
        command
            .args(args)
            .current_dir(builddir.join("worktree"))
            .env_clear()
            .envs(crate::jail::scrubbed_env())
            .env("PKGDEST", &opts.pkgdest)
            .env("SRCDEST", &opts.srcdest)
            .env("BUILDDIR", builddir)
            .env("LOGDEST", &opts.logdest);
        set_private_home(&mut command, builddir)?;
        return command.status().wrap_err("starting makepkg");
    }

    let spec = Spec {
        // makepkg needs to lock and sometimes update PKGBUILD, so it runs in
        // a disposable checkout copy contained by this writable build root.
        writable: vec![
            opts.pkgdest.clone(),
            opts.srcdest.clone(),
            builddir.to_path_buf(),
            opts.logdest.clone(),
        ],
        network,
        program: opts.makepkg.clone(),
        args: args.iter().map(|arg| (*arg).to_string()).collect(),
        cwd: builddir.join("worktree"),
    };
    let mut command = spec.command()?;
    command.env("PKGDEST", &opts.pkgdest);
    command.env("SRCDEST", &opts.srcdest);
    command.env("BUILDDIR", builddir);
    command.env("LOGDEST", &opts.logdest);
    set_private_home(&mut command, builddir)?;
    let mut child = command.spawn().wrap_err("starting the build jail")?;
    if let Some(mut stdin) = child.stdin.take() {
        serde_json::to_writer(&mut stdin, &spec).wrap_err("sending the jail spec")?;
    }
    child.wait().wrap_err("waiting for makepkg")
}

fn run_makepkg_output(
    opts: &BuildOpts,
    args: &[&str],
    network: bool,
    builddir: &Path,
) -> Result<std::process::Output> {
    if !opts.jail {
        let mut command = Command::new(&opts.makepkg);
        command
            .args(args)
            .current_dir(builddir.join("worktree"))
            .env_clear()
            .envs(crate::jail::scrubbed_env())
            .env("PKGDEST", &opts.pkgdest)
            .env("SRCDEST", &opts.srcdest)
            .env("BUILDDIR", builddir)
            .env("LOGDEST", &opts.logdest);
        set_private_home(&mut command, builddir)?;
        return command.output().wrap_err("starting makepkg");
    }
    let spec = Spec {
        writable: vec![
            opts.pkgdest.clone(),
            opts.srcdest.clone(),
            builddir.to_path_buf(),
            opts.logdest.clone(),
        ],
        network,
        program: opts.makepkg.clone(),
        args: args.iter().map(|arg| (*arg).to_string()).collect(),
        cwd: builddir.join("worktree"),
    };
    let mut command = spec.command()?;
    command
        .env("PKGDEST", &opts.pkgdest)
        .env("SRCDEST", &opts.srcdest)
        .env("BUILDDIR", builddir)
        .env("LOGDEST", &opts.logdest);
    set_private_home(&mut command, builddir)?;
    command.stdout(std::process::Stdio::piped());
    let mut child = command.spawn().wrap_err("starting the build jail")?;
    if let Some(mut stdin) = child.stdin.take() {
        serde_json::to_writer(&mut stdin, &spec).wrap_err("sending the jail spec")?;
    }
    child.wait_with_output().wrap_err("waiting for makepkg")
}

fn set_private_home(command: &mut Command, builddir: &Path) -> Result<()> {
    let home = builddir.join("home");
    let cache = home.join(".cache");
    std::fs::create_dir_all(&cache)
        .wrap_err_with(|| format!("creating private build home {}", home.display()))?;
    command
        .env("HOME", &home)
        .env("XDG_CACHE_HOME", &cache)
        .env("CARGO_HOME", home.join(".cargo"))
        .env("GOCACHE", cache.join("go-build"))
        .env("GOMODCACHE", cache.join("go-mod"))
        .env("npm_config_cache", cache.join("npm"))
        .env("TMPDIR", builddir.join("tmp"));
    std::fs::create_dir_all(builddir.join("tmp"))?;
    Ok(())
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
