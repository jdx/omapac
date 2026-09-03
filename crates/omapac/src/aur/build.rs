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
        Ok(BuildOpts {
            jail: settings.aur_jail,
            network: settings
                .aur_allow_network_build
                .iter()
                .any(|p| p == pkgbase),
            pkgdest: cache_dir.join("pkgs").join(pkgbase),
            srcdest: cache_dir.join("sources").join(pkgbase),
            builddir: cache_dir.join("build").join(pkgbase),
            logdest: cache_dir.join("logs").join(pkgbase),
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
    for dir in [&opts.srcdest, &opts.builddir, &opts.logdest] {
        std::fs::create_dir_all(dir).wrap_err_with(|| format!("creating {}", dir.display()))?;
    }

    // Phase 1 only downloads and verifies sources. Unlike --nobuild,
    // --verifysource does not run prepare() or pkgver() outside the jail.
    let status = Command::new(&opts.makepkg)
        .args(["--verifysource", "--noconfirm", "--force"])
        .current_dir(&checkout.dir)
        .env_clear()
        .envs(crate::jail::scrubbed_env())
        .env("PKGDEST", &opts.pkgdest)
        .env("SRCDEST", &opts.srcdest)
        .env("BUILDDIR", &opts.builddir)
        .env("LOGDEST", &opts.logdest)
        .status()
        .wrap_err("running makepkg --verifysource")?;
    if !status.success() {
        bail!(
            "makepkg --verifysource failed for {} with status {}",
            reviewed.pkgbase,
            status.code().unwrap_or(-1)
        );
    }

    // Phase 2 extracts, prepares, builds, and packages inside the jail.
    let args = vec!["--noconfirm".to_string(), "--force".to_string()];
    let status = if opts.jail {
        let spec = Spec {
            writable: vec![
                checkout.dir.clone(),
                opts.pkgdest.clone(),
                opts.srcdest.clone(),
                opts.builddir.clone(),
                opts.logdest.clone(),
                PathBuf::from("/tmp"),
                PathBuf::from("/var/tmp"),
                PathBuf::from("/dev/shm"),
            ],
            network: opts.network,
            program: opts.makepkg.clone(),
            args,
            cwd: checkout.dir.clone(),
        };
        // The helper inherits a scrubbed environment; PKGDEST rides along.
        let mut command = spec.command()?;
        command.env("PKGDEST", &opts.pkgdest);
        command.env("SRCDEST", &opts.srcdest);
        command.env("BUILDDIR", &opts.builddir);
        command.env("LOGDEST", &opts.logdest);
        let mut child = command.spawn().wrap_err("starting the build jail")?;
        if let Some(mut stdin) = child.stdin.take() {
            serde_json::to_writer(&mut stdin, &spec).wrap_err("sending the jail spec")?;
        }
        child.wait().wrap_err("waiting for makepkg")?
    } else {
        Command::new(&opts.makepkg)
            .args(&args)
            .current_dir(&checkout.dir)
            .env_clear()
            .envs(crate::jail::scrubbed_env())
            .env("PKGDEST", &opts.pkgdest)
            .env("SRCDEST", &opts.srcdest)
            .env("BUILDDIR", &opts.builddir)
            .env("LOGDEST", &opts.logdest)
            .status()
            .wrap_err("running makepkg")?
    };
    if !status.success() {
        bail!(
            "makepkg failed for {} with status {}",
            reviewed.pkgbase,
            status.code().unwrap_or(-1)
        );
    }

    // What was built: makepkg knows the file names.
    let output = Command::new(&opts.makepkg)
        .arg("--packagelist")
        .current_dir(&checkout.dir)
        .env_clear()
        .envs(crate::jail::scrubbed_env())
        .env("PKGDEST", &opts.pkgdest)
        .env("SRCDEST", &opts.srcdest)
        .env("BUILDDIR", &opts.builddir)
        .env("LOGDEST", &opts.logdest)
        .output()
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
