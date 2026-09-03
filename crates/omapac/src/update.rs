//! The pieces of `omapac update` that are not commands: release-age
//! holds, AUR upgrade candidates, the pacman lock wait, pacnew discovery,
//! and hooks. See `PLAN.md`, "Update flow".

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use alpm_db::vercmp;
use eyre::{Context as _, Result, bail};

use crate::aur::rpc::Rpc;
use crate::host::Host;
use crate::manifest::Settings;
use crate::manifest::settings::Age;
use crate::resolve::Tier;

/// A package an update leaves alone, and why.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Hold {
    pub name: String,
    pub reason: String,
}

/// Installed packages whose newer repository build is younger than the
/// tier's minimum release age.
pub fn age_holds(host: &Host, settings: &Settings, now: i64) -> Result<Vec<Hold>> {
    let mut holds = Vec::new();
    for package in host.installed()? {
        if settings
            .repo_min_release_age_excludes
            .iter()
            .any(|e| e == &package.name)
        {
            continue;
        }
        let Some((source, candidate)) = host.find_sync(&package.name)? else {
            continue;
        };
        if vercmp(&candidate.version, &package.version) != std::cmp::Ordering::Greater {
            continue;
        }
        let min = match &source.tier {
            Tier::Arch => settings.repo_min_release_age_arch,
            Tier::Opr => settings.repo_min_release_age_opr,
            _ => settings.repo_min_release_age_custom,
        };
        if min == Age::ZERO {
            continue;
        }
        let Some(built) = candidate.build_date else {
            continue;
        };
        let age = now - built;
        if age < min.0.as_secs() as i64 {
            holds.push(Hold {
                name: package.name.clone(),
                reason: format!(
                    "{} {} was built {} ago, less than the {} floor for {}",
                    source.name,
                    candidate.version,
                    crate::aur::format_age(built, now),
                    min,
                    source.tier
                ),
            });
        }
    }
    Ok(holds)
}

/// An installed foreign package the AUR has a newer version of.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct AurCandidate {
    pub name: String,
    pub installed: String,
    pub available: String,
}

/// Foreign packages (in no sync database) that the AUR carries at a newer
/// version.
pub fn aur_candidates(host: &Host, rpc: &dyn Rpc) -> Result<Vec<AurCandidate>> {
    let mut foreign = Vec::new();
    for package in host.installed()? {
        if host.find_sync(&package.name)?.is_none() {
            foreign.push(package);
        }
    }
    if foreign.is_empty() {
        return Ok(Vec::new());
    }
    let names: Vec<&str> = foreign.iter().map(|p| p.name.as_str()).collect();
    let remote = rpc.info(&names).wrap_err("asking the AUR for updates")?;
    let mut candidates = Vec::new();
    for package in foreign {
        let Some(available) = remote.iter().find(|r| r.name == package.name) else {
            continue;
        };
        if vercmp(&available.version, &package.version) == std::cmp::Ordering::Greater {
            candidates.push(AurCandidate {
                name: package.name.clone(),
                installed: package.version.clone(),
                available: available.version.clone(),
            });
        }
    }
    Ok(candidates)
}

/// Wait for pacman's database lock to clear.
pub fn wait_for_db_lock(db_path: &Path, timeout: Duration) -> Result<()> {
    let lock = db_path.join("db.lck");
    let started = Instant::now();
    let mut warned = false;
    while lock.exists() {
        if started.elapsed() > timeout {
            bail!(
                "{} still exists after {}s; another pacman is running, or remove the stale lock",
                lock.display(),
                timeout.as_secs()
            );
        }
        if !warned {
            eprintln!("waiting for {} to clear", lock.display());
            warned = true;
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    Ok(())
}

/// `.pacnew` and `.pacsave` files under `etc`, sorted.
pub fn pacnew_files(etc: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    walk(etc, &mut found, 0);
    found.sort();
    found
}

fn walk(dir: &Path, found: &mut Vec<PathBuf>, depth: usize) {
    if depth > 8 {
        return;
    }
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.filter_map(Result::ok) {
        let path = entry.path();
        let Ok(kind) = entry.file_type() else {
            continue;
        };
        if kind.is_dir() {
            walk(&path, found, depth + 1);
        } else if kind.is_file()
            && path
                .extension()
                .is_some_and(|e| e == "pacnew" || e == "pacsave")
        {
            found.push(path);
        }
    }
}

/// Run hook commands through `sh -c`, stopping at the first failure.
pub fn run_hooks(hooks: &[String], stage: &str) -> Result<()> {
    for hook in hooks {
        eprintln!("hook ({stage}): {hook}");
        let status = std::process::Command::new("sh")
            .arg("-c")
            .arg(hook)
            .env("OMAPAC_HOOK", stage)
            .status()
            .wrap_err_with(|| format!("running {stage} hook `{hook}`"))?;
        if !status.success() {
            bail!(
                "{stage} hook `{hook}` exited with status {}",
                status.code().unwrap_or(-1)
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_pacnew_files() {
        let dir = tempfile::tempdir().unwrap();
        let etc = dir.path().join("etc");
        std::fs::create_dir_all(etc.join("pacman.d")).unwrap();
        std::fs::write(etc.join("pacman.conf"), "").unwrap();
        std::fs::write(etc.join("pacman.conf.pacnew"), "").unwrap();
        std::fs::write(etc.join("pacman.d/mirrorlist.pacsave"), "").unwrap();
        std::fs::write(etc.join("hosts.pacnew.bak"), "").unwrap();
        let found = pacnew_files(&etc);
        assert_eq!(
            found,
            [
                etc.join("pacman.conf.pacnew"),
                etc.join("pacman.d/mirrorlist.pacsave")
            ]
        );
        assert!(pacnew_files(&dir.path().join("nope")).is_empty());
    }

    #[test]
    fn lock_wait_times_out() {
        let dir = tempfile::tempdir().unwrap();
        wait_for_db_lock(dir.path(), Duration::from_millis(10)).unwrap();
        std::fs::write(dir.path().join("db.lck"), "").unwrap();
        let err = wait_for_db_lock(dir.path(), Duration::from_millis(600))
            .unwrap_err()
            .to_string();
        assert!(err.contains("still exists"), "{err}");
    }

    #[test]
    fn hooks_run_and_fail_loudly() {
        run_hooks(
            &["true".into(), "test \"$OMAPAC_HOOK\" = pre".into()],
            "pre",
        )
        .unwrap();
        let err = run_hooks(&["exit 3".into()], "post")
            .unwrap_err()
            .to_string();
        assert!(err.contains("status 3"), "{err}");
    }
}
