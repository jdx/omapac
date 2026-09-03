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

/// Publish times from repository indexes: repository name, then package
/// file name, to unix seconds. What release-age floors prefer over the
/// build date, since a package can be built long before it is served.
#[derive(Debug, Default)]
pub struct Published {
    pub times: std::collections::BTreeMap<String, std::collections::BTreeMap<String, i64>>,
    /// Repositories whose signed index was rejected as stale or rolled back.
    pub unsafe_repos: std::collections::BTreeMap<String, String>,
}

impl Published {
    pub fn new() -> Published {
        Published::default()
    }

    pub fn insert(&mut self, repo: String, times: std::collections::BTreeMap<String, i64>) {
        self.times.insert(repo, times);
    }
}

/// Installed packages whose newer repository build is younger than the
/// tier's minimum release age, by publish time when the repository's
/// index records one and by build date otherwise.
pub fn age_holds(
    host: &Host,
    settings: &Settings,
    now: i64,
    published: &Published,
) -> Result<Vec<Hold>> {
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
        if let Some(reason) = published.unsafe_repos.get(&source.name) {
            holds.push(Hold {
                name: package.name.clone(),
                reason: format!(
                    "{} {} release age cannot be verified because its signed index was rejected: {reason}",
                    source.name, candidate.version
                ),
            });
            continue;
        }
        let (since, what) = match published
            .times
            .get(&source.name)
            .and_then(|files| files.get(&candidate.filename))
        {
            Some(&at) => (at, "published"),
            None => match candidate.build_date {
                Some(built) => (built, "built"),
                None => continue,
            },
        };
        let age = now - since;
        if age < min.0.as_secs() as i64 {
            holds.push(Hold {
                name: package.name.clone(),
                reason: format!(
                    "{} {} was {what} {} ago, less than the {} floor for {}",
                    source.name,
                    candidate.version,
                    crate::aur::format_age(since, now),
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

/// The update lock: one `omapac update` at a time per lock path. Held
/// for the life of the value.
pub struct UpdateLock {
    _flock: nix::fcntl::Flock<std::fs::File>,
    pub path: PathBuf,
}

impl UpdateLock {
    /// Where the lock lives: an existing readable system lock is shared
    /// even when this process cannot write it. Otherwise use the ledger
    /// directory when writable, then the user's runtime or cache directory.
    pub fn path(sysroot: Option<&Path>) -> PathBuf {
        let system = crate::ledger::Ledger::path(sysroot)
            .parent()
            .map(|dir| dir.join("update.lock"))
            .unwrap_or_else(|| PathBuf::from("/var/lib/omapac/update.lock"));
        if std::fs::symlink_metadata(&system).is_ok_and(|metadata| {
            metadata.file_type().is_file() && open_lock(&system, false, false).is_ok()
        }) {
            return system;
        }
        if let Some(dir) = system.parent() {
            let _ = std::fs::create_dir_all(dir);
            if dir.is_dir() && is_writable(dir) {
                return system;
            }
        }
        if let Some(runtime) = std::env::var_os("XDG_RUNTIME_DIR") {
            let runtime = PathBuf::from(runtime);
            if let Some(path) = user_lock_path(&runtime) {
                return path;
            }
        }
        crate::aur::cache_dir().join("update.lock")
    }

    /// Take the lock, waiting up to `wait` when another update holds it.
    pub fn acquire(path: &Path, wait: Option<Duration>) -> Result<UpdateLock> {
        use nix::fcntl::{Flock, FlockArg};
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).wrap_err_with(|| format!("creating {}", dir.display()))?;
        }
        let (file, can_record_holder) = match open_lock(path, true, true) {
            Ok(file) => (file, true),
            Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => (
                open_lock(path, false, false)
                    .wrap_err_with(|| format!("opening {}", path.display()))?,
                false,
            ),
            Err(err) => {
                return Err(err).wrap_err_with(|| format!("opening {}", path.display()));
            }
        };
        let started = Instant::now();
        let mut file = Some(file);
        loop {
            match Flock::lock(file.take().expect("file"), FlockArg::LockExclusiveNonblock) {
                Ok(flock) => {
                    use std::io::Write as _;
                    let mut f: &std::fs::File = &flock;
                    let _ = f.set_len(0);
                    let _ = writeln!(f, "{}", std::process::id());
                    return Ok(UpdateLock {
                        _flock: flock,
                        path: path.to_path_buf(),
                    });
                }
                Err((returned, nix::errno::Errno::EWOULDBLOCK)) => {
                    // A read-only participant cannot replace stale contents
                    // with its own pid after taking the lock. Do not present
                    // those contents as the identity of the current holder.
                    let holder = can_record_holder
                        .then(|| std::fs::read_to_string(path).ok())
                        .flatten()
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty());
                    match wait {
                        Some(limit) if started.elapsed() < limit => {
                            std::thread::sleep(Duration::from_millis(250));
                            file = Some(returned);
                        }
                        Some(limit) => bail!(
                            "timed out after {:.1}s waiting for another omapac update{}",
                            limit.as_secs_f64(),
                            holder
                                .map(|pid| format!(" (pid {pid})"))
                                .unwrap_or_default()
                        ),
                        None => bail!(
                            "another omapac update is running{}; pass --wait to queue behind it",
                            holder
                                .map(|pid| format!(" (pid {pid})"))
                                .unwrap_or_default()
                        ),
                    }
                }
                Err((_, err)) => bail!("locking {}: {err}", path.display()),
            }
        }
    }
}

fn open_lock(path: &Path, writable: bool, create: bool) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt as _;

    std::fs::OpenOptions::new()
        .read(true)
        .write(writable)
        .create(create)
        .truncate(false)
        .custom_flags(nix::libc::O_NOFOLLOW)
        .open(path)
}

fn user_lock_path(root: &Path) -> Option<PathBuf> {
    if root.as_os_str().is_empty() || !root.is_absolute() {
        return None;
    }
    let dir = root.join("omapac");
    std::fs::create_dir_all(&dir).ok()?;
    (dir.is_dir() && is_writable(&dir)).then(|| dir.join("update.lock"))
}

fn is_writable(dir: &Path) -> bool {
    for attempt in 0..16 {
        let probe = dir.join(format!(
            ".omapac-lock-probe-{}-{attempt}",
            std::process::id()
        ));
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&probe)
        {
            Ok(file) => {
                drop(file);
                return std::fs::remove_file(probe).is_ok();
            }
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(_) => return false,
        }
    }
    false
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
    fn update_lock_wait_reports_timeout() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("update.lock");
        let _held = UpdateLock::acquire(&path, None).unwrap();
        let err = UpdateLock::acquire(&path, Some(Duration::ZERO))
            .err()
            .unwrap()
            .to_string();
        assert!(err.contains("timed out"), "{err}");
        assert!(!err.contains("pass --wait"), "{err}");
    }

    #[test]
    fn existing_read_only_system_lock_is_shared() {
        let root = tempfile::tempdir().unwrap();
        let directory = root.path().join("var/lib/omapac");
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join("update.lock");
        std::fs::write(&path, "system\n").unwrap();
        let mut file_permissions = std::fs::metadata(&path).unwrap().permissions();
        std::os::unix::fs::PermissionsExt::set_mode(&mut file_permissions, 0o444);
        std::fs::set_permissions(&path, file_permissions).unwrap();
        let mut directory_permissions = std::fs::metadata(&directory).unwrap().permissions();
        std::os::unix::fs::PermissionsExt::set_mode(&mut directory_permissions, 0o555);
        std::fs::set_permissions(&directory, directory_permissions).unwrap();

        assert_eq!(UpdateLock::path(Some(root.path())), path);
        let _held = UpdateLock::acquire(&path, None).unwrap();
        let err = UpdateLock::acquire(&path, Some(Duration::ZERO))
            .err()
            .unwrap()
            .to_string();

        let mut directory_permissions = std::fs::metadata(&directory).unwrap().permissions();
        std::os::unix::fs::PermissionsExt::set_mode(&mut directory_permissions, 0o755);
        std::fs::set_permissions(&directory, directory_permissions).unwrap();
        assert!(err.contains("timed out"), "{err}");
        assert!(!err.contains("pid system"), "{err}");
    }

    #[test]
    fn runtime_lock_path_must_be_absolute_and_usable() {
        assert!(user_lock_path(Path::new("")).is_none());
        assert!(user_lock_path(Path::new("relative/runtime")).is_none());

        let dir = tempfile::tempdir().unwrap();
        assert_eq!(
            user_lock_path(dir.path()),
            Some(dir.path().join("omapac/update.lock"))
        );

        let stale = dir.path().join("stale");
        std::fs::write(&stale, "not a directory").unwrap();
        assert!(user_lock_path(&stale).is_none());
        assert!(
            !is_writable(Path::new("/proc")),
            "an actual write probe must reject a read-only virtual filesystem even as root"
        );
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
