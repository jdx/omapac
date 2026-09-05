//! Build process supervision. Limits also apply when filesystem confinement is disabled.
use eyre::{Context as _, Result, bail};
use nix::sys::{
    resource::{Resource, getrlimit, setrlimit},
    signal::{Signal, killpg},
};
use nix::unistd::Pid;
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::process::{Child, ExitStatus};
use std::sync::{
    Arc, Mutex, OnceLock,
    atomic::{AtomicBool, Ordering},
};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Limits {
    #[serde(default = "default_cpu_percent")]
    pub cpu_percent: u64,
    pub wall_seconds: u64,
    pub cpu_seconds: u64,
    pub memory_mb: u64,
    pub processes: u64,
    pub file_mb: u64,
    pub disk_mb: u64,
}
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LimitsToml {
    pub cpu_percent: Option<u64>,
    pub wall_seconds: Option<u64>,
    pub cpu_seconds: Option<u64>,
    pub memory_mb: Option<u64>,
    pub processes: Option<u64>,
    pub file_mb: Option<u64>,
    pub disk_mb: Option<u64>,
}
fn default_cpu_percent() -> u64 {
    100
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            cpu_percent: default_cpu_percent(),
            wall_seconds: 7200,
            cpu_seconds: 7200,
            memory_mb: 32768,
            processes: 4096,
            file_mb: 4096,
            disk_mb: 20480,
        }
    }
}
impl Limits {
    pub fn merge(&mut self, layer: &LimitsToml, managed: bool) {
        macro_rules! field {
            ($f:ident) => {
                if let Some(v) = layer.$f {
                    self.$f = if managed { self.$f.min(v) } else { v };
                }
            };
        }
        field!(cpu_percent);
        field!(wall_seconds);
        field!(cpu_seconds);
        field!(memory_mb);
        field!(processes);
        field!(file_mb);
        field!(disk_mb);
    }
    pub fn validate(&self) -> Result<()> {
        for n in [
            self.cpu_percent,
            self.wall_seconds,
            self.cpu_seconds,
            self.memory_mb,
            self.processes,
            self.file_mb,
            self.disk_mb,
        ] {
            if n == 0 || n > u64::MAX / (1024 * 1024) {
                bail!("build limits must be positive and representable");
            }
        }
        Ok(())
    }
    pub fn effective_kernel_limits(&self) -> Result<KernelLimits> {
        self.validate()?;
        fn ceiling(resource: Resource, value: u64) -> Result<u64> {
            let (soft, hard) = getrlimit(resource)?;
            Ok(value.min(soft).min(hard))
        }
        Ok(KernelLimits {
            memory_bytes: ceiling(Resource::RLIMIT_AS, self.memory_mb * 1024 * 1024)?,
            cpu_seconds: ceiling(Resource::RLIMIT_CPU, self.cpu_seconds)?,
            processes: ceiling(Resource::RLIMIT_NPROC, self.processes)?,
            file_bytes: ceiling(Resource::RLIMIT_FSIZE, self.file_mb * 1024 * 1024)?,
        })
    }
    pub fn apply(&self) -> Result<()> {
        let effective = self.effective_kernel_limits()?;
        for (resource, value) in [
            (Resource::RLIMIT_AS, effective.memory_bytes),
            (Resource::RLIMIT_CPU, effective.cpu_seconds),
            (Resource::RLIMIT_NPROC, effective.processes),
            (Resource::RLIMIT_FSIZE, effective.file_bytes),
            (Resource::RLIMIT_CORE, 0),
        ] {
            setrlimit(resource, value, value)?;
        }
        Ok(())
    }
}
pub struct KernelLimits {
    pub memory_bytes: u64,
    pub cpu_seconds: u64,
    pub processes: u64,
    pub file_bytes: u64,
}
#[derive(Serialize, Deserialize)]
pub struct BuildSpec {
    #[serde(default)]
    pub cgroup_path: Option<std::path::PathBuf>,
    pub spec: crate::jail::Spec,
    pub jail: bool,
    pub limits: Limits,
}

/// Prevent descendants from escaping the process group used for cancellation.
pub fn confine_process_group() -> Result<()> {
    use seccompiler::{SeccompAction, SeccompFilter, SeccompRule, TargetArch};
    let arch: TargetArch = std::env::consts::ARCH
        .try_into()
        .map_err(|e: seccompiler::BackendError| eyre::eyre!(e))?;
    let rules = [libc::SYS_setsid, libc::SYS_setpgid]
        .into_iter()
        .map(|syscall| (syscall, Vec::<SeccompRule>::new()))
        .collect();
    let filter = SeccompFilter::new(
        rules,
        SeccompAction::Allow,
        SeccompAction::Errno(libc::EPERM as u32),
        arch,
    )?;
    let program: seccompiler::BpfProgram = filter.try_into()?;
    seccompiler::apply_filter(&program)?;
    Ok(())
}

// signal-hook retains its OS handler after unregistering callbacks. Keep a
// permanent conditional default action so signals still terminate the CLI
// between builds, and share cancellation while any build is supervised.
struct BuildSignals {
    active: Mutex<usize>,
    default_action: Arc<AtomicBool>,
    cancelled: Arc<AtomicBool>,
}
fn build_signals() -> Result<&'static BuildSignals> {
    static SIGNALS: OnceLock<std::io::Result<BuildSignals>> = OnceLock::new();
    SIGNALS
        .get_or_init(|| {
            let signals = BuildSignals {
                active: Mutex::new(0),
                default_action: Arc::new(AtomicBool::new(true)),
                cancelled: Arc::new(AtomicBool::new(false)),
            };
            for sig in [
                signal_hook::consts::SIGINT,
                signal_hook::consts::SIGTERM,
                signal_hook::consts::SIGHUP,
            ] {
                signal_hook::flag::register_conditional_default(
                    sig,
                    signals.default_action.clone(),
                )?;
                signal_hook::flag::register(sig, signals.cancelled.clone())?;
            }
            Ok(signals)
        })
        .as_ref()
        .map_err(|err| eyre::eyre!("registering build cancellation signals: {err}"))
}

pub struct ManagedChild {
    pub cgroup: Option<crate::cgroup::Group>,
    pub child: Child,
    group: Pid,
    cancelled: Arc<AtomicBool>,
    signals: Option<&'static BuildSignals>,
}
impl ManagedChild {
    pub fn new(child: Child) -> Result<Self> {
        let mut managed = Self {
            cgroup: None,
            group: Pid::from_raw(child.id() as i32),
            child,
            cancelled: Arc::new(AtomicBool::new(false)),
            signals: None,
        };
        let signals = build_signals()?;
        let mut active = signals.active.lock().unwrap_or_else(|err| err.into_inner());
        if *active == 0 {
            signals.cancelled.store(false, Ordering::SeqCst);
            signals.default_action.store(false, Ordering::SeqCst);
        }
        *active += 1;
        managed.cancelled = signals.cancelled.clone();
        managed.signals = Some(signals);
        Ok(managed)
    }
    pub fn wait(&mut self, limits: &Limits, run: &Path) -> Result<ExitStatus> {
        let start = Instant::now();
        let mut disk_check = Instant::now();
        let mut unreadable_since: Option<Instant> = None;
        let check_running = || {
            if self.cancelled.load(Ordering::Relaxed) {
                bail!("build cancelled");
            }
            if start.elapsed() >= Duration::from_secs(limits.wall_seconds) {
                bail!("build exceeded wall-clock limit");
            }
            Ok(())
        };
        loop {
            check_running()?;
            if disk_check.elapsed() >= Duration::from_secs(1) {
                match check_disk(run, limits.disk_mb * 1024 * 1024, check_running) {
                    Ok(()) => {
                        unreadable_since = None;
                    }
                    Err(err)
                        if err
                            .chain()
                            .filter_map(|e| e.downcast_ref::<std::io::Error>())
                            .any(|e| e.kind() == std::io::ErrorKind::PermissionDenied) =>
                    {
                        // fakeroot briefly tests permissions with inaccessible directories.
                        // A persistently unaccountable tree must still fail closed.
                        if unreadable_since.get_or_insert_with(Instant::now).elapsed()
                            >= Duration::from_secs(3)
                        {
                            return Err(err).wrap_err("build disk accounting remained unavailable");
                        }
                    }
                    Err(err) => return Err(err),
                }
                disk_check = Instant::now();
            }
            if let Some(status) = self.child.try_wait()? {
                // Stop lingering writers before the mandatory final accounting pass.
                let _ = killpg(self.group, Signal::SIGKILL);
                check_disk(run, limits.disk_mb * 1024 * 1024, check_running)?;
                return Ok(status);
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}
impl Drop for ManagedChild {
    fn drop(&mut self) {
        let _ = killpg(self.group, Signal::SIGKILL);
        let _ = self.child.wait();
        if let Some(signals) = self.signals {
            let mut active = signals.active.lock().unwrap_or_else(|err| err.into_inner());
            *active -= 1;
            if *active == 0 {
                signals.default_action.store(true, Ordering::SeqCst);
            }
        }
    }
}
fn accounting_flags() -> nix::fcntl::OFlag {
    use nix::fcntl::OFlag;
    OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC
}
fn check_disk(path: &Path, budget: u64, check_running: impl FnMut() -> Result<()>) -> Result<()> {
    let root = nix::dir::Dir::open(path, accounting_flags(), nix::sys::stat::Mode::empty())
        .map_err(std::io::Error::from)
        .wrap_err_with(|| format!("accounting build directory {}", path.display()))?;
    check_disk_dir(root, budget, check_running).map(|_| ())
}
/// Live cache estimates use the same anchored, no-follow accounting as builds.
pub(crate) fn disk_size(path: &Path) -> Result<u64> {
    use nix::errno::Errno;
    let root = match nix::dir::Dir::open(path, accounting_flags(), nix::sys::stat::Mode::empty()) {
        Ok(root) => root,
        Err(Errno::ENOENT | Errno::ENOTDIR | Errno::ELOOP) => return Ok(0),
        Err(err) => return Err(std::io::Error::from(err).into()),
    };
    check_disk_dir(root, u64::MAX, || Ok(()))
}
fn check_disk_dir(
    root: nix::dir::Dir,
    budget: u64,
    mut check_running: impl FnMut() -> Result<()>,
) -> Result<u64> {
    use nix::{
        dir::{Dir, OwningIter},
        errno::Errno,
        fcntl::AtFlags,
        sys::stat::{Mode, SFlag, fstat, fstatat},
    };
    use std::os::fd::{AsFd as _, OwnedFd};
    fn frame(dir: Dir) -> std::io::Result<(OwnedFd, OwningIter)> {
        Ok((dir.as_fd().try_clone_to_owned()?, dir.into_iter()))
    }
    // Count preallocation as well as sparse logical length. Linux st_blocks
    // is expressed in 512-byte units, independent of the filesystem block size.
    fn bytes(stat: &nix::sys::stat::FileStat) -> u64 {
        (stat.st_size.max(0) as u64).max((stat.st_blocks.max(0) as u64).saturating_mul(512))
    }
    let mut total = bytes(&fstat(&root).map_err(std::io::Error::from)?);
    let mut stack = vec![frame(root)?];
    while let Some((fd, entries)) = stack.last_mut() {
        check_running()?;
        if total > budget {
            bail!("build exceeded disk budget");
        }
        let Some(entry) = entries.next() else {
            stack.pop();
            continue;
        };
        let entry = entry.map_err(std::io::Error::from)?;
        let name = entry.file_name();
        if name.to_bytes() == b"." || name.to_bytes() == b".." {
            continue;
        }
        let stat = match fstatat(&*fd, name, AtFlags::AT_SYMLINK_NOFOLLOW) {
            Ok(stat) => stat,
            Err(Errno::ENOENT) => continue,
            Err(err) => return Err(std::io::Error::from(err).into()),
        };
        let kind = SFlag::from_bits_truncate(stat.st_mode) & SFlag::S_IFMT;
        if kind == SFlag::S_IFDIR {
            // The no-follow open is relative to the already-open parent. A
            // rename/symlink swap after fstatat cannot redirect traversal.
            let child = match Dir::openat(&*fd, name, accounting_flags(), Mode::empty()) {
                Ok(child) => child,
                Err(Errno::ENOENT | Errno::ENOTDIR | Errno::ELOOP) => continue,
                Err(err) => {
                    return Err(std::io::Error::from(err)).wrap_err_with(|| {
                        format!("accounting build directory {}", name.to_string_lossy())
                    });
                }
            };
            total = total.saturating_add(bytes(&fstat(&child).map_err(std::io::Error::from)?));
            stack.push(frame(child)?);
        } else if kind == SFlag::S_IFREG {
            total = total.saturating_add(bytes(&stat));
        }
    }
    Ok(total)
}

#[cfg(test)]
mod accounting_tests {
    use super::*;
    #[test]
    fn scan_stays_anchored_and_does_not_follow_symlinks() {
        let tmp = tempfile::tempdir().unwrap();
        let run = tmp.path().join("run");
        let outside = tmp.path().join("outside");
        std::fs::create_dir(&run).unwrap();
        std::fs::create_dir(&outside).unwrap();
        std::fs::write(outside.join("large"), vec![0; 2 * 1024 * 1024]).unwrap();
        std::os::unix::fs::symlink(&outside, run.join("link")).unwrap();
        let root =
            nix::dir::Dir::open(&run, accounting_flags(), nix::sys::stat::Mode::empty()).unwrap();
        std::fs::rename(&run, tmp.path().join("original")).unwrap();
        std::os::unix::fs::symlink(&outside, &run).unwrap();
        check_disk_dir(root, 1024 * 1024, || Ok(())).unwrap();
        assert!(check_disk(&run, 1024 * 1024, || Ok(())).is_err());
    }
    #[test]
    fn traversal_checks_cancellation_and_deadlines() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("entry"), b"x").unwrap();
        let mut checks = 0;
        let err = check_disk(tmp.path(), u64::MAX, || {
            checks += 1;
            if checks == 2 {
                bail!("build cancelled during traversal");
            }
            Ok(())
        })
        .unwrap_err();
        assert!(err.to_string().contains("cancelled during traversal"));
    }
}
