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
    pub wall_seconds: Option<u64>,
    pub cpu_seconds: Option<u64>,
    pub memory_mb: Option<u64>,
    pub processes: Option<u64>,
    pub file_mb: Option<u64>,
    pub disk_mb: Option<u64>,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
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
        field!(wall_seconds);
        field!(cpu_seconds);
        field!(memory_mb);
        field!(processes);
        field!(file_mb);
        field!(disk_mb);
    }
    pub fn validate(&self) -> Result<()> {
        for n in [
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
    pub fn apply(&self) -> Result<()> {
        self.validate()?;
        for (resource, value) in [
            (Resource::RLIMIT_AS, self.memory_mb * 1024 * 1024),
            (Resource::RLIMIT_CPU, self.cpu_seconds),
            (Resource::RLIMIT_NPROC, self.processes),
            (Resource::RLIMIT_FSIZE, self.file_mb * 1024 * 1024),
            (Resource::RLIMIT_CORE, 0),
        ] {
            let (soft, hard) = getrlimit(resource)?;
            let ceiling = value.min(soft).min(hard);
            setrlimit(resource, ceiling, ceiling)?;
        }
        Ok(())
    }
}
#[derive(Serialize, Deserialize)]
pub struct BuildSpec {
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
    pub child: Child,
    group: Pid,
    cancelled: Arc<AtomicBool>,
    signals: Option<&'static BuildSignals>,
}
impl ManagedChild {
    pub fn new(child: Child) -> Result<Self> {
        let mut managed = Self {
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
        loop {
            if self.cancelled.load(Ordering::Relaxed) {
                bail!("build cancelled");
            }
            if start.elapsed() >= Duration::from_secs(limits.wall_seconds) {
                bail!("build exceeded wall-clock limit");
            }
            if disk_check.elapsed() >= Duration::from_secs(1) {
                match disk_bytes(run) {
                    Ok(bytes) => {
                        unreadable_since = None;
                        if bytes > limits.disk_mb * 1024 * 1024 {
                            bail!("build exceeded disk budget");
                        }
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
                if disk_bytes(run)? > limits.disk_mb * 1024 * 1024 {
                    bail!("build exceeded disk budget");
                }
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
fn disk_bytes(path: &Path) -> Result<u64> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(e) => return Err(e.into()),
    };
    if metadata.is_symlink() {
        return Ok(0);
    }
    if metadata.is_file() {
        return Ok(metadata.len());
    }
    let mut total = 0u64;
    if metadata.is_dir() {
        let entries = match std::fs::read_dir(path) {
            Ok(entries) => entries,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(0),
            Err(err) => {
                return Err(err)
                    .wrap_err_with(|| format!("accounting build directory {}", path.display()));
            }
        };
        for entry in entries {
            total = total.saturating_add(disk_bytes(&entry?.path())?);
        }
    }
    Ok(total)
}
