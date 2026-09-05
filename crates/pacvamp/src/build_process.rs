//! Build process supervision. Limits also apply when filesystem confinement is disabled.
use eyre::{Result, bail};
use nix::sys::{
    resource::{Resource, setrlimit},
    signal::{Signal, killpg},
};
use nix::unistd::Pid;
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::process::{Child, ExitStatus};
use std::sync::{
    Arc,
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
            setrlimit(resource, value, value)?;
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

pub struct ManagedChild {
    pub child: Child,
    group: Pid,
    cancelled: Arc<AtomicBool>,
    handlers: Vec<signal_hook::SigId>,
}
impl ManagedChild {
    pub fn new(child: Child) -> Result<Self> {
        let mut managed = Self {
            group: Pid::from_raw(child.id() as i32),
            child,
            cancelled: Arc::new(AtomicBool::new(false)),
            handlers: Vec::new(),
        };
        for sig in [
            signal_hook::consts::SIGINT,
            signal_hook::consts::SIGTERM,
            signal_hook::consts::SIGHUP,
        ] {
            managed
                .handlers
                .push(signal_hook::flag::register(sig, managed.cancelled.clone())?);
        }
        Ok(managed)
    }
    pub fn wait(&mut self, limits: &Limits, run: &Path) -> Result<ExitStatus> {
        let start = Instant::now();
        let mut disk_check = Instant::now();
        loop {
            if self.cancelled.load(Ordering::Relaxed) {
                bail!("build cancelled");
            }
            if start.elapsed() >= Duration::from_secs(limits.wall_seconds) {
                bail!("build exceeded wall-clock limit");
            }
            if disk_check.elapsed() >= Duration::from_secs(1) {
                if disk_bytes(run)? > limits.disk_mb * 1024 * 1024 {
                    bail!("build exceeded disk budget");
                }
                disk_check = Instant::now();
            }
            if let Some(status) = self.child.try_wait()? {
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
        for handler in self.handlers.drain(..) {
            signal_hook::low_level::unregister(handler);
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
        for entry in std::fs::read_dir(path)? {
            total = total.saturating_add(disk_bytes(&entry?.path())?);
        }
    }
    Ok(total)
}
