//! The build jail: Landlock for the filesystem and TCP, seccomp for inet
//! sockets, applied by a helper process that restricts itself and then
//! execs the build. That keeps the crate free of `unsafe` (no
//! `pre_exec`) and keeps the parent unrestricted. See `PLAN.md`, "Jailed
//! builds".
//!
//! If the kernel cannot enforce what was asked for, the build fails
//! instead of running unjailed.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use eyre::{Context as _, Result, bail};
use serde::{Deserialize, Serialize};

/// What a jailed command may do.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Spec {
    /// Additional read-only inputs, beyond the system runtime paths.
    #[serde(default)]
    pub readable: Vec<PathBuf>,
    /// Directories the command may read and write. Other paths are denied.
    pub writable: Vec<PathBuf>,
    /// Whether the command may use the network.
    pub network: bool,
    pub program: PathBuf,
    pub args: Vec<String>,
    /// Working directory.
    pub cwd: PathBuf,
}

/// Environment variable names that never reach a build.
const SCRUBBED: &[&str] = &[
    "SSH_AUTH_SOCK",
    "GPG_AGENT_INFO",
    "DBUS_SESSION_BUS_ADDRESS",
    "DISPLAY",
    "XAUTHORITY",
    "WAYLAND_DISPLAY",
    "XDG_RUNTIME_DIR",
    "GITHUB_TOKEN",
    "GH_TOKEN",
    "NPM_TOKEN",
    "CARGO_REGISTRY_TOKEN",
    "PYPI_TOKEN",
];
const SCRUBBED_PREFIXES: &[&str] = &["AWS_", "AZURE_", "GOOGLE_", "OPENAI_", "ANTHROPIC_"];
const SCRUBBED_INFIXES: &[&str] = &["TOKEN", "SECRET", "PASSWORD", "API_KEY", "PRIVATE_KEY"];

/// Whether an environment variable should be withheld from a build.
pub fn is_sensitive(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    SCRUBBED.contains(&upper.as_str())
        || SCRUBBED_PREFIXES.iter().any(|p| upper.starts_with(p))
        || SCRUBBED_INFIXES.iter().any(|i| upper.contains(i))
}

/// The environment a build receives: the current one minus secrets.
pub fn scrubbed_env() -> BTreeMap<String, String> {
    std::env::vars()
        .filter(|(name, _)| !is_sensitive(name))
        .collect()
}

impl Spec {
    /// Build the command that runs `self` through the `__jail` helper.
    pub fn command(&self) -> Result<Command> {
        let exe = std::env::current_exe().wrap_err("locating pacvamp")?;
        let mut command = Command::new(exe);
        command.arg("__jail");
        command.env_clear();
        command.envs(scrubbed_env());
        command.stdin(std::process::Stdio::piped());
        Ok(command)
    }

    /// Restrict the current process as the spec says. Called by the helper.
    pub fn apply(&self) -> Result<()> {
        restrict_filesystem(&self.readable, &self.writable, self.network)?;
        if !self.network {
            deny_inet_sockets()?;
        }
        Ok(())
    }
}

/// Exercise the actual helper and both restrictions in a disposable process.
/// The caller remains unrestricted; this does not execute a package recipe.
pub fn probe() -> Result<()> {
    let spec = Spec {
        readable: vec![],
        writable: vec![],
        network: false,
        program: PathBuf::from("/usr/bin/true"),
        args: vec![],
        cwd: PathBuf::from("/"),
    };
    let mut child = spec
        .command()?
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .wrap_err("starting sandbox probe")?;
    serde_json::to_writer(
        child
            .stdin
            .take()
            .ok_or_else(|| eyre::eyre!("probe stdin unavailable"))?,
        &spec,
    )?;
    let output = child.wait_with_output()?;
    if !output.status.success() {
        bail!(
            "sandbox probe failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(())
}

fn restrict_filesystem(readable: &[PathBuf], writable: &[PathBuf], network: bool) -> Result<()> {
    use landlock::{
        ABI, Access, AccessFs, AccessNet, Compatible, RulesetAttr, RulesetCreatedAttr,
        RulesetStatus, path_beneath_rules,
    };
    let abi = ABI::V4;
    let mut ruleset = landlock::Ruleset::default()
        .set_compatibility(landlock::CompatLevel::HardRequirement)
        .handle_access(AccessFs::from_all(abi))
        .map_err(|e| eyre::eyre!("landlock: {e}"))?;
    if !network {
        ruleset = ruleset
            .handle_access(AccessNet::BindTcp | AccessNet::ConnectTcp)
            .map_err(|e| eyre::eyre!("landlock: {e}"))?;
    }
    let created = ruleset
        .create()
        .map_err(|e| eyre::eyre!("landlock: this kernel cannot enforce the build jail: {e}"))?;
    // Grant only the ordinary character devices, never the whole /dev tree.
    let devices = ["/dev/null", "/dev/zero", "/dev/random", "/dev/urandom"].map(PathBuf::from);
    // Never grant /, /home, /etc, /proc, /run, or a shared temporary tree.
    // These paths supply compilers, makepkg, DNS, TLS and package metadata,
    // without exposing credentials or another process's environment.
    let runtime = [
        "/usr",
        "/bin",
        "/sbin",
        "/lib",
        "/lib64",
        "/etc/ld.so.cache",
        "/etc/ld.so.conf",
        "/etc/ld.so.conf.d",
        "/etc/passwd",
        "/etc/group",
        "/etc/nsswitch.conf",
        "/etc/hosts",
        "/etc/resolv.conf",
        "/etc/gai.conf",
        "/etc/ssl/certs",
        "/etc/ssl/openssl.cnf",
        "/etc/ssl/cert.pem",
        "/etc/ca-certificates",
        "/etc/localtime",
        "/etc/os-release",
        "/etc/arch-release",
        "/etc/makepkg.conf",
        "/etc/makepkg.conf.d",
        "/etc/pacman.conf",
        "/etc/pacman.d/mirrorlist",
        "/var/lib/pacman/local",
        "/proc/cpuinfo",
        "/proc/meminfo",
    ]
    .map(PathBuf::from);
    let config = Path::new(alpm_db::conf::DEFAULT_PATH);
    let inputs = if config.exists() {
        pacman_inputs(config)?
    } else {
        PacmanInputs::default()
    };
    let reads: Vec<&Path> = runtime
        .iter()
        .chain(readable)
        .chain(&inputs.files)
        .chain(&devices)
        .map(PathBuf::as_path)
        .filter(|p| p.exists())
        .collect();
    let existing: Vec<&Path> = writable
        .iter()
        .map(PathBuf::as_path)
        .filter(|p| p.exists())
        .collect();
    let devices: Vec<&Path> = devices
        .iter()
        .map(PathBuf::as_path)
        .filter(|p| p.exists())
        .collect();
    let status = created
        .add_rules(path_beneath_rules(&reads, AccessFs::from_read(abi)))
        .map_err(|e| eyre::eyre!("landlock: {e}"))?
        // glob(3) must list include directories, but this grants no file
        // contents beneath them (notably pacman's private signing keys).
        .add_rules(path_beneath_rules(&inputs.directories, AccessFs::ReadDir))
        .map_err(|e| eyre::eyre!("landlock: {e}"))?
        .add_rules(path_beneath_rules(&existing, AccessFs::from_all(abi)))
        .map_err(|e| eyre::eyre!("landlock: {e}"))?
        .add_rules(path_beneath_rules(
            &devices,
            AccessFs::WriteFile | AccessFs::Truncate,
        ))
        .map_err(|e| eyre::eyre!("landlock: {e}"))?
        .restrict_self()
        .map_err(|e| eyre::eyre!("landlock: {e}"))?;
    if status.ruleset != RulesetStatus::FullyEnforced {
        bail!(
            "landlock: the build jail is {:?}, refusing to build unjailed",
            status.ruleset
        );
    }
    Ok(())
}

#[derive(Default)]
struct PacmanInputs {
    files: Vec<PathBuf>,
    directories: Vec<PathBuf>,
}

/// Follow pacman's actual Include graph instead of exposing /etc/pacman.d.
fn pacman_inputs(path: &Path) -> Result<PacmanInputs> {
    use alpm_db::conf::{Config, FsLoader, Loader};
    use std::cell::RefCell;
    #[derive(Default)]
    struct TrackingLoader {
        fs: FsLoader,
        inputs: RefCell<PacmanInputs>,
    }
    impl Loader for TrackingLoader {
        fn read(&self, path: &Path) -> std::io::Result<String> {
            let text = self.fs.read(path)?;
            self.inputs.borrow_mut().files.push(path.to_path_buf());
            Ok(text)
        }
        fn expand(&self, pattern: &str) -> Vec<PathBuf> {
            let paths = self.fs.expand(pattern);
            let mut inputs = self.inputs.borrow_mut();
            for path in &paths {
                if let Some(parent) = path.parent() {
                    inputs.directories.push(parent.to_path_buf());
                }
            }
            paths
        }
    }
    let loader = TrackingLoader::default();
    Config::load_with(path, &loader)
        .wrap_err("reading pacman's build-time configuration inputs")?;
    let mut inputs = loader.inputs.into_inner();
    inputs.files.sort();
    inputs.files.dedup();
    inputs.directories.sort();
    inputs.directories.dedup();
    Ok(inputs)
}

fn deny_inet_sockets() -> Result<()> {
    use seccompiler::{
        SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter,
        SeccompRule, TargetArch,
    };
    let families = [libc::AF_INET, libc::AF_INET6, libc::AF_PACKET];
    let rules: Vec<SeccompRule> = families
        .iter()
        .map(|family| {
            SeccompRule::new(vec![
                SeccompCondition::new(0, SeccompCmpArgLen::Dword, SeccompCmpOp::Eq, *family as u64)
                    .map_err(|e| eyre::eyre!("seccomp: {e}"))?,
            ])
            .map_err(|e| eyre::eyre!("seccomp: {e}"))
        })
        .collect::<Result<_>>()?;
    let mut map = BTreeMap::new();
    map.insert(libc::SYS_socket, rules);
    let arch =
        TargetArch::try_from(std::env::consts::ARCH).map_err(|e| eyre::eyre!("seccomp: {e}"))?;
    let filter = SeccompFilter::new(
        map,
        SeccompAction::Allow,
        SeccompAction::Errno(libc::EPERM as u32),
        arch,
    )
    .map_err(|e| eyre::eyre!("seccomp: {e}"))?;
    let program: seccompiler::BpfProgram =
        filter.try_into().map_err(|e| eyre::eyre!("seccomp: {e}"))?;
    seccompiler::apply_filter(&program)
        .map_err(|e| eyre::eyre!("seccomp: this kernel cannot enforce the network deny: {e}"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pacman_include_graph_excludes_unrelated_files_and_private_keys() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("pacman.conf");
        let includes = dir.path().join("pacman.d");
        std::fs::create_dir_all(includes.join("gnupg")).unwrap();
        let mirror = includes.join("mirrorlist");
        std::fs::write(&mirror, "Server = https://example.invalid/$repo/$arch\n").unwrap();
        let repo = includes.join("custom.conf");
        std::fs::write(&repo, format!("[custom]\nInclude = {}\n", mirror.display())).unwrap();
        std::fs::write(includes.join("gnupg/private.key"), "fake secret").unwrap();
        std::fs::write(
            &config,
            format!(
                "[options]\nArchitecture = x86_64\nInclude = {}/*.conf\n",
                includes.display()
            ),
        )
        .unwrap();
        let inputs = pacman_inputs(&config).unwrap();
        assert_eq!(inputs.files.len(), 3);
        for expected in [&config, &repo, &mirror] {
            assert!(inputs.files.contains(expected));
        }
        assert_eq!(inputs.directories, vec![includes]);
    }

    #[test]
    fn sensitive_names() {
        for name in [
            "GITHUB_TOKEN",
            "npm_token",
            "AWS_SECRET_ACCESS_KEY",
            "SSH_AUTH_SOCK",
            "DISPLAY",
            "XAUTHORITY",
            "WAYLAND_DISPLAY",
            "XDG_RUNTIME_DIR",
            "MISE_GITHUB_TOKEN",
            "MY_API_KEY",
            "OPENAI_ORG",
        ] {
            assert!(is_sensitive(name), "{name}");
        }
        for name in ["PATH", "HOME", "MAKEFLAGS", "PKGDEST", "LANG", "TERM"] {
            assert!(!is_sensitive(name), "{name}");
        }
        assert!(!scrubbed_env().keys().any(|k| is_sensitive(k)));
    }

    #[test]
    fn spec_round_trips() {
        let spec = Spec {
            readable: vec![],
            writable: vec![PathBuf::from("/tmp/x")],
            network: false,
            program: PathBuf::from("/usr/bin/makepkg"),
            args: vec!["--noextract".into()],
            cwd: PathBuf::from("/tmp/x"),
        };
        let json = serde_json::to_string(&spec).unwrap();
        assert_eq!(serde_json::from_str::<Spec>(&json).unwrap(), spec);
    }
}
