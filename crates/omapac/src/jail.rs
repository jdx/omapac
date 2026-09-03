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
    /// Directories the command may write under. Everything else is
    /// read-only.
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
        let exe = std::env::current_exe().wrap_err("locating omapac")?;
        let mut command = Command::new(exe);
        command.arg("__jail");
        command.env_clear();
        command.envs(scrubbed_env());
        command.stdin(std::process::Stdio::piped());
        Ok(command)
    }

    /// Run through the helper with inherited stdout and stderr.
    pub fn run(&self) -> Result<std::process::ExitStatus> {
        let mut child = self
            .command()?
            .spawn()
            .wrap_err("starting the jail helper")?;
        if let Some(mut stdin) = child.stdin.take() {
            serde_json::to_writer(&mut stdin, self).wrap_err("sending the jail spec")?;
        }
        child.wait().wrap_err("waiting for the jailed command")
    }

    /// Restrict the current process as the spec says. Called by the helper.
    pub fn apply(&self) -> Result<()> {
        restrict_filesystem(&self.writable, self.network)?;
        if !self.network {
            deny_inet_sockets()?;
        }
        Ok(())
    }
}

fn restrict_filesystem(writable: &[PathBuf], network: bool) -> Result<()> {
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
        .add_rules(path_beneath_rules(&["/"], AccessFs::from_read(abi)))
        .map_err(|e| eyre::eyre!("landlock: {e}"))?
        .add_rules(path_beneath_rules(&existing, AccessFs::from_all(abi)))
        .map_err(|e| eyre::eyre!("landlock: {e}"))?
        .add_rules(path_beneath_rules(&devices, AccessFs::WriteFile))
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
