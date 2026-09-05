//! Elevation policy, following mise's `system/sudo.rs`: root runs a
//! command directly, an interactive user goes through `sudo` so the
//! password prompt works, and a non-interactive user goes through
//! `sudo -n` so a missing credential fails fast instead of hanging.
//!
//! Environment variables travel through `sudo env K=V`, which the default
//! sudoers policy allows where a bare `sudo K=V cmd` might not.

use std::io::IsTerminal;
use std::path::PathBuf;

use super::{Error, Result};

/// Whether a command may be elevated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Elevation {
    /// Elevate through sudo when not root.
    #[default]
    Auto,
    /// Never elevate; the command runs as the invoking user.
    Never,
}

/// What the policy needs to know about the process it runs in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Context {
    pub is_root: bool,
    pub interactive: bool,
    pub sudo: Option<PathBuf>,
    pub elevation: Elevation,
}

impl Context {
    /// Detect the current process's situation.
    pub fn detect(elevation: Elevation) -> Context {
        Context {
            is_root: nix::unistd::geteuid().is_root(),
            interactive: std::io::stdin().is_terminal() && std::io::stderr().is_terminal(),
            sudo: which::which("sudo").ok(),
            elevation,
        }
    }
}

/// A command ready to run: program, arguments, and extra environment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invocation {
    pub program: PathBuf,
    pub args: Vec<String>,
    pub env: Vec<(String, String)>,
}

impl Invocation {
    pub fn new(program: impl Into<PathBuf>, args: Vec<String>) -> Invocation {
        Invocation {
            program: program.into(),
            args,
            env: Vec::new(),
        }
    }

    pub fn with_env(mut self, key: &str, value: &str) -> Invocation {
        self.env.push((key.to_string(), value.to_string()));
        self
    }

    /// Wrap for the privileges the command needs, per the policy.
    pub fn elevated(self, ctx: &Context) -> Result<Invocation> {
        if ctx.is_root || ctx.elevation == Elevation::Never {
            return Ok(self);
        }
        let Some(sudo) = &ctx.sudo else {
            return Err(Error::Elevation(
                "this command needs root and sudo is not installed; run it as root".to_string(),
            ));
        };
        let mut args = Vec::new();
        if !ctx.interactive {
            args.push("-n".to_string());
        }
        if !self.env.is_empty() {
            args.push("env".to_string());
            for (key, value) in &self.env {
                args.push(format!("{key}={value}"));
            }
        }
        args.push(self.program.to_string_lossy().into_owned());
        args.extend(self.args);
        Ok(Invocation {
            program: sudo.clone(),
            args,
            env: Vec::new(),
        })
    }

    /// The command line as a user would type it.
    pub fn display(&self) -> String {
        let mut words = Vec::new();
        for (key, value) in &self.env {
            words.push(format!("{key}={}", quote(value)));
        }
        words.push(quote(&self.program.to_string_lossy()));
        words.extend(self.args.iter().map(|arg| quote(arg)));
        words.join(" ")
    }

    /// Build the process, with the environment applied.
    pub fn command(&self) -> std::process::Command {
        let mut command = std::process::Command::new(&self.program);
        command.args(&self.args);
        for (key, value) in &self.env {
            command.env(key, value);
        }
        command
    }
}

/// Quote a word for display, only when a shell would need it. `=` stays
/// bare so `env K=V` reads as typed.
pub(crate) fn quote(word: &str) -> String {
    let safe = |c: char| c.is_ascii_alphanumeric() || "_-./:@%+=,".contains(c);
    if !word.is_empty() && word.chars().all(safe) {
        word.to_string()
    } else {
        format!("'{}'", word.replace('\'', "'\\''"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx(is_root: bool, interactive: bool, sudo: bool) -> Context {
        Context {
            is_root,
            interactive,
            sudo: sudo.then(|| PathBuf::from("/usr/bin/sudo")),
            elevation: Elevation::Auto,
        }
    }

    fn pacman() -> Invocation {
        Invocation::new("/usr/bin/pacman", vec!["-S".into(), "helix".into()])
    }

    #[test]
    fn root_runs_directly() {
        let inv = pacman().elevated(&ctx(true, true, true)).unwrap();
        assert_eq!(inv.program, PathBuf::from("/usr/bin/pacman"));
        assert_eq!(inv.display(), "/usr/bin/pacman -S helix");
    }

    #[test]
    fn interactive_user_uses_sudo() {
        let inv = pacman().elevated(&ctx(false, true, true)).unwrap();
        assert_eq!(inv.display(), "/usr/bin/sudo /usr/bin/pacman -S helix");
    }

    #[test]
    fn non_interactive_user_uses_sudo_n() {
        let inv = pacman().elevated(&ctx(false, false, true)).unwrap();
        assert_eq!(inv.display(), "/usr/bin/sudo -n /usr/bin/pacman -S helix");
    }

    #[test]
    fn env_goes_through_env_under_sudo_and_directly_as_root() {
        let inv = pacman()
            .with_env("OMARCHY_UPDATE_PACMAN", "1")
            .elevated(&ctx(false, true, true))
            .unwrap();
        assert_eq!(
            inv.display(),
            "/usr/bin/sudo env OMARCHY_UPDATE_PACMAN=1 /usr/bin/pacman -S helix"
        );
        assert!(inv.env.is_empty());

        let inv = pacman()
            .with_env("OMARCHY_UPDATE_PACMAN", "1")
            .elevated(&ctx(true, true, true))
            .unwrap();
        assert_eq!(
            inv.display(),
            "OMARCHY_UPDATE_PACMAN=1 /usr/bin/pacman -S helix"
        );
        assert_eq!(
            inv.env,
            [("OMARCHY_UPDATE_PACMAN".to_string(), "1".to_string())]
        );
    }

    #[test]
    fn missing_sudo_is_an_error_and_never_means_never() {
        let err = pacman().elevated(&ctx(false, true, false)).unwrap_err();
        assert!(err.to_string().contains("sudo is not installed"));
        let mut never = ctx(false, false, false);
        never.elevation = Elevation::Never;
        let inv = pacman().elevated(&never).unwrap();
        assert_eq!(inv.display(), "/usr/bin/pacman -S helix");
    }

    #[test]
    fn quoting() {
        assert_eq!(quote("plain"), "plain");
        assert_eq!(quote("K=V"), "K=V");
        assert_eq!(quote("/usr/share/omarchy/*"), "'/usr/share/omarchy/*'");
        assert_eq!(quote("has space"), "'has space'");
        assert_eq!(quote("it's"), "'it'\\''s'");
        assert_eq!(quote(""), "''");
    }

    #[test]
    fn display_quotes_what_needs_quoting() {
        let inv = Invocation::new(
            "pacman",
            vec![
                "-S".into(),
                "--overwrite".into(),
                "/usr/share/omarchy/*".into(),
            ],
        );
        assert_eq!(
            inv.display(),
            "pacman -S --overwrite '/usr/share/omarchy/*'"
        );
    }
}
