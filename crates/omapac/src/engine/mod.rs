//! The transaction engine: the seam between omapac and whatever performs
//! package transactions on disk.
//!
//! Today that is pacman, driven through its command line by
//! [`pacman::PacmanCli`]. Later it is a native implementation. Everything
//! above this module speaks in [`Transaction`] and [`ResolvedTx`] and never
//! in pacman flags, so the swap is a new `impl Engine`, not a rewrite. See
//! `PLAN.md`, "Engine trait".

pub mod pacman;
pub mod sudo;

use std::fmt;
use std::path::PathBuf;
use std::str::FromStr;

/// A package to sync, optionally pinned to a repository (`repo/name`).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Target {
    pub repo: Option<String>,
    pub name: String,
}

impl Target {
    pub fn named(name: impl Into<String>) -> Target {
        Target {
            repo: None,
            name: name.into(),
        }
    }
}

impl FromStr for Target {
    type Err = std::convert::Infallible;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Ok(match s.split_once('/') {
            Some((repo, name)) if !repo.is_empty() => Target {
                repo: Some(repo.to_string()),
                name: name.to_string(),
            },
            _ => Target::named(s),
        })
    }
}

impl fmt::Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.repo {
            Some(repo) => write!(f, "{repo}/{}", self.name),
            None => f.write_str(&self.name),
        }
    }
}

/// What a transaction does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Operation {
    /// Install or reinstall packages from sync databases.
    Install {
        targets: Vec<Target>,
        /// Skip targets that are already installed at the current version.
        needed: bool,
        /// Record the targets as dependencies rather than explicit installs.
        as_deps: bool,
    },
    /// Remove installed packages.
    Remove {
        targets: Vec<String>,
        /// Also remove dependencies that nothing else needs.
        recursive: bool,
        /// Also remove packages that depend on the targets.
        cascade: bool,
        /// Do not keep `.pacsave` copies of configuration files.
        nosave: bool,
        /// Only remove targets nothing else depends on.
        unneeded: bool,
    },
    /// Upgrade every installed package that a sync database has newer.
    Upgrade {
        /// Also move to older versions the databases carry.
        allow_downgrade: bool,
    },
}

/// A transaction request, independent of any engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transaction {
    pub operation: Operation,
    /// Packages to leave alone during an upgrade.
    pub ignore: Vec<String>,
    /// Package groups to leave alone during an upgrade.
    pub ignore_group: Vec<String>,
    /// File globs that a package may overwrite.
    pub overwrite: Vec<String>,
}

impl Transaction {
    pub fn new(operation: Operation) -> Transaction {
        Transaction {
            operation,
            ignore: Vec::new(),
            ignore_group: Vec::new(),
            overwrite: Vec::new(),
        }
    }

    pub fn install(targets: Vec<Target>) -> Transaction {
        Transaction::new(Operation::Install {
            targets,
            needed: true,
            as_deps: false,
        })
    }

    pub fn remove(targets: Vec<String>) -> Transaction {
        Transaction::new(Operation::Remove {
            targets,
            recursive: true,
            cascade: false,
            nosave: false,
            unneeded: false,
        })
    }

    pub fn upgrade() -> Transaction {
        Transaction::new(Operation::Upgrade {
            allow_downgrade: false,
        })
    }

    pub fn ignoring(mut self, packages: impl IntoIterator<Item = String>) -> Transaction {
        self.ignore.extend(packages);
        self
    }

    pub fn overwriting(mut self, globs: impl IntoIterator<Item = String>) -> Transaction {
        self.overwrite.extend(globs);
        self
    }
}

/// One package a resolved transaction touches.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Change {
    pub name: String,
    pub version: String,
    /// The repository the package comes from; `local` for removals.
    pub repo: Option<String>,
    /// Where the package file is fetched from.
    pub location: Option<String>,
    /// Download size in bytes, when the engine knows it.
    pub download_size: Option<u64>,
}

/// A transaction the engine has resolved: the exact packages it would touch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedTx {
    pub transaction: Transaction,
    pub changes: Vec<Change>,
}

impl ResolvedTx {
    pub fn is_empty(&self) -> bool {
        self.changes.is_empty()
    }
}

/// Package files to install directly (`pacman -U`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileInstall {
    pub files: Vec<PathBuf>,
    pub as_deps: bool,
    /// Skip dependency checks for a temporary split-package bootstrap.
    pub nodeps: bool,
    pub overwrite: Vec<String>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RefreshOpts {
    /// Re-download databases even when they look current.
    pub force: bool,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ApplyOpts {
    /// Print what would run and run nothing.
    pub dry_run: bool,
    /// Answer every engine prompt with its default.
    pub no_confirm: bool,
}

/// What an engine did, or would have done.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    /// The command line, rendered for humans.
    pub command: String,
    /// Whether anything ran. `false` on a dry run.
    pub performed: bool,
}

/// Why an engine call failed.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    NotAvailable(String),
    #[error("{0}")]
    Elevation(String),
    #[error("`{command}` exited with status {status}{}", stderr_suffix(.stderr))]
    Command {
        command: String,
        status: i32,
        stderr: String,
    },
    #[error("could not parse engine output: {0}")]
    Parse(String),
    #[error("could not run `{command}`")]
    Io {
        command: String,
        #[source]
        source: std::io::Error,
    },
}

fn stderr_suffix(stderr: &str) -> String {
    let stderr = stderr.trim();
    if stderr.is_empty() {
        String::new()
    } else {
        format!(":\n{stderr}")
    }
}

pub type Result<T> = std::result::Result<T, Error>;

/// Something that performs package transactions.
pub trait Engine {
    /// A short name for messages, such as `pacman`.
    fn name(&self) -> &str;

    /// Refresh sync databases.
    fn refresh(&self, opts: RefreshOpts, apply: ApplyOpts) -> Result<Report>;

    /// Resolve a transaction without performing it. Never elevates and
    /// never changes anything.
    fn plan(&self, tx: &Transaction) -> Result<ResolvedTx>;

    /// Perform a resolved transaction.
    fn apply(&self, tx: &ResolvedTx, opts: ApplyOpts) -> Result<Report>;

    /// Install package files directly, for locally built packages.
    fn install_files(&self, install: &FileInstall, opts: ApplyOpts) -> Result<Report>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn targets_parse_and_display() {
        let plain: Target = "helix".parse().unwrap();
        assert_eq!(plain, Target::named("helix"));
        assert_eq!(plain.to_string(), "helix");
        let pinned: Target = "extra/helix".parse().unwrap();
        assert_eq!(pinned.repo.as_deref(), Some("extra"));
        assert_eq!(pinned.to_string(), "extra/helix");
        let odd: Target = "/helix".parse().unwrap();
        assert_eq!(odd.repo, None);
        assert_eq!(odd.name, "/helix");
    }

    #[test]
    fn command_errors_render_stderr_when_present() {
        let err = Error::Command {
            command: "pacman -S x".into(),
            status: 1,
            stderr: "error: target not found: x\n".into(),
        };
        assert_eq!(
            err.to_string(),
            "`pacman -S x` exited with status 1:\nerror: target not found: x"
        );
        let quiet = Error::Command {
            command: "pacman -S x".into(),
            status: 1,
            stderr: String::new(),
        };
        assert_eq!(quiet.to_string(), "`pacman -S x` exited with status 1");
    }
}
