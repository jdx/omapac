//! Manifest convergence shared by `plan`, `apply`, `status`, `add`, and
//! `drop`: compare what is declared with what is installed and turn the
//! difference into engine transactions.

use std::fmt::Write as _;

use eyre::{Result, bail};
use serde::Serialize;

use super::transaction;
use crate::engine::{Engine, Operation, Target, Transaction};
use crate::host::Host;
use crate::manifest::{Manifest, Source, State};

/// What one declaration needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Action {
    /// Declared present and installed, or declared absent and not.
    Noop,
    Install,
    Remove,
    /// Declared present from the AUR; needs the review flow.
    NeedsAur,
    /// Declared present but no repository carries it.
    Unavailable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Step {
    pub name: String,
    pub action: Action,
    pub state: State,
    pub source: Source,
    pub repo: Option<String>,
    pub hold: bool,
    pub installed: Option<String>,
    pub declared_in: String,
}

/// The difference between the manifest and the machine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Diff {
    pub steps: Vec<Step>,
}

impl Diff {
    pub fn compute(host: &Host, manifest: &Manifest) -> Result<Diff> {
        let mut steps = Vec::new();
        for declared in manifest.packages.values() {
            let installed = host
                .installed_package(&declared.name)?
                .map(|p| p.version.clone());
            let package = &declared.package;
            let action = match (package.state, installed.is_some()) {
                (State::Present, true) | (State::Absent, false) => Action::Noop,
                (State::Absent, true) => Action::Remove,
                (State::Present, false) => match package.source {
                    Source::Aur => Action::NeedsAur,
                    Source::Repo => {
                        let found = match &package.repo {
                            Some(repo) => host.find_sync_in(repo, &declared.name)?.is_some(),
                            None => host.find_sync(&declared.name)?.is_some(),
                        };
                        if found {
                            Action::Install
                        } else {
                            Action::Unavailable
                        }
                    }
                },
            };
            steps.push(Step {
                name: declared.name.clone(),
                action,
                state: package.state,
                source: package.source,
                repo: package.repo.clone(),
                hold: package.hold,
                installed,
                declared_in: declared.declared_in.display().to_string(),
            });
        }
        Ok(Diff { steps })
    }

    /// Only the steps matching `names`, for `add` and `drop`.
    pub fn restricted_to(mut self, names: &[String]) -> Diff {
        self.steps.retain(|s| names.contains(&s.name));
        self
    }

    pub fn has_changes(&self) -> bool {
        self.steps.iter().any(|s| s.action != Action::Noop)
    }

    fn installs(&self) -> Vec<Target> {
        self.steps
            .iter()
            .filter(|s| s.action == Action::Install)
            .map(|s| Target {
                repo: s.repo.clone(),
                name: s.name.clone(),
            })
            .collect()
    }

    fn removes(&self) -> Vec<String> {
        self.steps
            .iter()
            .filter(|s| s.action == Action::Remove)
            .map(|s| s.name.clone())
            .collect()
    }

    /// Render for a human.
    pub fn render(&self) -> String {
        let mut out = String::new();
        if self.steps.is_empty() {
            let _ = writeln!(out, "nothing declared");
            return out;
        }
        let width = self.steps.iter().map(|s| s.name.len()).max().unwrap_or(0);
        for step in &self.steps {
            let mark = match step.action {
                Action::Noop => " ",
                Action::Install => "+",
                Action::Remove => "-",
                Action::NeedsAur | Action::Unavailable => "!",
            };
            let detail = match step.action {
                Action::Noop => match (&step.installed, step.state) {
                    (Some(v), _) => format!("installed {v}"),
                    (None, _) => "absent".to_string(),
                },
                Action::Install => match &step.repo {
                    Some(repo) => format!("install from {repo}"),
                    None => "install".to_string(),
                },
                Action::Remove => {
                    format!("remove {}", step.installed.as_deref().unwrap_or_default())
                }
                Action::NeedsAur => "needs the AUR review flow (not in this build)".to_string(),
                Action::Unavailable => "not in any repository".to_string(),
            };
            let hold = if step.hold { " (hold)" } else { "" };
            let _ = writeln!(
                out,
                "{mark} {:<width$}  {detail}{hold}  <- {}",
                step.name, step.declared_in
            );
        }
        let installs = self.installs().len();
        let removes = self.removes().len();
        let _ = writeln!(out, "\n{installs} to install, {removes} to remove");
        out
    }

    /// Apply the diff: one install transaction, then one remove
    /// transaction, each shown and confirmed like `install` and `remove`.
    pub fn apply(
        &self,
        host: &Host,
        manifest: &Manifest,
        engine: &crate::engine::pacman::PacmanCli,
        yes: bool,
        dry_run: bool,
    ) -> Result<()> {
        let unavailable: Vec<&str> = self
            .steps
            .iter()
            .filter(|s| s.action == Action::Unavailable)
            .map(|s| s.name.as_str())
            .collect();
        if !unavailable.is_empty() {
            bail!("declared but in no repository: {}", unavailable.join(", "));
        }
        let installs = self.installs();
        if !installs.is_empty() {
            let mut tx = Transaction::install(installs)
                .ignoring(
                    manifest.settings.update_ignore.iter().cloned().chain(
                        self.steps
                            .iter()
                            .filter(|step| step.hold)
                            .map(|step| step.name.clone()),
                    ),
                )
                .overwriting(manifest.settings.update_overwrite.iter().cloned());
            tx.ignore_group
                .extend(manifest.settings.update_ignore_group.iter().cloned());
            run(host, engine, tx, "install", yes, dry_run)?;
        }
        let removes = self.removes();
        if !removes.is_empty() {
            let mut tx = Transaction::remove(removes);
            if let Operation::Remove { recursive, .. } = &mut tx.operation {
                *recursive = false;
            }
            run(host, engine, tx, "remove", yes, dry_run)?;
        }
        let aur: Vec<&str> = self
            .steps
            .iter()
            .filter(|s| s.action == Action::NeedsAur)
            .map(|s| s.name.as_str())
            .collect();
        if !aur.is_empty() {
            eprintln!(
                "warning: skipped AUR package(s) {}: the review flow is not in this build",
                aur.join(", ")
            );
        }
        Ok(())
    }
}

fn run(
    host: &Host,
    engine: &crate::engine::pacman::PacmanCli,
    tx: Transaction,
    verb: &str,
    yes: bool,
    dry_run: bool,
) -> Result<()> {
    let resolved = engine.plan(&tx)?;
    let command = engine
        .apply_invocation(
            &tx,
            crate::engine::ApplyOpts {
                dry_run: true,
                no_confirm: true,
            },
        )
        .display();
    let plan = transaction::plan(host, &resolved, command);
    transaction::confirm_and_apply(engine, &resolved, &plan, verb, yes, dry_run)
}
