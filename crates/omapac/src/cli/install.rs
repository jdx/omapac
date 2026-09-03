use eyre::{Result, bail};
use usage_rs::RunWith;

use super::transaction::{self, Plan};
use super::{App, print_json};
use crate::engine::pacman::PacmanCli;
use crate::engine::{Engine, Target, Transaction};
use crate::host::Host;

/// Install packages from the repositories
///
/// Each name is looked up in the sync databases in repository order, or
/// pinned with `repo/name`. The plan shows every package the transaction
/// would touch with its trust tier before anything happens. Nothing is
/// recorded in the manifest; see `add` for that.
#[derive(Debug, usage_rs::Args)]
pub struct Install {
    /// Package names, optionally as repo/name
    #[usage(required = true)]
    packages: Vec<String>,
    /// Proceed without asking; refuses a plan with warnings
    #[usage(short = 'y', long)]
    yes: bool,
    /// Show the plan and the command, run nothing
    #[usage(short = 'n', long)]
    dry_run: bool,
    /// Reinstall packages that are already installed
    #[usage(long)]
    reinstall: bool,
    /// Record the packages as dependencies rather than explicit installs
    #[usage(long)]
    as_deps: bool,
    /// Print the plan as JSON and run nothing
    #[usage(short = 'J', long)]
    json: bool,
}

impl RunWith<&App> for Install {
    type Output = Result<()>;

    fn run_with(self, app: &App) -> Self::Output {
        let host = app.host()?;
        let targets = resolve_targets(&host, &self.packages)?;
        let engine = app.engine()?;
        let mut tx = Transaction::install(targets);
        if let crate::engine::Operation::Install {
            needed, as_deps, ..
        } = &mut tx.operation
        {
            *needed = !self.reinstall;
            *as_deps = self.as_deps;
        }
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
        let plan: Plan = transaction::plan(&host, &resolved, command);
        if self.json {
            return print_json(&plan);
        }
        transaction::confirm_and_apply(&engine, &resolved, &plan, "install", self.yes, self.dry_run)
    }
}

/// Turn names into targets, refusing names no repository carries.
pub fn resolve_targets(host: &Host, names: &[String]) -> Result<Vec<Target>> {
    let mut targets = Vec::new();
    let mut unknown = Vec::new();
    for name in names {
        let target: Target = name.parse().expect("infallible");
        let found = match &target.repo {
            Some(repo) => host.find_sync_in(repo, &target.name)?.is_some(),
            None => host.find_sync(&target.name)?.is_some(),
        };
        if found {
            targets.push(target);
        } else {
            unknown.push(name.clone());
        }
    }
    if !unknown.is_empty() {
        bail!(
            "not in any repository: {}\nAUR packages need the review flow, which is not in this build yet",
            unknown.join(", ")
        );
    }
    Ok(targets)
}

impl App {
    /// The engine that performs transactions on this host.
    pub fn engine(&self) -> Result<PacmanCli> {
        let mut engine = PacmanCli::detect()?;
        engine.config = self.paths.config.clone();
        engine.sysroot = self.paths.sysroot.clone();
        Ok(engine)
    }
}
