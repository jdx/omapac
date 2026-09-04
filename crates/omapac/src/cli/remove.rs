use eyre::{Result, bail};
use usage_rs::RunWith;

use super::transaction::{self, Plan};
use super::{App, print_json};
use crate::engine::{Engine, Operation, Transaction};

/// Remove installed packages
///
/// Dependencies nothing else needs are removed too, like `pacman -Rs`,
/// unless `--keep-deps` is given. The plan shows everything that would go
/// before anything happens.
#[derive(Debug, usage_rs::Args)]
pub struct Remove {
    /// Package names
    #[usage(required = true)]
    packages: Vec<String>,
    /// Proceed without asking; refuses a plan with warnings
    #[usage(short = 'y', long)]
    yes: bool,
    /// Show the plan and the command, run nothing
    #[usage(short = 'n', long)]
    dry_run: bool,
    /// Leave dependencies installed
    #[usage(long)]
    keep_deps: bool,
    /// Also remove packages that depend on the targets
    #[usage(long)]
    cascade: bool,
    /// Do not keep .pacsave copies of configuration files
    #[usage(long)]
    nosave: bool,
    /// Print the plan as JSON and run nothing
    #[usage(short = 'J', long)]
    json: bool,
}

impl RunWith<&App> for Remove {
    type Output = Result<()>;

    fn run_with(self, app: &App) -> Self::Output {
        let host = app.host()?;
        let mut not_installed = Vec::new();
        for name in &self.packages {
            if host.installed_package(name)?.is_none() {
                not_installed.push(name.as_str());
            }
        }
        if !not_installed.is_empty() {
            bail!("not installed: {}", not_installed.join(", "));
        }
        let engine = app.engine()?;
        let mut tx = Transaction::remove(self.packages.clone());
        if let Operation::Remove {
            recursive,
            cascade,
            nosave,
            ..
        } = &mut tx.operation
        {
            *recursive = !self.keep_deps;
            *cascade = self.cascade;
            *nosave = self.nosave;
        }
        let resolved = engine.plan(&tx)?;
        let mut plan: Plan = transaction::plan(&host, &resolved, String::new());
        plan.command = engine
            .apply_invocation(
                &tx,
                crate::engine::ApplyOpts {
                    dry_run: true,
                    no_confirm: transaction::apply_no_confirm(&plan, self.yes),
                },
            )
            .display();
        if self.json {
            return print_json(&plan);
        }
        transaction::confirm_and_apply(&engine, &resolved, &plan, "remove", self.yes, self.dry_run)
    }
}
