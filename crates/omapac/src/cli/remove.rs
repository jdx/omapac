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
    /// Package names; or none with --pick
    packages: Vec<String>,
    /// Choose explicitly installed packages in a picker
    #[usage(short = 'p', long)]
    pick: bool,
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

    fn run_with(mut self, app: &App) -> Self::Output {
        let host = app.host()?;
        if self.pick {
            crate::tui::require_terminal("remove --pick")?;
            let mut installed: Vec<&alpm_db::local::LocalPackage> = host
                .installed()?
                .iter()
                .filter(|p| p.reason == alpm_db::local::InstallReason::Explicit)
                .collect();
            installed.sort_by(|a, b| a.name.cmp(&b.name));
            let items: Vec<crate::tui::Item> = installed
                .iter()
                .map(|p| {
                    crate::tui::Item::new(
                        p.name.clone(),
                        format!("{}  {}", p.version, p.desc.as_deref().unwrap_or_default()),
                        "explicit",
                    )
                })
                .collect();
            let Some(chosen) = crate::tui::pick("Remove", items, true)? else {
                eprintln!("nothing chosen");
                return Ok(());
            };
            self.packages = chosen.iter().map(|&i| installed[i].name.clone()).collect();
        }
        if self.packages.is_empty() {
            bail!("give package names, or --pick to choose from installed packages");
        }
        let ledger = app.ledger()?;
        let mut not_installed = Vec::new();
        let mut packages = Vec::new();
        for name in &self.packages {
            if host.installed_package(name)?.is_none() {
                if !ledger.packages.contains_key(name) {
                    not_installed.push(name.as_str());
                }
            } else {
                packages.push(name.clone());
            }
        }
        if !not_installed.is_empty() {
            bail!("not installed: {}", not_installed.join(", "));
        }
        if packages.is_empty() {
            if !self.dry_run && !self.json {
                app.record(&crate::ledger::Patch {
                    remove: self.packages,
                    ..Default::default()
                })?;
            }
            println!("nothing to remove");
            return Ok(());
        }
        let engine = app.engine()?;
        let mut tx = Transaction::remove(packages);
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
        let performed = transaction::confirm_and_apply(
            &engine,
            &resolved,
            &plan,
            "remove",
            self.yes,
            self.dry_run,
        )?;
        if performed {
            let mut patch = transaction::ledger_patch(&plan, &[], "remove", true);
            patch.remove.extend(
                self.packages
                    .into_iter()
                    .filter(|name| host.installed_package(name).ok().flatten().is_none()),
            );
            app.record(&patch)?;
        }
        Ok(())
    }
}
