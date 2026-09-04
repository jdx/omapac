//! The declarative commands: `plan`, `apply`, `status`, `add`, `drop`.

use std::io::Write as _;

use eyre::{Result, bail};
use usage_rs::RunWith;

use super::converge::{Action, Diff, RunOpts};
use super::{App, print_json};
use crate::engine::Engine;
use crate::manifest::{Manifest, ManifestPaths, PackageToml, Source, State, edit};

impl App {
    /// Where this machine's manifest layers live.
    pub fn manifest_paths(&self) -> ManifestPaths {
        ManifestPaths::conventional(self.paths.sysroot.as_deref())
    }

    /// The merged manifest.
    pub fn manifest(&self) -> Result<Manifest> {
        Manifest::load(&self.manifest_paths())
    }
}

/// Show what `apply` would change
///
/// Compares every declared package with the local database and lists the
/// installs and removals, with the file each declaration came from.
#[derive(Debug, usage_rs::Args)]
pub struct Plan {
    /// Print as JSON
    #[usage(short = 'J', long)]
    json: bool,
    /// Exit 2 when there are changes, 0 when there are none
    #[usage(long)]
    detailed_exitcode: bool,
}

impl RunWith<&App> for Plan {
    type Output = Result<()>;

    fn run_with(self, app: &App) -> Self::Output {
        let host = app.host()?;
        let manifest = app.manifest()?;
        let diff = Diff::compute(&host, &manifest)?;
        if self.json {
            print_json(&diff)?;
        } else {
            print!("{}", diff.render());
        }
        if self.detailed_exitcode && diff.has_changes() {
            std::io::stdout().flush()?;
            std::process::exit(2);
        }
        Ok(())
    }
}

/// Make the machine match the manifest
///
/// Installs what is declared present and missing, then removes what is
/// declared absent and installed. Each transaction is shown and confirmed
/// like `install` and `remove`.
#[derive(Debug, usage_rs::Args)]
pub struct Apply {
    /// Proceed without asking; refuses a plan with warnings
    #[usage(short = 'y', long)]
    yes: bool,
    /// Show the plan and the commands, run nothing
    #[usage(short = 'n', long)]
    dry_run: bool,
}

impl RunWith<&App> for Apply {
    type Output = Result<()>;

    fn run_with(self, app: &App) -> Self::Output {
        let host = app.host()?;
        let manifest = app.manifest()?;
        let diff = Diff::compute(&host, &manifest)?;
        print!("{}", diff.render());
        if !diff.has_changes() {
            if !self.dry_run {
                diff.record_noops(app, &host, "apply")?;
            }
            return Ok(());
        }
        let engine = app.engine()?;
        let mut committed = false;
        diff.apply(
            app,
            &host,
            &manifest,
            &engine,
            RunOpts {
                by: "apply",
                yes: self.yes,
                dry_run: self.dry_run,
            },
            &mut committed,
        )
    }
}

/// Show every declared package and whether the machine matches
#[derive(Debug, usage_rs::Args)]
pub struct Status {
    /// Only declarations the machine does not match
    #[usage(long)]
    missing: bool,
    /// Print as JSON
    #[usage(short = 'J', long)]
    json: bool,
}

impl RunWith<&App> for Status {
    type Output = Result<()>;

    fn run_with(self, app: &App) -> Self::Output {
        let host = app.host()?;
        let manifest = app.manifest()?;
        let mut diff = Diff::compute(&host, &manifest)?;
        if self.missing {
            diff.steps.retain(|s| s.action != Action::Noop);
        }
        if self.json {
            return print_json(&diff);
        }
        if self.missing && diff.steps.is_empty() {
            println!("nothing missing");
        } else {
            print!("{}", diff.render());
        }
        if !manifest.layers.is_empty() {
            println!(
                "layers: {}",
                manifest
                    .layers
                    .iter()
                    .map(|p| p.display().to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
        if !manifest.managed.is_empty() {
            println!(
                "managed: {}",
                manifest
                    .managed
                    .iter()
                    .map(|p| p.display().to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
        Ok(())
    }
}

/// Declare packages in your manifest, then install them
///
/// Writes to the user manifest and converges only the packages named,
/// so other declarations are left for `apply`.
#[derive(Debug, usage_rs::Args)]
pub struct Add {
    /// Package names, optionally as repo/name
    #[usage(required = true)]
    packages: Vec<String>,
    /// Declare the packages absent, and remove them if installed
    #[usage(long)]
    absent: bool,
    /// Declare the packages as coming from the AUR
    #[usage(long)]
    aur: bool,
    /// Never upgrade the packages
    #[usage(long)]
    hold: bool,
    /// Proceed without asking; refuses a plan with warnings
    #[usage(short = 'y', long)]
    yes: bool,
    /// Update the manifest and show what would run, run nothing
    #[usage(short = 'n', long)]
    dry_run: bool,
}

impl RunWith<&App> for Add {
    type Output = Result<()>;

    fn run_with(self, app: &App) -> Self::Output {
        let paths = app.manifest_paths();
        let previous = match std::fs::read(&paths.user) {
            Ok(bytes) => Some(bytes),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => None,
            Err(err) => return Err(err.into()),
        };
        let mut declared = Vec::new();
        let mut committed = false;
        let result = (|| {
            let mut names = Vec::new();
            for spec in &self.packages {
                let (repo, name) = match spec.split_once('/') {
                    Some((repo, name)) if !self.aur => (Some(repo.to_string()), name.to_string()),
                    Some(_) => bail!("{spec}: repo/name does not apply with --aur"),
                    None => (None, spec.clone()),
                };
                let package = PackageToml {
                    source: if self.aur { Source::Aur } else { Source::Repo },
                    repo,
                    state: if self.absent {
                        State::Absent
                    } else {
                        State::Present
                    },
                    hold: self.hold,
                };
                edit::set_package(&paths.user, &name, &package)?;
                declared.push(name.clone());
                names.push(name);
            }
            let host = app.host()?;
            let manifest = app.manifest()?;
            let diff = Diff::compute(&host, &manifest)?.restricted_to(&names);
            if !diff.has_changes() {
                print!("{}", diff.render());
                if !self.dry_run {
                    diff.record_noops(app, &host, "add")?;
                }
                return Ok(());
            }
            let engine = app.engine()?;
            diff.apply(
                app,
                &host,
                &manifest,
                &engine,
                RunOpts {
                    by: "add",
                    yes: self.yes,
                    dry_run: self.dry_run,
                },
                &mut committed,
            )
        })();
        if let Err(err) = result {
            if committed {
                for name in declared {
                    println!("declared {name} in {}", paths.user.display());
                }
                return Err(err);
            }
            let restore = match previous {
                Some(bytes) => std::fs::write(&paths.user, bytes),
                None => std::fs::remove_file(&paths.user),
            };
            if let Err(restore_err) = restore
                && restore_err.kind() != std::io::ErrorKind::NotFound
            {
                return Err(eyre::eyre!(
                    "{err:#}; restoring {}: {restore_err}",
                    paths.user.display()
                ));
            }
            return Err(err);
        }
        for name in declared {
            println!("declared {name} in {}", paths.user.display());
        }
        Ok(())
    }
}

/// Remove packages from your manifest, then from the machine
///
/// Deletes the entries from the user manifest. A package that no lower
/// layer still declares present is then removed if installed; one the
/// distro layer declares stays, since dropping it means "back to the
/// default".
#[derive(Debug, usage_rs::Args)]
pub struct Drop {
    /// Package names
    #[usage(required = true)]
    packages: Vec<String>,
    /// Proceed without asking; refuses a plan with warnings
    #[usage(short = 'y', long)]
    yes: bool,
    /// Update the manifest and show what would run, run nothing
    #[usage(short = 'n', long)]
    dry_run: bool,
}

impl RunWith<&App> for Drop {
    type Output = Result<()>;

    fn run_with(self, app: &App) -> Self::Output {
        let paths = app.manifest_paths();
        let mut packages = Vec::new();
        for spec in &self.packages {
            let target: crate::engine::Target = spec.parse().expect("target parsing is infallible");
            if !packages
                .iter()
                .any(|existing: &crate::engine::Target| existing.name == target.name)
            {
                packages.push(target);
            }
        }
        for target in &packages {
            let name = &target.name;
            if edit::remove_package(&paths.user, name)? {
                println!("removed {name} from {}", paths.user.display());
            } else {
                println!("{name} was not declared in {}", paths.user.display());
            }
        }
        let host = app.host()?;
        let manifest = app.manifest()?;
        let ledger = (!self.dry_run).then(|| app.ledger()).transpose()?;
        let mut removals = Vec::new();
        let mut stale = Vec::new();
        for target in &packages {
            let name = &target.name;
            // Still declared present by a lower layer: keep it.
            if manifest
                .declared(name)
                .is_some_and(|d| d.package.state == State::Present)
            {
                continue;
            }
            if host.installed_package(name)?.is_some() {
                removals.push(name.clone());
            } else if ledger
                .as_ref()
                .is_some_and(|ledger| ledger.packages.contains_key(name))
            {
                stale.push(name.clone());
            }
        }
        if removals.is_empty() {
            println!("nothing to remove");
            if !stale.is_empty() {
                app.record(&crate::ledger::Patch {
                    remove: stale,
                    ..Default::default()
                })?;
            }
            return Ok(());
        }
        let engine = app.engine()?;
        let mut tx = crate::engine::Transaction::remove(removals);
        if let crate::engine::Operation::Remove { recursive, .. } = &mut tx.operation {
            *recursive = false;
        }
        let resolved = engine.plan(&tx)?;
        let mut plan = super::transaction::plan(
            &host,
            &resolved,
            engine
                .apply_invocation(
                    &tx,
                    crate::engine::ApplyOpts {
                        dry_run: true,
                        no_confirm: false,
                    },
                )
                .display(),
        );
        plan.command = engine
            .apply_invocation(
                &tx,
                crate::engine::ApplyOpts {
                    dry_run: true,
                    no_confirm: super::transaction::apply_no_confirm(&plan, self.yes),
                },
            )
            .display();
        let performed = super::transaction::confirm_and_apply(
            &engine,
            &resolved,
            &plan,
            "remove",
            self.yes,
            self.dry_run,
        )?;
        if !self.dry_run {
            let mut patch = if performed {
                super::transaction::ledger_patch(&plan, &[], "drop", true)
            } else {
                Default::default()
            };
            patch.remove.extend(stale);
            app.record(&patch)?;
        }
        Ok(())
    }
}
