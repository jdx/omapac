use std::fmt::Write as _;
use std::time::Duration;

use eyre::Result;
use serde::Serialize;
use usage_rs::RunWith;

use super::transaction::{self, Plan};
use super::{App, print_json};
use crate::engine::{ApplyOpts, Engine, Operation, RefreshOpts, Transaction};
use crate::update::{AurCandidate, Hold, age_holds, aur_candidates, pacnew_files, run_hooks};

/// Update the machine: repositories, then the AUR
///
/// Refreshes the sync databases, plans the repository upgrade with the
/// manifest's holds and the per-tier release-age floors, reviews every
/// AUR package that has a newer commit, shows one plan, and applies it.
/// Unattended (-y), a finding that denies skips that AUR package and the
/// rest continues. Ends with the orphan and pacnew reports.
#[derive(Debug, usage_rs::Args)]
pub struct Update {
    /// Proceed without asking; findings deny rather than warn
    #[usage(short = 'y', long)]
    yes: bool,
    /// Plan everything, run nothing
    #[usage(short = 'n', long)]
    dry_run: bool,
    /// Skip the AUR
    #[usage(long)]
    no_aur: bool,
    /// Only the AUR
    #[usage(long)]
    aur_only: bool,
    /// Do not refresh the sync databases first
    #[usage(long)]
    no_refresh: bool,
    /// Remove dependencies nothing needs any more
    #[usage(long)]
    prune_orphans: bool,
    /// Print the plan as JSON and run nothing
    #[usage(short = 'J', long)]
    json: bool,
}

#[derive(Debug, Serialize)]
pub struct UpdatePlan {
    pub repo: Option<Plan>,
    pub holds: Vec<Hold>,
    pub aur: Vec<AurCandidate>,
    pub orphans: Vec<String>,
    pub pacnew: Vec<String>,
}

impl RunWith<&App> for Update {
    type Output = Result<()>;

    fn run_with(self, app: &App) -> Self::Output {
        let manifest = app.manifest()?;
        let settings = &manifest.settings;
        let unattended = self.yes || !crate::ui::interactive();
        let dry_run = self.dry_run || self.json;
        let engine = app.engine()?;

        if !dry_run {
            run_hooks(&settings.update_pre_hooks, "pre")?;
        }

        // Refresh first so the plan is against current databases.
        let host = app.host()?;
        crate::update::wait_for_db_lock(&host.config.options.db_path(), Duration::from_secs(60))?;
        if !self.no_refresh && !self.aur_only && !dry_run {
            engine.refresh(
                RefreshOpts::default(),
                ApplyOpts {
                    dry_run: false,
                    no_confirm: true,
                },
            )?;
        }
        // Re-read after the refresh.
        let host = app.host()?;
        let now = crate::ledger::now();

        // Repository upgrades with holds.
        let mut holds = Vec::new();
        for declared in manifest.packages.values() {
            if declared.package.hold {
                holds.push(Hold {
                    name: declared.name.clone(),
                    reason: format!("held by {}", declared.declared_in.display()),
                });
            }
        }
        holds.extend(age_holds(&host, settings, now)?);
        let repo_plan = if self.aur_only {
            None
        } else {
            let mut ignore: Vec<String> = settings.update_ignore.clone();
            ignore.extend(holds.iter().map(|h| h.name.clone()));
            ignore.sort();
            ignore.dedup();
            let mut tx = Transaction::new(Operation::Upgrade {
                allow_downgrade: false,
            })
            .ignoring(ignore)
            .overwriting(settings.update_overwrite.iter().cloned());
            tx.ignore_group
                .extend(settings.update_ignore_group.iter().cloned());
            let resolved = engine.plan(&tx)?;
            let command = engine
                .apply_invocation(
                    &tx,
                    ApplyOpts {
                        dry_run: true,
                        no_confirm: true,
                    },
                )
                .display();
            let plan = transaction::plan(&host, &resolved, command);
            Some((resolved, plan))
        };

        // AUR candidates.
        let aur = if self.no_aur {
            Vec::new()
        } else {
            aur_candidates(&host, &app.aur_rpc())?
        };

        let orphans: Vec<String> = host.orphans()?.iter().map(|p| p.name.clone()).collect();
        let etc = app
            .paths
            .sysroot
            .as_ref()
            .map(|r| r.join("etc"))
            .unwrap_or_else(|| "/etc".into());
        let pacnew: Vec<String> = pacnew_files(&etc)
            .iter()
            .map(|p| p.display().to_string())
            .collect();

        let plan = UpdatePlan {
            repo: repo_plan.as_ref().map(|(_, p)| Plan {
                changes: Vec::new(),
                download_size: p.download_size,
                warnings: p.warnings.clone(),
                command: p.command.clone(),
            }),
            holds: holds.clone(),
            aur: aur.clone(),
            orphans: orphans.clone(),
            pacnew: pacnew.clone(),
        };
        if self.json {
            let mut json = serde_json::to_value(&plan)?;
            if let Some((_, p)) = &repo_plan {
                json["repo"] = serde_json::to_value(p)?;
            }
            return print_json(&json);
        }

        // One plan.
        if let Some((_, p)) = &repo_plan {
            print!("{}", transaction::render("upgrade", p));
        }
        for hold in &holds {
            println!("hold: {}: {}", hold.name, hold.reason);
        }
        if !aur.is_empty() {
            println!("aur: {} package(s) have a newer commit:", aur.len());
            for c in &aur {
                println!("  {}  {} -> {}", c.name, c.installed, c.available);
            }
        } else if !self.no_aur {
            println!("aur: nothing newer");
        }
        if !orphans.is_empty() {
            println!(
                "orphans: {}{}",
                orphans.join(", "),
                if self.prune_orphans {
                    " (will be removed)"
                } else {
                    " (pass --prune-orphans to remove)"
                }
            );
        }
        for file in &pacnew {
            println!("pacnew: {file}");
        }
        if dry_run {
            if let Some((_, p)) = &repo_plan {
                println!("would run: {}", p.command);
            }
            return Ok(());
        }

        // Repository transaction.
        if let Some((resolved, p)) = &repo_plan
            && !resolved.is_empty()
        {
            let performed =
                transaction::confirm_and_apply(&engine, resolved, p, "upgrade", self.yes, false)?;
            if performed {
                app.record(&transaction::ledger_patch(p, &[], "update", false))?;
            }
        }

        // AUR upgrades, one at a time.
        let mut skipped = Vec::new();
        for candidate in &aur {
            match update_aur_package(app, &candidate.name, unattended)? {
                AurOutcome::Updated(commit) => {
                    println!(
                        "updated {} to {} from AUR commit {}",
                        candidate.name,
                        candidate.available,
                        &commit[..12]
                    );
                }
                AurOutcome::Skipped(reason) => {
                    eprintln!("skipped {}: {reason}", candidate.name);
                    skipped.push(candidate.name.clone());
                }
            }
        }

        // Orphans.
        if self.prune_orphans && !orphans.is_empty() {
            let tx = Transaction::remove(orphans.clone());
            let resolved = engine.plan(&tx)?;
            let command = engine
                .apply_invocation(
                    &tx,
                    ApplyOpts {
                        dry_run: true,
                        no_confirm: true,
                    },
                )
                .display();
            let p = transaction::plan(&host, &resolved, command);
            let performed = transaction::confirm_and_apply(
                &engine,
                &resolved,
                &p,
                "remove orphans",
                self.yes,
                false,
            )?;
            if performed {
                app.record(&transaction::ledger_patch(&p, &[], "update", true))?;
            }
        }

        run_hooks(&settings.update_post_hooks, "post")?;
        if !skipped.is_empty() {
            let mut msg = String::new();
            let _ = write!(
                msg,
                "{} AUR package(s) skipped: {}; review them with `omapac aur review <name>`",
                skipped.len(),
                skipped.join(", ")
            );
            eprintln!("{msg}");
        }
        Ok(())
    }
}

enum AurOutcome {
    Updated(String),
    Skipped(String),
}

/// Review the package at its current commit; unattended, a denial skips
/// it and a clean report approves it; interactive, the user decides.
fn update_aur_package(app: &App, name: &str, unattended: bool) -> Result<AurOutcome> {
    let (reviewed, mut lock) = app.review_aur(name, None, !unattended)?;
    let approved_here = lock
        .aur
        .get(name)
        .is_some_and(|e| e.commit == reviewed.target);
    if !approved_here {
        if unattended {
            if reviewed.report.denied() {
                let reasons: Vec<String> = reviewed
                    .report
                    .denials()
                    .map(|j| j.finding.id.to_string())
                    .collect();
                return Ok(AurOutcome::Skipped(reasons.join(", ")));
            }
        } else {
            print!("{}", super::aur_cmd::render(&reviewed));
            let text = reviewed.review_text()?;
            if !text.is_empty() {
                println!();
                print!("{text}");
            }
            if !crate::ui::confirm(
                &format!("Approve and update {name} at {}?", &reviewed.target[..12]),
                false,
            )? {
                return Ok(AurOutcome::Skipped("not approved".to_string()));
            }
        }
        lock.aur.insert(name.to_string(), reviewed.lock_entry());
        lock.save(&app.lockfile_path())?;
    }
    let prepared = app.prepare_aur(name, None, true, true)?;
    let files = app.build_aur(&prepared)?;
    let engine = app.engine()?;
    engine.install_files(
        &crate::engine::FileInstall {
            files,
            as_deps: false,
            overwrite: Vec::new(),
        },
        ApplyOpts {
            dry_run: false,
            no_confirm: true,
        },
    )?;
    let mut patch = crate::ledger::Patch::default();
    patch.upsert.insert(
        name.to_string(),
        crate::ledger::Entry {
            version: prepared.reviewed.srcinfo.version(),
            tier: crate::resolve::Tier::Aur,
            repo: None,
            aur_commit: Some(prepared.reviewed.target.clone()),
            explicit: app
                .host()?
                .installed_package(name)?
                .is_none_or(|p| p.reason == alpm_db::InstallReason::Explicit),
            by: "update".to_string(),
            at: crate::ledger::now(),
        },
    );
    app.record(&patch)?;
    Ok(AurOutcome::Updated(prepared.reviewed.target.clone()))
}
