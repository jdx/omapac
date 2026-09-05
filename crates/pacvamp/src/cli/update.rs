use std::fmt::Write as _;
use std::time::Duration;

use eyre::{Result, bail};
use serde::Serialize;
use usage_rs::RunWith;

use super::transaction::{self, Plan};
use super::{App, print_json};
use crate::engine::{ApplyOpts, Engine, Operation, RefreshOpts, Transaction};
use crate::host::Host;
use crate::manifest::settings::Settings;
use crate::update::{
    AurCandidate, Hold, Published, age_holds, aur_candidates, pacnew_files, run_hooks,
};

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
    /// Queue behind another running update instead of failing
    #[usage(long)]
    wait: bool,
}

#[derive(Debug, Serialize)]
pub struct UpdatePlan {
    /// The channel snapshot the repositories are at, when known.
    pub snapshot: Option<String>,
    pub repo: Option<Plan>,
    pub holds: Vec<Hold>,
    pub aur: Vec<AurCandidate>,
    pub blocked: Vec<Hold>,
    pub orphans: Vec<String>,
    pub pacnew: Vec<String>,
}

impl App {
    /// Publish times from the index of every repository whose tier has a
    /// release-age floor. Best effort: without trust keys nothing is
    /// fetched, and a repository whose index cannot be read falls back to
    /// build dates with a note.
    pub fn published_times(
        &self,
        host: &Host,
        settings: &Settings,
        offline: bool,
        record_sequence: bool,
    ) -> Published {
        use std::str::FromStr as _;
        let mut published = Published::new();
        let Ok(keyring) = crate::trust::Keyring::load(self.paths.sysroot.as_deref()) else {
            return published;
        };
        if keyring.is_empty() {
            return published;
        }
        for source in &host.sources {
            let floor = match &source.tier {
                crate::resolve::Tier::Arch => settings.repo_min_release_age_arch,
                crate::resolve::Tier::Opr => settings.repo_min_release_age_opr,
                _ => settings.repo_min_release_age_custom,
            };
            if floor == crate::manifest::settings::Age::ZERO {
                continue;
            }
            let fetched = if record_sequence {
                self.index(host, &source.name, offline)
            } else {
                self.index_readonly(host, &source.name, offline)
            };
            match fetched {
                Ok(index) => {
                    if let Some(detail) = &index.fallback_error
                        && (detail.contains("older than")
                            || detail.contains("stale")
                            || detail.contains("rolled-back"))
                    {
                        eprintln!(
                            "warning: [{}] stale or rolled-back index; release-age floor blocks upgrades: {detail}",
                            source.name
                        );
                        published
                            .unsafe_repos
                            .insert(source.name.clone(), detail.clone());
                        continue;
                    }
                    let times = index
                        .value
                        .packages
                        .iter()
                        .filter_map(|(file, entry)| {
                            let at = entry.published_at.as_deref()?;
                            let stamp = jiff::Timestamp::from_str(at).ok()?;
                            Some((file.clone(), stamp.as_second()))
                        })
                        .collect();
                    published.insert(source.name.clone(), times);
                }
                Err(err) => {
                    let detail = format!("{err:#}");
                    if detail.contains("older than")
                        || detail.contains("stale")
                        || detail.contains("rolled-back")
                    {
                        eprintln!(
                            "warning: [{}] stale or rolled-back index; release-age floor blocks upgrades: {detail}",
                            source.name
                        );
                        published.unsafe_repos.insert(source.name.clone(), detail);
                    } else {
                        eprintln!(
                            "note: [{}] index unavailable, release ages use build dates: {detail}",
                            source.name
                        );
                    }
                }
            }
        }
        published
    }
}

impl RunWith<&App> for Update {
    type Output = Result<()>;

    fn run_with(self, app: &App) -> Self::Output {
        let manifest = app.manifest()?;
        let settings = &manifest.settings;
        let dry_run = self.dry_run || self.json;
        let engine = app.engine()?;
        let lock_path = crate::update::UpdateLock::path(app.paths.sysroot.as_deref());
        let _lock = crate::update::UpdateLock::acquire(
            &lock_path,
            self.wait.then_some(Duration::from_secs(3600)),
        )?;

        // Refresh first so the plan is against current databases.
        let host = app.host()?;
        crate::update::wait_for_db_lock(&host.db_path(), Duration::from_secs(60))?;
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
        // The channel's release manifest, fetched now so the tested label
        // and the recorded snapshot are current; absent is fine.
        let release = match app.active_release(&host, false) {
            Ok(release) => release,
            Err(err) => {
                eprintln!("note: release manifest unavailable: {err:#}");
                None
            }
        };

        // Repository upgrades with holds.
        let mut holds = Vec::new();
        let mut held_names = Vec::new();
        for declared in manifest.packages.values() {
            if declared.package.hold {
                held_names.push(declared.name.clone());
                holds.push(Hold {
                    name: declared.name.clone(),
                    installed: host
                        .installed_package(&declared.name)?
                        .map(|p| p.version.clone()),
                    eligible_at: None,
                    next_step: format!(
                        "Review the hold in {} before changing it.",
                        declared.declared_in.display()
                    ),
                    reason: format!("held by {}", declared.declared_in.display()),
                });
            }
        }
        for name in &settings.update_ignore {
            if !holds.iter().any(|hold| &hold.name == name) {
                holds.push(Hold {
                    name: name.clone(),
                    installed: host.installed_package(name)?.map(|p| p.version.clone()),
                    reason: "excluded by update.ignore".into(),
                    eligible_at: None,
                    next_step: "Review update.ignore in the manifest before changing it.".into(),
                });
            }
        }
        // Dry runs verify feeds and rollback state without advancing it.
        let published = app.published_times(&host, settings, false, !dry_run);
        holds.extend(age_holds(&host, settings, now, &published)?);
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
            let plan = transaction::plan_with_custom_repos(
                &host,
                &resolved,
                command,
                settings.trust_custom_repos,
            );
            Some((resolved, plan))
        };

        // AUR candidates.
        let mut aur = if self.no_aur {
            Vec::new()
        } else {
            aur_candidates(&host, &app.aur_rpc())?
        };
        aur.retain(|candidate| {
            !held_names.contains(&candidate.name)
                && !settings.update_ignore.contains(&candidate.name)
        });

        // Preview the same unattended policy used during execution. Re-review
        // immediately before building so a changed upstream cannot reuse this plan.
        let mut blocked = Vec::new();
        for candidate in &aur {
            let (reviewed, lock) = app.review_aur(&candidate.name, None, false)?;
            let approved = lock
                .aur
                .get(&reviewed.pkgbase)
                .or_else(|| lock.aur.get(&candidate.name))
                .is_some_and(|entry| entry.commit == reviewed.target);
            if let Some(hold) = crate::update::aur_blocker(
                &reviewed,
                settings,
                Some(candidate.installed.clone()),
                approved,
            ) {
                blocked.push(hold);
            }
        }

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
            snapshot: release.as_ref().map(|r| r.id.clone()),
            repo: repo_plan.as_ref().map(|(_, p)| Plan {
                changes: Vec::new(),
                download_size: p.download_size,
                warnings: p.warnings.clone(),
                command: p.command.clone(),
            }),
            holds: holds.clone(),
            aur: aur.clone(),
            blocked: blocked.clone(),
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
        if let Some(release) = &release {
            println!(
                "snapshot: {} ({}; {} tested pkgbase(s))",
                release.id,
                super::channel::describe(release),
                release.tested_pkgbases.len()
            );
        }
        if let Some((_, p)) = &repo_plan {
            print!("{}", transaction::render("upgrade", p));
        }
        for hold in &holds {
            println!("hold: {}: {}", hold.name, hold.render());
        }
        if !aur.is_empty() {
            println!("aur: {} package(s) have a newer commit:", aur.len());
            for c in &aur {
                println!("  {}  {} -> {}", c.name, c.installed, c.available);
            }
        } else if !self.no_aur {
            println!("aur: nothing newer");
        }
        for hold in &blocked {
            println!("blocked unattended: {}: {}", hold.name, hold.render());
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

        // Resolve and cache the exact release after a successful refresh. A
        // pinned mirror must use its snapshot manifest, not today's channel
        // pointer. An empty package plan still means the host converged.
        let repo_empty = repo_plan
            .as_ref()
            .is_some_and(|(resolved, _)| resolved.is_empty());
        let converged_release = if repo_plan.is_some() && !self.no_refresh {
            release.clone()
        } else {
            None
        };
        if let Some((_, plan)) = &repo_plan {
            transaction::validate_plan(plan, "upgrade", self.yes)?;
        }
        let has_work = repo_plan
            .as_ref()
            .is_some_and(|(resolved, _)| !resolved.is_empty())
            || !aur.is_empty()
            || (self.prune_orphans && !orphans.is_empty());
        if has_work && !self.yes && !crate::ui::confirm("Proceed with update?", true)? {
            eyre::bail!("cancelled");
        }
        if !has_work {
            if repo_empty && let Some(release) = &converged_release {
                app.record(&crate::ledger::Patch {
                    snapshot: Some(release.id.clone()),
                    ..Default::default()
                })?;
            }
            return Ok(());
        }

        // Hooks bracket only an update the user has accepted. Always run the
        // post hooks once the pre hooks succeeded, including on update errors.
        run_hooks(&settings.update_pre_hooks, "pre")?;
        let update_result: Result<()> = (|| {
            // Repository transaction.
            if let Some((resolved, p)) = &repo_plan
                && !resolved.is_empty()
            {
                let accepted = transaction::verify_and_apply(
                    app, &host, settings, &engine, resolved, p, self.yes,
                )?;
                if let Some(accepted) = accepted {
                    let mut explicit = Vec::new();
                    for change in &p.changes {
                        if host
                            .installed_package(&change.name)?
                            .is_some_and(|package| {
                                package.reason == alpm_db::InstallReason::Explicit
                            })
                        {
                            explicit.push(change.name.clone());
                        }
                    }
                    let mut patch = transaction::ledger_patch(p, &explicit, "update", false);
                    accepted.attach(&mut patch);
                    app.record(&patch)?;
                    if let Some(release) = &converged_release {
                        let patch = crate::ledger::Patch {
                            snapshot: Some(release.id.clone()),
                            ..Default::default()
                        };
                        app.record(&patch)?;
                    }
                }
            }

            // AUR upgrades, one at a time.
            let mut skipped = Vec::new();
            for candidate in &aur {
                match update_aur_package(app, &candidate.name, self.yes)? {
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
                let p = transaction::plan_with_custom_repos(
                    &host,
                    &resolved,
                    command,
                    settings.trust_custom_repos,
                );
                transaction::validate_plan(&p, "remove orphans", self.yes)?;
                let performed = transaction::apply_confirmed(&engine, &resolved, &p, self.yes)?;
                if performed {
                    app.record(&transaction::ledger_patch(&p, &[], "update", true))?;
                }
            }

            let final_pacnew: Vec<String> = pacnew_files(&etc)
                .iter()
                .map(|path| path.display().to_string())
                .collect();
            for file in final_pacnew.iter().filter(|file| !pacnew.contains(file)) {
                println!("pacnew: {file}");
            }

            if !skipped.is_empty() {
                let mut msg = String::new();
                let _ = write!(
                    msg,
                    "{} AUR package(s) skipped: {}; review them with `pacvamp aur review <name>`",
                    skipped.len(),
                    skipped.join(", ")
                );
                eprintln!("{msg}");
            }
            if repo_empty && let Some(release) = &converged_release {
                app.record(&crate::ledger::Patch {
                    snapshot: Some(release.id.clone()),
                    ..Default::default()
                })?;
            }
            Ok(())
        })();
        let post_result = run_hooks(&settings.update_post_hooks, "post");
        update_result.and(post_result)
    }
}

enum AurOutcome {
    Updated(String),
    Skipped(String),
}

/// Review the package at its current commit. With explicit `-y`, a denial
/// skips it and a clean report approves it; otherwise the user decides.
fn update_aur_package(app: &App, name: &str, yes: bool) -> Result<AurOutcome> {
    let (reviewed, mut lock) = app.review_aur(name, None, !yes && crate::ui::interactive())?;
    let settings = app.manifest()?.settings;
    let installed = app
        .host()?
        .installed_package(name)?
        .map(|p| p.version.clone());
    let approved_here = lock
        .aur
        .get(&reviewed.pkgbase)
        .or_else(|| lock.aur.get(name))
        .is_some_and(|e| e.commit == reviewed.target);
    if (yes || settings.aur_install_scripts == crate::manifest::settings::InstallScripts::Deny)
        && let Some(hold) =
            crate::update::aur_blocker(&reviewed, &settings, installed.clone(), approved_here)
    {
        // Interactive warnings still go to the review prompt; script policy cannot be overridden.
        if yes || !reviewed.evidence.recipe.install_files.is_empty() {
            return Ok(AurOutcome::Skipped(hold.render()));
        }
    }
    if !approved_here {
        if !yes {
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
                return Ok(AurOutcome::Skipped(format!(
                    "not approved; remains: {}; review with `pacvamp aur review --commit {} -- {}`; waiting alone will not resolve this",
                    installed.as_deref().unwrap_or("not installed"),
                    reviewed.target,
                    crate::engine::sudo::quote(name)
                )));
            }
        }
        lock.aur.remove(name);
        lock.aur
            .insert(reviewed.pkgbase.clone(), reviewed.lock_entry());
        lock.save(&app.lockfile_path())?;
    } else if !yes
        && !crate::ui::confirm(
            &format!("Update {name} to {}?", reviewed.evidence.recipe.version),
            true,
        )?
    {
        return Ok(AurOutcome::Skipped(format!(
            "not approved; remains: {}; review with `pacvamp aur review --commit {} -- {}`; waiting alone will not resolve this",
            installed.as_deref().unwrap_or("not installed"),
            reviewed.target,
            crate::engine::sudo::quote(name)
        )));
    }
    let prepared = app.prepare_aur(name, Some(&reviewed.target), true, yes)?;
    let files = app.build_aur(&prepared, yes)?;
    let built = crate::aur::build::built_packages(&files)?;
    if !built.iter().any(|package| package.name == name) {
        bail!("{name}: makepkg did not produce the requested package");
    }
    let host = app.host()?;
    let mut selected_names = vec![name.to_string()];
    for package in &built {
        if host.installed_package(&package.name)?.is_some()
            && !selected_names.contains(&package.name)
        {
            selected_names.push(package.name.clone());
        }
    }
    let mut next = 0;
    while next < selected_names.len() {
        let selected = selected_names[next].clone();
        next += 1;
        for dep in prepared.reviewed.srcinfo.depends(&selected, &prepared.arch) {
            for package in &built {
                let provides = prepared
                    .reviewed
                    .srcinfo
                    .provides(&package.name, &prepared.arch);
                if !selected_names.contains(&package.name)
                    && dep.satisfied_by(&package.name, &package.version, &provides)
                {
                    selected_names.push(package.name.clone());
                }
            }
        }
    }
    let mut selected_packages = Vec::new();
    let mut dependency_files = Vec::new();
    let mut explicit_files = Vec::new();
    for (file, package) in files.into_iter().zip(built) {
        if selected_names.contains(&package.name) {
            let explicit = host
                .installed_package(&package.name)?
                .is_some_and(|installed| installed.reason == alpm_db::InstallReason::Explicit);
            if explicit {
                explicit_files.push(file.clone());
            } else {
                dependency_files.push(file.clone());
            }
            selected_packages.push((package, explicit));
        }
    }
    let engine = app.engine()?;
    for (files, as_deps) in [(dependency_files, true), (explicit_files, false)] {
        if !files.is_empty() {
            engine.install_files(
                &crate::engine::FileInstall {
                    files,
                    as_deps,
                    overwrite: Vec::new(),
                },
                ApplyOpts {
                    dry_run: false,
                    no_confirm: true,
                },
            )?;
        }
    }
    let mut patch = crate::ledger::Patch::default();
    for (package, explicit) in selected_packages {
        patch.upsert.insert(
            package.name,
            crate::ledger::Entry {
                version: package.version,
                tier: crate::resolve::Tier::Aur,
                repo: None,
                aur_commit: Some(prepared.reviewed.target.clone()),
                verification: None,
                explicit,
                by: "update".to_string(),
                at: crate::ledger::now(),
            },
        );
    }
    app.record(&patch)?;
    Ok(AurOutcome::Updated(prepared.reviewed.target.clone()))
}
