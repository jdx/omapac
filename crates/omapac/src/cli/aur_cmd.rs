use std::fmt::Write as _;

use eyre::{Context as _, Result, bail};
use omapac_policy::Decision;
use usage_rs::RunWith;

use super::{App, print_json};
use crate::aur::review::{Request, Reviewed, review};
use crate::lockfile::Lockfile;

/// Review, approve, and build AUR packages
#[derive(Debug, usage_rs::Args)]
pub struct Aur {
    #[usage(subcommand)]
    command: AurCommands,
}

#[derive(Debug, usage_rs::Subcommands)]
#[usage(run_with)]
enum AurCommands {
    Approve(Approve),
    Build(Build),
    Diff(Diff),
    Review(Review),
}

/// Build an approved AUR package without installing it
///
/// Sources are fetched with network, then makepkg runs in the jail with
/// writes limited to the build directory and no network unless the
/// manifest grants it. Prints the package files it built.
#[derive(Debug, usage_rs::Args)]
pub struct Build {
    /// The package name
    package: String,
    /// Build this commit instead of the approved one
    #[usage(long)]
    commit: Option<String>,
    /// Install missing repository dependencies without asking
    #[usage(short = 'y', long)]
    yes: bool,
    /// Print the files as JSON
    #[usage(short = 'J', long)]
    json: bool,
}

impl RunWith<&App> for Build {
    type Output = Result<()>;

    fn run_with(self, app: &App) -> Self::Output {
        let prepared = app.prepare_aur(&self.package, self.commit.as_deref(), true, self.yes)?;
        let files = app.build_aur(&prepared, self.yes)?;
        if self.json {
            return print_json(&files);
        }
        for file in files {
            println!("{}", file.display());
        }
        Ok(())
    }
}

impl RunWith<&App> for Aur {
    type Output = Result<()>;

    fn run_with(self, app: &App) -> Self::Output {
        self.command.run_with(app)
    }
}

/// Review an AUR package at its current commit
///
/// Fetches the package's git history and metadata, evaluates the policy
/// findings against the last approved commit, and shows the PKGBUILD diff
/// (or the whole PKGBUILD on a first review). Nothing is built.
#[derive(Debug, usage_rs::Args)]
pub struct Review {
    /// The package name
    package: String,
    /// Review this commit instead of the current one
    #[usage(long)]
    commit: Option<String>,
    /// Do not print the PKGBUILD diff
    #[usage(long)]
    no_diff: bool,
    /// Evaluate as an unattended run would
    #[usage(long)]
    unattended: bool,
    /// Print as JSON
    #[usage(short = 'J', long)]
    json: bool,
    /// Show the review and diff in a scrollable pager
    #[usage(long)]
    pager: bool,
}

/// Approve an AUR package's commit for building
///
/// Records the reviewed commit and the evidence in omapac.lock next to
/// the user manifest. Interactively, the findings are shown and you
/// confirm; unattended, a denied review is refused unless --force.
#[derive(Debug, usage_rs::Args)]
pub struct Approve {
    /// The package name
    package: String,
    /// Approve this commit instead of the current one
    #[usage(long)]
    commit: Option<String>,
    /// Approve without asking, even over denials
    #[usage(long)]
    force: bool,
    /// Approve without asking when nothing denies
    #[usage(short = 'y', long)]
    yes: bool,
}

/// Show the PKGBUILD diff since the approved commit
#[derive(Debug, usage_rs::Args)]
pub struct Diff {
    /// The package name
    package: String,
    /// Diff to this commit instead of the current one
    #[usage(long)]
    commit: Option<String>,
}

/// A package that has been reviewed and is cleared for building.
pub struct Prepared {
    pub reviewed: Reviewed,
    pub settings: crate::manifest::Settings,
    pub arch: String,
}

impl App {
    /// Review `name` and check it is approved at the target commit, or
    /// approve it interactively. `yes` means unattended: an unapproved or
    /// denied package is refused rather than asked about.
    pub fn prepare_aur(
        &self,
        name: &str,
        commit: Option<&str>,
        _interactive_hint: bool,
        yes: bool,
    ) -> Result<Prepared> {
        let interactive = !yes && crate::ui::interactive();
        let (reviewed, mut lock) = self.review_aur(name, commit, interactive)?;
        let manifest = self.manifest()?;
        let settings = manifest.settings.clone();
        let approved_here = lock
            .aur
            .get(&reviewed.pkgbase)
            .or_else(|| lock.aur.get(name))
            .is_some_and(|entry| entry.commit == reviewed.target);
        if !approved_here {
            if !interactive {
                bail!(
                    "{name} at {} is not approved; run `omapac aur review {name}` and `omapac aur approve {name}` first",
                    &reviewed.target[..12]
                );
            }
            print!("{}", render(&reviewed));
            let text = reviewed.review_text()?;
            if !text.is_empty() {
                println!();
                print!("{text}");
            }
            if reviewed.report.denied() {
                bail!(
                    "{} finding(s) deny this commit; review it and use `omapac aur approve --force {name}` to override explicitly",
                    reviewed.report.denials().count(),
                );
            }
            if !crate::ui::confirm(
                &format!("Approve and build {name} at {}?", &reviewed.target[..12]),
                false,
            )? {
                bail!("not approved");
            }
            lock.aur.remove(name);
            lock.aur
                .insert(reviewed.pkgbase.clone(), reviewed.lock_entry());
            lock.save(&self.lockfile_path())?;
        }
        if !reviewed.evidence.recipe.install_files.is_empty()
            && settings.aur_install_scripts == crate::manifest::settings::InstallScripts::Deny
        {
            bail!(
                "{name} carries install scriptlet(s) {} and policy says deny",
                reviewed.evidence.recipe.install_files.join(", ")
            );
        }
        let host = self.host()?;
        let arch = host
            .config
            .options
            .arch()
            .unwrap_or_else(|| alpm_db::conf::host_arch().to_string());
        Ok(Prepared {
            reviewed,
            settings,
            arch,
        })
    }

    /// Install missing repository dependencies, then build.
    pub fn build_aur(&self, prepared: &Prepared, yes: bool) -> Result<Vec<std::path::PathBuf>> {
        let host = self.host()?;
        let missing = crate::aur::build::missing_deps(&host, &prepared.reviewed, &prepared.arch)?;
        if !missing.other.is_empty() {
            bail!(
                "{}: dependencies not in any repository: {}; install them first (AUR dependencies are not resolved yet)",
                prepared.reviewed.pkgname,
                missing.other.join(", ")
            );
        }
        if !missing.repo.is_empty() {
            let engine = self.engine()?;
            let mut tx = crate::engine::Transaction::install(missing.repo.clone());
            if let crate::engine::Operation::Install { as_deps, .. } = &mut tx.operation {
                *as_deps = true;
            }
            let resolved = crate::engine::Engine::plan(&engine, &tx)?;
            let command = engine
                .apply_invocation(
                    &tx,
                    crate::engine::ApplyOpts {
                        dry_run: true,
                        no_confirm: true,
                    },
                )
                .display();
            let plan = super::transaction::plan(&host, &resolved, command);
            let performed = super::transaction::confirm_and_apply(
                &engine,
                &resolved,
                &plan,
                "install dependencies",
                yes,
                false,
            )?;
            if performed {
                self.record(&super::transaction::ledger_patch(
                    &plan,
                    &[],
                    "install",
                    false,
                ))?;
            }
        }
        let opts = crate::aur::build::BuildOpts::from_settings(
            &prepared.settings,
            &prepared.reviewed.pkgbase,
            &crate::aur::cache_dir(),
        )?;
        crate::aur::build::build(&prepared.reviewed, &opts)
    }

    /// Where AUR repositories are cloned from; `OMAPAC_AUR_GIT_BASE`
    /// points at a mirror or a test remote.
    pub fn aur_remote(&self) -> crate::aur::git::Remote {
        match std::env::var("OMAPAC_AUR_GIT_BASE") {
            Ok(base) if !base.is_empty() => crate::aur::git::Remote { base },
            _ => crate::aur::git::Remote::aur(),
        }
    }

    /// The user lockfile, beside the user manifest.
    pub fn lockfile_path(&self) -> std::path::PathBuf {
        Lockfile::path_beside(&self.manifest_paths().user)
    }

    /// Review `name`, at `commit` or the remote head.
    pub fn review_aur(
        &self,
        name: &str,
        commit: Option<&str>,
        interactive: bool,
    ) -> Result<(Reviewed, Lockfile)> {
        self.review_aur_with_pin(name, commit, interactive, commit.is_some())
    }

    fn review_aur_with_pin(
        &self,
        name: &str,
        commit: Option<&str>,
        interactive: bool,
        pinned: bool,
    ) -> Result<(Reviewed, Lockfile)> {
        let host = self.host()?;
        let manifest = self.manifest()?;
        let lock = Lockfile::load(&self.lockfile_path())?;
        let rpc = self.aur_rpc();
        let remote = self.aur_remote();
        let cache_dir = crate::aur::cache_dir();
        let arch = host
            .config
            .options
            .arch()
            .unwrap_or_else(|| alpm_db::conf::host_arch().to_string());
        let feeds = self.feeds(&host, &manifest.settings)?;
        let request = Request {
            host: &host,
            rpc: &rpc,
            remote: &remote,
            cache_dir: &cache_dir,
            settings: &manifest.settings,
            locked: &lock.aur,
            commit,
            pinned,
            interactive,
            arch: &arch,
            advisories: feeds.as_ref().and_then(|f| f.0.as_ref()),
            verdicts: feeds.as_ref().and_then(|f| f.1.as_ref()),
        };
        let reviewed = review(name, &request)?;
        Ok((reviewed, lock))
    }
}

impl App {
    /// The advisory and verdict feeds of the first `opr` repository, per
    /// `trust.advisories`: `off` never fetches, `on` warns and continues
    /// when they cannot be had, `required` fails.
    pub fn feeds(
        &self,
        host: &crate::host::Host,
        settings: &crate::manifest::Settings,
    ) -> Result<
        Option<(
            Option<crate::trust::Advisories>,
            Option<crate::trust::Verdicts>,
        )>,
    > {
        use crate::manifest::settings::Advisories as Mode;
        if settings.trust_advisories == Mode::Off {
            return Ok(None);
        }
        let unavailable = |detail: String| {
            if settings.trust_advisories == Mode::Required {
                bail!("trust.advisories is required: {detail}");
            }
            eprintln!("warning: advisory feeds unavailable: {detail}");
            Ok(None)
        };
        let Some(source) = host
            .sources
            .iter()
            .find(|s| matches!(s.tier, crate::resolve::Tier::Opr))
        else {
            return unavailable("no OPR repository is configured".into());
        };
        let Some(feed) = self.feed_source(host, &source.name) else {
            return unavailable(format!(
                "[{}] has no server to fetch feeds from",
                source.name
            ));
        };
        let keyring = match crate::trust::Keyring::load(self.paths.sysroot.as_deref()) {
            Ok(keyring) => keyring,
            Err(err) => {
                return unavailable(format!("loading trust keys: {err:#}"));
            }
        };
        let cache = crate::trust::Cache::for_repo(&source.name, self.paths.sysroot.as_deref())?;
        let advisories = crate::trust::fetch(&feed, "advisories.json", &keyring, &cache, false)
            .map(|fetched: crate::trust::Fetched<crate::trust::Advisories>| fetched.value);
        let verdicts = crate::trust::fetch(&feed, "verdicts.json", &keyring, &cache, false)
            .map(|fetched: crate::trust::Fetched<crate::trust::Verdicts>| fetched.value);
        if settings.trust_advisories == Mode::Required {
            return Ok(Some((
                Some(advisories.wrap_err("trust.advisories is required")?),
                Some(verdicts.wrap_err("trust.advisories is required")?),
            )));
        }
        let advisories = advisories
            .map_err(|err| {
                eprintln!("warning: advisory feeds unavailable (advisories): {err:#}");
            })
            .ok();
        let verdicts = verdicts
            .map_err(|err| {
                eprintln!("warning: advisory feeds unavailable (verdicts): {err:#}");
            })
            .ok();
        Ok(Some((advisories, verdicts)))
    }
}

/// Render a review for a human.
pub fn render(reviewed: &Reviewed) -> String {
    let mut out = String::new();
    let e = &reviewed.evidence;
    let _ = writeln!(
        out,
        "{} {} at {} [aur]",
        reviewed.pkgname,
        e.recipe.version,
        &reviewed.target[..12]
    );
    if let Some(rpc) = &e.rpc {
        let _ = writeln!(
            out,
            "maintainer {}, {} votes, last modified {}",
            rpc.maintainer.as_deref().unwrap_or("nobody (orphan)"),
            rpc.num_votes,
            crate::aur::format_age(rpc.last_modified, e.now)
        );
    }
    match &e.approved {
        Some(approved) if approved.commit == reviewed.target => {
            let _ = writeln!(out, "approved: this commit");
        }
        Some(approved) => {
            let _ = writeln!(
                out,
                "approved: {} (reviewing the change since)",
                &approved.commit[..12]
            );
        }
        None => {
            let _ = writeln!(out, "approved: never (first review)");
        }
    }
    for note in &reviewed.notes {
        let _ = writeln!(out, "note: {note}");
    }
    if reviewed.report.findings.is_empty() {
        let _ = writeln!(out, "findings: none");
    } else {
        let _ = writeln!(out, "findings ({:?} mode):", reviewed.report.mode);
        for judged in &reviewed.report.findings {
            let mark = match judged.decision {
                Decision::Allow => "info",
                Decision::Warn => "warn",
                Decision::Deny => "DENY",
            };
            let _ = writeln!(
                out,
                "  {mark}  {}: {}",
                judged.finding.id, judged.finding.message
            );
        }
    }
    out
}

impl RunWith<&App> for Review {
    type Output = Result<()>;

    fn run_with(self, app: &App) -> Self::Output {
        let interactive = !self.unattended && crate::ui::interactive();
        let (reviewed, _) = app.review_aur(&self.package, self.commit.as_deref(), interactive)?;
        let denied = reviewed.report.denied();
        if self.json {
            print_json(&serde_json::json!({
                "pkgbase": reviewed.pkgbase,
                "pkgname": reviewed.pkgname,
                "commit": reviewed.target,
                "version": reviewed.evidence.recipe.version,
                "approved": reviewed.evidence.approved.as_ref().map(|a| a.commit.clone()),
                "report": reviewed.report,
                "notes": reviewed.notes,
                "diff": if self.no_diff { None } else { Some(reviewed.review_text()?) },
            }))?;
            if denied {
                std::process::exit(1);
            }
            return Ok(());
        }
        if self.pager {
            crate::tui::require_terminal("aur review --pager", "run without --pager")?;
            let mut text = render(&reviewed);
            if !self.no_diff {
                let diff = reviewed.review_text()?;
                if !diff.is_empty() {
                    text.push('\n');
                    text.push_str(&diff);
                }
            }
            crate::tui::page(
                &format!("Review {} at {}", reviewed.pkgname, &reviewed.target[..12]),
                &text,
            )?;
        } else {
            print!("{}", render(&reviewed));
            if !self.no_diff {
                let text = reviewed.review_text()?;
                if !text.is_empty() {
                    println!();
                    print!("{text}");
                }
            }
        }
        if denied {
            std::process::exit(1);
        }
        Ok(())
    }
}

impl RunWith<&App> for Approve {
    type Output = Result<()>;

    fn run_with(self, app: &App) -> Self::Output {
        let interactive = !self.yes && crate::ui::interactive();
        let (reviewed, mut lock) =
            app.review_aur_with_pin(&self.package, self.commit.as_deref(), interactive, false)?;
        print!("{}", render(&reviewed));
        if reviewed.report.denied() && !self.force {
            bail!(
                "{}: {} finding(s) deny; review interactively or pass --force to approve anyway",
                self.package,
                reviewed.report.denials().count()
            );
        }
        if !self.yes && !self.force {
            let text = reviewed.review_text()?;
            if !text.is_empty() {
                println!();
                print!("{text}");
            }
            if !crate::ui::confirm(
                &format!("Approve {} at {}?", self.package, &reviewed.target[..12]),
                false,
            )? {
                bail!("not approved");
            }
        }
        // One approval covers all split packages produced by the pkgbase.
        lock.aur.remove(&self.package);
        lock.aur
            .insert(reviewed.pkgbase.clone(), reviewed.lock_entry());
        let path = app.lockfile_path();
        lock.save(&path)?;
        println!(
            "approved {} at {} in {}",
            self.package,
            &reviewed.target[..12],
            path.display()
        );
        Ok(())
    }
}

impl RunWith<&App> for Diff {
    type Output = Result<()>;

    fn run_with(self, app: &App) -> Self::Output {
        let (reviewed, _) = app.review_aur(&self.package, self.commit.as_deref(), true)?;
        print!("{}", reviewed.review_text()?);
        Ok(())
    }
}
