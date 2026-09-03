use std::fmt::Write as _;

use eyre::{Result, bail};
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
    Diff(Diff),
    Review(Review),
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

impl App {
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
        let request = Request {
            host: &host,
            rpc: &rpc,
            remote: &remote,
            cache_dir: &cache_dir,
            settings: &manifest.settings,
            locked: lock.aur.get(name),
            commit,
            interactive,
            arch: &arch,
        };
        let reviewed = review(name, &request)?;
        Ok((reviewed, lock))
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
        if self.json {
            return print_json(&serde_json::json!({
                "pkgbase": reviewed.pkgbase,
                "pkgname": reviewed.pkgname,
                "commit": reviewed.target,
                "version": reviewed.evidence.recipe.version,
                "approved": reviewed.evidence.approved.as_ref().map(|a| a.commit.clone()),
                "report": reviewed.report,
                "diff": if self.no_diff { None } else { Some(reviewed.review_text()?) },
            }));
        }
        print!("{}", render(&reviewed));
        if !self.no_diff {
            let text = reviewed.review_text()?;
            if !text.is_empty() {
                println!();
                print!("{text}");
            }
        }
        if reviewed.report.denied() {
            std::process::exit(1);
        }
        Ok(())
    }
}

impl RunWith<&App> for Approve {
    type Output = Result<()>;

    fn run_with(self, app: &App) -> Self::Output {
        let interactive = crate::ui::interactive();
        let (reviewed, mut lock) =
            app.review_aur(&self.package, self.commit.as_deref(), interactive)?;
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
        lock.aur.insert(self.package.clone(), reviewed.lock_entry());
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
