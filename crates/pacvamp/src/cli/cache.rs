use super::{App, print_json};
use eyre::Result;
use usage_rs::RunWith;

/// Inspect retained build data or prune unused runs
#[derive(Debug, usage_rs::Args)]
pub struct Cache {
    #[usage(subcommand)]
    command: Commands,
}
#[derive(Debug, usage_rs::Subcommands)]
#[usage(run_with)]
enum Commands {
    Status(Status),
    Prune(Prune),
}
/// Show retained build runs and protected evidence
#[derive(Debug, usage_rs::Args)]
pub struct Status {
    #[usage(long)]
    json: bool,
}
/// Remove unused runs older than the retention window or over the size budget
#[derive(Debug, usage_rs::Args)]
pub struct Prune {
    /// Preview without deleting anything
    #[usage(long)]
    dry_run: bool,
    /// Retain unused runs for this many days (recent runs always have a one-hour grace)
    #[usage(long, default = "30")]
    older_than_days: u64,
    /// Target total bytes; protected runs can keep usage above this target
    #[usage(long)]
    max_bytes: Option<u64>,
    #[usage(long)]
    json: bool,
}
impl RunWith<&App> for Cache {
    type Output = Result<()>;
    fn run_with(self, app: &App) -> Result<()> {
        self.command.run_with(app)
    }
}
impl RunWith<&App> for Status {
    type Output = Result<()>;
    fn run_with(self, app: &App) -> Result<()> {
        show(app, 30, None, false, self.json)
    }
}
impl RunWith<&App> for Prune {
    type Output = Result<()>;
    fn run_with(self, app: &App) -> Result<()> {
        show(
            app,
            self.older_than_days,
            self.max_bytes,
            !self.dry_run,
            self.json,
        )
    }
}
fn show(app: &App, days: u64, max: Option<u64>, remove: bool, json: bool) -> Result<()> {
    let cache = crate::aur::cache_dir();
    // Only deletion needs an exclusive lease; previews can run during builds.
    let _lease = crate::aur::cache::lease(&cache, remove)?;
    let ledger = app.ledger()?;
    let references = ledger
        .packages
        .values()
        .chain(
            ledger
                .pending
                .values()
                .flat_map(|p| p.patch.upsert.values()),
        )
        .filter_map(|e| e.build_receipt.as_ref())
        .map(|r| r.path.canonicalize())
        .collect::<std::io::Result<_>>()?;
    let runs = crate::aur::cache::inventory(&cache, &references, days, max)?;
    if remove {
        for run in runs.iter().filter(|r| r.prune) {
            std::fs::remove_dir_all(&run.path)?;
        }
    }
    if json {
        return print_json(&runs);
    }
    for run in runs {
        println!(
            "{} {} {}",
            if run.protected {
                "protected"
            } else if run.prune {
                if remove { "removed" } else { "eligible" }
            } else {
                "retained"
            },
            super::format_size(run.bytes),
            run.path.display()
        );
    }
    Ok(())
}
