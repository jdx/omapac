use super::App;
use crate::ledger::{Patch, Pending};
use eyre::{Result, bail};
use usage_rs::RunWith;

/// Inspect interrupted transactions and recover recorded successful operations
#[derive(Debug, usage_rs::Args)]
pub struct Recover {
    /// Restore completed transactions whose installed versions still match
    #[usage(long)]
    write: bool,
    /// Print pending transaction details as JSON
    #[usage(long)]
    json: bool,
    /// Discard one inspected journal entry without changing installed packages
    #[usage(long)]
    discard: Option<String>,
}

impl RunWith<&App> for Recover {
    type Output = Result<()>;
    fn run_with(self, app: &App) -> Result<()> {
        if self.json && (self.write || self.discard.is_some()) {
            bail!("--json is a preview; cannot combine with --write or --discard");
        }
        if self.write && self.discard.is_some() {
            bail!("choose --write or --discard");
        }
        let ledger = app.ledger()?;
        if let Some(id) = self.discard {
            if !ledger.pending.contains_key(&id) {
                bail!("unknown transaction {id}");
            }
            let mut patch = Patch::default();
            patch.pending.insert(id, None);
            return app.record(&patch);
        }
        if self.json {
            return super::print_json(&ledger.pending);
        }
        let host = app.host()?;
        for (id, pending) in &ledger.pending {
            let mut matches = true;
            for (name, entry) in &pending.patch.upsert {
                matches &= host
                    .installed_package(name)?
                    .is_some_and(|p| p.version == entry.version);
            }
            for name in &pending.patch.remove {
                matches &= host.installed_package(name)?.is_none();
            }
            println!(
                "{id}: {}{}",
                if pending.completed {
                    "pacman completed"
                } else {
                    "outcome uncertain; inspect pacman logs before discarding"
                },
                if matches {
                    ""
                } else {
                    "; installed state differs"
                }
            );
            if self.write && pending.completed && matches {
                let mut patch = *pending.patch.clone();
                patch.pending.insert(id.clone(), None);
                app.record(&patch)?;
                println!("restored ledger for {id}");
            }
        }
        if ledger.pending.is_empty() {
            println!("no interrupted transactions");
        }
        Ok(())
    }
}

impl App {
    /// Persist intent before pacman; retain uncertainty on error or interruption.
    pub(super) fn journaled<T>(
        &self,
        patch: Patch,
        apply: impl FnOnce() -> Result<T>,
    ) -> Result<T> {
        if patch.is_empty() {
            return apply();
        }
        let id = format!(
            "{}-{}-{}",
            crate::ledger::now(),
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .subsec_nanos()
        );
        let mut pending = Pending {
            at: crate::ledger::now(),
            completed: false,
            patch: Box::new(patch.clone()),
        };
        let mut intent = Patch::default();
        intent.pending.insert(id.clone(), Some(pending.clone()));
        self.record(&intent)?;
        let result = apply().map_err(|err| {
            eyre::eyre!("{err:#}; transaction {id} retained; inspect with pacvamp recover")
        })?;
        pending.completed = true;
        intent.pending.insert(id.clone(), Some(pending));
        self.record(&intent)?;
        let mut finished = patch;
        finished.pending.insert(id, None);
        self.record(&finished)?;
        Ok(result)
    }
}
