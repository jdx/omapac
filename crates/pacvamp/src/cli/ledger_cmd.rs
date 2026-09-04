use std::io::Read as _;

use eyre::{Context as _, Result};
use usage_rs::RunWith;

use super::App;
use crate::ledger::{self, Ledger, Patch};

/// Merge a ledger patch from stdin; pacvamp runs this elevated
#[derive(Debug, usage_rs::Args)]
pub struct LedgerMerge {}

impl RunWith<&App> for LedgerMerge {
    type Output = Result<()>;

    fn run_with(self, app: &App) -> Self::Output {
        let mut json = String::new();
        std::io::stdin()
            .read_to_string(&mut json)
            .wrap_err("reading the ledger patch from stdin")?;
        let patch: Patch = serde_json::from_str(&json).wrap_err("parsing the ledger patch")?;
        ledger::merge_into(&app.ledger_path(), &patch)?;
        Ok(())
    }
}

impl App {
    /// Where this machine's ledger lives.
    pub fn ledger_path(&self) -> std::path::PathBuf {
        Ledger::path(self.paths.sysroot.as_deref())
    }

    /// The ledger, read without elevation.
    pub fn ledger(&self) -> Result<Ledger> {
        Ledger::load(&self.ledger_path())
    }

    /// Record a patch, elevating if the ledger directory requires it.
    pub fn record(&self, patch: &Patch) -> Result<()> {
        ledger::record(&self.ledger_path(), self.paths.sysroot.as_deref(), patch)
    }
}
