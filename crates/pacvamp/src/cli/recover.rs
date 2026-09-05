use super::App;
use crate::ledger::{Patch, Pending};
use eyre::{Context as _, Result, bail};
use usage_rs::RunWith;

/// Inspect interrupted transactions and recover recorded successful operations
#[derive(Debug, usage_rs::Args)]
pub struct Recover {
    /// Restore completed transactions whose installed versions still match
    #[usage(long)]
    write: bool,
    /// Inspect or restore only this transaction
    #[usage(long)]
    id: Option<String>,
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
        if self.discard.is_some() && self.id.is_some() {
            bail!("--discard already selects a transaction; omit --id");
        }
        let ledger = app.ledger()?;
        if let Some(id) = &self.id
            && !ledger.pending.contains_key(id)
        {
            bail!("unknown transaction {id}");
        }
        if let Some(id) = self.discard {
            if !ledger.pending.contains_key(&id) {
                bail!("unknown transaction {id}");
            }
            let mut patch = Patch::default();
            patch.pending.insert(id, None);
            return app.record(&patch);
        }
        let host = app.host()?;
        let mut reports = std::collections::BTreeMap::new();
        for (id, pending) in &ledger.pending {
            if self.id.as_ref().is_some_and(|selected| selected != id) {
                continue;
            }
            let mut packages = Vec::new();
            let mut matches = true;
            for (name, entry) in &pending.patch.upsert {
                let installed = host.installed_package(name)?.map(|p| p.version.clone());
                let matched = installed.as_ref() == Some(&entry.version);
                matches &= matched;
                packages.push(PackageState {
                    name: name.clone(),
                    expected: Some(entry.version.clone()),
                    installed,
                    matches: matched,
                });
            }
            for name in &pending.patch.remove {
                let installed = host.installed_package(name)?.map(|p| p.version.clone());
                let matched = installed.is_none();
                matches &= matched;
                packages.push(PackageState {
                    name: name.clone(),
                    expected: None,
                    installed,
                    matches: matched,
                });
            }
            let next_steps = if pending.completed && matches {
                vec![format!("pacvamp recover --id {id} --write")]
            } else {
                vec!["Inspect the package differences and pacman log context; reconcile the host with an explicitly reviewed install/update if needed.".into(),
                     format!("After inspection: pacvamp recover --discard {id} (removes this journal entry only; does not certify package provenance)")]
            };
            let log = app.rooted(&host.config.options.log_file());
            let (logs, log_notice) = log_context(&log, &packages, pending.at);
            let report = RecoveryReport {
                journal: pending,
                packages,
                restorable: pending.completed && matches,
                next_steps,
                logs,
                log_notice,
            };
            if !self.json {
                println!(
                    "{id}: {}",
                    if pending.completed {
                        "pacman completed"
                    } else {
                        "outcome uncertain; log matches do not establish provenance"
                    }
                );
                for package in &report.packages {
                    println!(
                        "  {}: expected {}; installed {}{}",
                        package.name,
                        package.expected.as_deref().unwrap_or("absent"),
                        package.installed.as_deref().unwrap_or("absent"),
                        if package.matches {
                            " (matches)"
                        } else {
                            " (differs)"
                        }
                    );
                }
                println!("  {}", report.log_notice);
                for line in &report.logs {
                    println!("    {}", line.escape_debug());
                }
                for step in &report.next_steps {
                    println!("  next: {step}");
                }
            }
            reports.insert(id, report);
            if self.write && pending.completed && matches {
                let mut patch = *pending.patch.clone();
                patch.pending.insert(id.clone(), None);
                app.record(&patch)?;
                println!("restored ledger for {id}");
            }
        }
        if self.json {
            return super::print_json(&reports);
        }
        if ledger.pending.is_empty() {
            println!("no interrupted transactions");
        }
        Ok(())
    }
}

#[derive(serde::Serialize)]
struct PackageState {
    name: String,
    expected: Option<String>,
    installed: Option<String>,
    matches: bool,
}
#[derive(serde::Serialize)]
struct RecoveryReport<'a> {
    journal: &'a Pending,
    packages: Vec<PackageState>,
    restorable: bool,
    next_steps: Vec<String>,
    logs: Vec<String>,
    log_notice: String,
}
fn log_context(
    path: &std::path::Path,
    packages: &[PackageState],
    since: i64,
) -> (Vec<String>, String) {
    use std::io::{Read as _, Seek as _};
    let read = || -> std::io::Result<Vec<String>> {
        let mut file = std::fs::File::open(path)?;
        let start = file.metadata()?.len().saturating_sub(256 * 1024);
        file.seek(std::io::SeekFrom::Start(start))?;
        let mut bytes = Vec::new();
        file.take(256 * 1024).read_to_end(&mut bytes)?;
        let text = String::from_utf8_lossy(&bytes);
        let lines = text
            .lines()
            .skip(usize::from(start != 0))
            .filter(|line| {
                let Some((stamp, message)) = line.strip_prefix('[').and_then(|s| s.split_once(']'))
                else {
                    return false;
                };
                let Ok(at) = jiff::Timestamp::strptime("%Y-%m-%dT%H:%M:%S%z", stamp) else {
                    return false;
                };
                at.as_second() >= since
                    && packages.iter().any(|p| {
                        [
                            "installed",
                            "upgraded",
                            "downgraded",
                            "removed",
                            "reinstalled",
                        ]
                        .iter()
                        .any(|verb| message.starts_with(&format!(" [ALPM] {verb} {} (", p.name)))
                    })
            })
            .map(str::to_owned)
            .collect::<Vec<_>>();
        Ok(lines
            .into_iter()
            .rev()
            .take(50)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect())
    };
    match read() {
        Ok(lines) => (lines, "Matching pacman log context since the intent (last 256 KiB, at most 50 lines); context is not proof of transaction identity or provenance.".into()),
        Err(err) => (Vec::new(), format!("Pacman log unavailable: {err}; journal certainty is unchanged.")),
    }
}

#[derive(Debug, thiserror::Error)]
#[error("package mutation completed; bookkeeping failed; inspect with pacvamp recover")]
pub(super) struct MutationCompleted;

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
        self.record(&intent).wrap_err(MutationCompleted)?;
        let mut finished = patch;
        finished.pending.insert(id, None);
        self.record(&finished).wrap_err(MutationCompleted)?;
        Ok(result)
    }
}
