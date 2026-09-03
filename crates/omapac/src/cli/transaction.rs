//! What `install`, `remove`, and later `update` share: rendering a resolved
//! transaction by trust tier, the policy checks that apply to any
//! transaction, and the confirm-then-apply step.

use std::fmt::Write as _;
use std::io::Write as _;

use alpm_db::Check;
use eyre::{Result, bail};
use serde::Serialize;

use super::{check_rank, format_size, trust_rank};
use crate::engine::{ApplyOpts, Change, Engine, ResolvedTx};
use crate::host::Host;
use crate::ledger::{Entry, Patch};
use crate::resolve::Tier;
use crate::ui;

/// One change with the trust tier of where it comes from.
#[derive(Debug, Serialize)]
pub struct TieredChange {
    pub name: String,
    pub version: String,
    pub repo: Option<String>,
    /// Pacman reports packages removed by this transaction from `local`.
    pub removal: bool,
    pub tier: Tier,
    pub download_size: Option<u64>,
}

/// A resolved transaction annotated for display and policy.
#[derive(Debug, Serialize)]
pub struct Plan {
    pub changes: Vec<TieredChange>,
    pub download_size: u64,
    /// Problems that stop an unattended run and are shown to a human.
    pub warnings: Vec<String>,
    /// The command that would apply the transaction.
    pub command: String,
}

/// Annotate `resolved` with tiers and policy warnings.
pub fn plan(host: &Host, resolved: &ResolvedTx, command: String) -> Plan {
    let mut warnings = Vec::new();
    let changes: Vec<TieredChange> = resolved
        .changes
        .iter()
        .map(|change| tiered(host, change))
        .collect();
    for (resolved_change, change) in resolved.changes.iter().zip(&changes) {
        if resolved_change.repo.as_deref() != Some("local")
            && let Some(repo) = resolved_change.repo.as_deref()
            && let Some(source) = host.sources.iter().find(|s| s.name == repo)
        {
            let level = source.repo.sig_level;
            let floor = host.config.options.sig_level;
            let package_weak = check_rank(level.package()) < check_rank(floor.package())
                || (floor.package() != Check::Never
                    && trust_rank(level.package_trust()) < trust_rank(floor.package_trust()));
            let database_weak = check_rank(level.database()) < check_rank(floor.database())
                || (floor.database() != Check::Never
                    && trust_rank(level.database_trust()) < trust_rank(floor.database_trust()));
            if level.package() == Check::Never && floor.package() != Check::Never {
                warnings.push(format!(
                    "{}: repository [{repo}] does not check package signatures",
                    change.name
                ));
            } else if package_weak {
                warnings.push(format!(
                    "{}: repository [{repo}] has package SigLevel {level}, weaker than the floor ({floor})",
                    change.name
                ));
            }
            if level.database() == Check::Never && floor.database() != Check::Never {
                warnings.push(format!(
                    "{}: repository [{repo}] does not check database signatures",
                    change.name
                ));
            } else if database_weak {
                warnings.push(format!(
                    "{}: repository [{repo}] has database SigLevel {level}, weaker than the floor ({floor})",
                    change.name
                ));
            }
            if matches!(change.tier, Tier::Custom(_)) {
                warnings.push(format!(
                    "{}: repository [{repo}] is outside Arch and Omarchy review",
                    change.name
                ));
            }
        }
    }
    // pacman asks before removing a HoldPkg package; upgrades are fine.
    if matches!(
        resolved.transaction.operation,
        crate::engine::Operation::Remove { .. }
    ) {
        let hold: Vec<&str> = changes
            .iter()
            .filter(|c| host.config.options.hold_pkg.contains(&c.name))
            .map(|c| c.name.as_str())
            .collect();
        if !hold.is_empty() {
            warnings.push(format!("HoldPkg: {}", hold.join(", ")));
        }
    }
    Plan {
        download_size: changes.iter().filter_map(|c| c.download_size).sum(),
        changes,
        warnings,
        command,
    }
}

fn tiered(host: &Host, change: &Change) -> TieredChange {
    let removal = change.repo.as_deref() == Some("local");
    let tier = match change.repo.as_deref() {
        Some("local") | None => host
            .find_sync(&change.name)
            .ok()
            .flatten()
            .map(|(source, _)| source.tier.clone())
            .unwrap_or(Tier::Foreign),
        Some(repo) => Tier::of_repo(repo),
    };
    TieredChange {
        name: change.name.clone(),
        version: change.version.clone(),
        repo: change.repo.clone().filter(|r| r != "local"),
        removal,
        tier,
        download_size: change.download_size,
    }
}

/// Render a plan for a human.
pub fn render(verb: &str, plan: &Plan) -> String {
    let mut out = String::new();
    if plan.changes.is_empty() {
        let _ = writeln!(out, "nothing to {verb}");
        return out;
    }
    let _ = writeln!(out, "{verb} {} package(s):", plan.changes.len());
    let name_width = plan
        .changes
        .iter()
        .map(|c| c.name.len() + c.repo.as_ref().map_or(0, |r| r.len() + 1))
        .max()
        .unwrap_or(0);
    let version_width = plan
        .changes
        .iter()
        .map(|c| c.version.len())
        .max()
        .unwrap_or(0);
    for change in &plan.changes {
        let qualified = match &change.repo {
            Some(repo) => format!("{repo}/{}", change.name),
            None => change.name.clone(),
        };
        let _ = writeln!(
            out,
            "  {qualified:<name_width$}  {:<version_width$}  [{}]",
            change.version, change.tier
        );
    }
    if plan.download_size > 0 {
        let _ = writeln!(out, "download size: {}", format_size(plan.download_size));
    }
    for warning in &plan.warnings {
        let _ = writeln!(out, "warning: {warning}");
    }
    out
}

/// Show the plan, then confirm and apply it unless this is a dry run.
///
/// Unattended runs (`yes`) refuse a plan with warnings: what a human is
/// warned about, automation is denied. See `PLAN.md`, principle 5.
pub fn confirm_and_apply(
    engine: &dyn Engine,
    resolved: &ResolvedTx,
    plan: &Plan,
    verb: &str,
    yes: bool,
    dry_run: bool,
) -> Result<bool> {
    print!("{}", render(verb, plan));
    std::io::stdout().flush()?;
    if plan.changes.is_empty() {
        return Ok(false);
    }
    if dry_run {
        println!("would run: {}", plan.command);
        return Ok(false);
    }
    if yes {
        let blocking = plan
            .warnings
            .iter()
            .filter(|warning| {
                verb != "upgrade" || !warning.contains("is outside Arch and Omarchy review")
            })
            .count();
        if blocking != 0 {
            bail!(
                "refusing to {verb} unattended with {} warning(s); run interactively to decide",
                blocking
            );
        }
    } else {
        println!("run: {}", plan.command);
        if !ui::confirm("Proceed?", true)? {
            bail!("cancelled");
        }
    }
    engine.apply(
        resolved,
        ApplyOpts {
            dry_run: false,
            no_confirm: apply_no_confirm(plan, yes),
        },
    )?;
    Ok(true)
}

/// The ledger patch for a plan that was performed: every installed change
/// is recorded, explicit when it was a target, and every removal dropped.
pub fn ledger_patch(plan: &Plan, targets: &[String], by: &str, removing: bool) -> Patch {
    let mut patch = Patch::default();
    let at = crate::ledger::now();
    for change in &plan.changes {
        if removing || change.removal {
            patch.remove.push(change.name.clone());
            continue;
        }
        patch.upsert.insert(
            change.name.clone(),
            Entry {
                version: change.version.clone(),
                tier: change.tier.clone(),
                repo: change.repo.clone(),
                aur_commit: None,
                explicit: targets.iter().any(|t| t == &change.name),
                by: by.to_string(),
                at,
            },
        );
    }
    patch
}

/// Reconstruct ledger entries from packages that are already in the local
/// database. This lets a repeated command repair a ledger write that failed
/// after pacman had successfully changed the machine.
pub fn ledger_patch_for_installed(
    host: &Host,
    ledger: &crate::ledger::Ledger,
    names: &[String],
    explicit: bool,
    by: &str,
) -> Result<Patch> {
    let mut patch = Patch::default();
    let at = crate::ledger::now();
    let installed = host.installed()?;
    let roots: std::collections::BTreeSet<&str> = names.iter().map(String::as_str).collect();
    let mut pending = names.to_vec();
    let mut seen = std::collections::BTreeSet::new();
    while let Some(name) = pending.pop() {
        if !seen.insert(name.clone()) {
            continue;
        }
        let Some(package) = installed.iter().find(|package| package.name == name) else {
            continue;
        };
        for dependency in &package.depends {
            if let Some(provider) = installed
                .iter()
                .find(|candidate| candidate.satisfies(dependency))
            {
                pending.push(provider.name.clone());
            }
        }
        if ledger.packages.contains_key(&name) {
            continue;
        }
        let source = host.find_sync(&name)?.map(|(source, _)| source);
        patch.upsert.insert(
            name.clone(),
            Entry {
                version: package.version.clone(),
                tier: source.map_or(Tier::Foreign, |source| source.tier.clone()),
                repo: source.map(|source| source.name.clone()),
                aur_commit: None,
                explicit: roots.contains(name.as_str()) && explicit,
                by: by.to_string(),
                at,
            },
        );
    }
    Ok(patch)
}

/// Whether the eventual pacman command may suppress prompts. Interactive
/// HoldPkg removals must leave pacman's override question available.
pub fn apply_no_confirm(plan: &Plan, yes: bool) -> bool {
    yes || !plan
        .warnings
        .iter()
        .any(|warning| warning.starts_with("HoldPkg:"))
}
