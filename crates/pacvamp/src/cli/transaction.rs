//! What `install`, `remove`, and later `update` share: rendering a resolved
//! transaction by trust tier, the policy checks that apply to any
//! transaction, and the confirm-then-apply step.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::io::Write as _;

use alpm_db::Check;
use eyre::{Result, bail};
use serde::Serialize;

use super::{check_rank, format_size, trust_rank};
use crate::engine::{ApplyOpts, Change, Engine, ResolvedTx};
use crate::host::Host;
use crate::ledger::Verification;
use crate::ledger::{Entry, Patch};
use crate::manifest::settings::{Enforcement, Settings};
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
    plan_with_custom_repos(
        host,
        resolved,
        command,
        crate::manifest::settings::CustomRepos::Warn,
    )
}

pub fn plan_with_custom_repos(
    host: &Host,
    resolved: &ResolvedTx,
    command: String,
    custom_repos: crate::manifest::settings::CustomRepos,
) -> Plan {
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
                match custom_repos {
                    crate::manifest::settings::CustomRepos::Allow => {}
                    crate::manifest::settings::CustomRepos::Warn => warnings.push(format!(
                        "{}: repository [{repo}] is outside Arch and Omarchy review",
                        change.name
                    )),
                    crate::manifest::settings::CustomRepos::Deny => warnings.push(format!(
                        "{}: repository [{repo}] is denied by trust.custom_repos policy",
                        change.name
                    )),
                }
            }
        }
    }
    // Pacman asks before removing HoldPkg entries, including removals caused
    // by replacements or conflicts during an upgrade.
    let hold: Vec<&str> = changes
        .iter()
        .filter(|change| change.removal && host.config.options.hold_pkg.contains(&change.name))
        .map(|change| change.name.as_str())
        .collect();
    if !hold.is_empty() {
        warnings.push(format!("HoldPkg: {}", hold.join(", ")));
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
    app: &super::App,
    engine: &dyn Engine,
    resolved: &ResolvedTx,
    plan: &Plan,
    verb: &str,
    yes: bool,
    dry_run: bool,
) -> Result<bool> {
    if !confirm_plan(plan, verb, yes, dry_run)? {
        return Ok(false);
    }
    let removing = matches!(
        resolved.transaction.operation,
        crate::engine::Operation::Remove { .. }
    );
    let patch = intent_patch(app, resolved, plan, verb, removing)?;
    app.journaled(patch, || apply_confirmed(engine, resolved, plan, yes))
}

/// Show and confirm a plan without applying it yet.
pub fn confirm_plan(plan: &Plan, verb: &str, yes: bool, dry_run: bool) -> Result<bool> {
    print!("{}", render(verb, plan));
    std::io::stdout().flush()?;
    if plan.changes.is_empty() {
        return Ok(false);
    }
    if dry_run {
        println!("would run: {}", plan.command);
        return Ok(false);
    }
    validate_plan(plan, verb, yes)?;
    if !yes {
        println!("run: {}", plan.command);
        if !ui::confirm("Proceed?", true)? {
            bail!("cancelled");
        }
    }
    Ok(true)
}

/// Enforce the unattended warning policy before any side effects begin.
pub fn validate_plan(plan: &Plan, verb: &str, yes: bool) -> Result<()> {
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
    }
    Ok(())
}

/// Apply a plan whose containing workflow has already confirmed it.
pub fn apply_confirmed(
    engine: &dyn Engine,
    resolved: &ResolvedTx,
    plan: &Plan,
    yes: bool,
) -> Result<bool> {
    if plan.changes.is_empty() {
        return Ok(false);
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

fn intent_patch(
    app: &super::App,
    resolved: &ResolvedTx,
    plan: &Plan,
    by: &str,
    removing: bool,
) -> Result<Patch> {
    let host = app.host()?;
    let mut explicit = Vec::new();
    for change in &plan.changes {
        if host
            .installed_package(&change.name)?
            .is_some_and(|p| p.reason == alpm_db::InstallReason::Explicit)
        {
            explicit.push(change.name.clone());
        }
    }
    if let crate::engine::Operation::Install {
        targets,
        as_deps: false,
        ..
    } = &resolved.transaction.operation
    {
        explicit.extend(targets.iter().map(|t| t.name.clone()));
    }
    let mut patch = ledger_patch(plan, &explicit, by, removing);
    if let crate::engine::Operation::Install {
        targets,
        as_deps: true,
        ..
    } = &resolved.transaction.operation
    {
        for target in targets {
            if let Some(entry) = patch.upsert.get_mut(&target.name) {
                entry.explicit = false;
                patch.install_reasons.insert(target.name.clone(), false);
            }
        }
    }
    Ok(patch)
}

/// Repository evidence accepted for a resolved transaction. Callers merge
/// this into the package ledger patch after pacman succeeds, so package state
/// and rollback state are written atomically.
#[derive(Debug, Default, Clone)]
pub struct AcceptedEvidence {
    packages: BTreeMap<String, Verification>,
    index_sequences: BTreeMap<String, u64>,
}

impl AcceptedEvidence {
    pub fn attach(self, patch: &mut Patch) {
        for (name, verification) in self.packages {
            if let Some(entry) = patch.upsert.get_mut(&name) {
                entry.verification = Some(verification);
            }
        }
        patch.index_sequences.extend(self.index_sequences);
    }
}

/// Cache, verify, and apply a repository transaction. Verification happens
/// after confirmation but before pacman can change the installed package set.
pub fn verify_and_apply(
    app: &super::App,
    host: &Host,
    settings: &Settings,
    engine: &dyn Engine,
    resolved: &ResolvedTx,
    plan: &Plan,
    yes: bool,
) -> Result<Option<AcceptedEvidence>> {
    if plan.changes.is_empty() {
        return Ok(None);
    }
    let evidence = verify_transaction(app, host, settings, engine, resolved)?;
    let removing = matches!(
        resolved.transaction.operation,
        crate::engine::Operation::Remove { .. }
    );
    let mut patch = intent_patch(app, resolved, plan, "transaction", removing)?;
    evidence.clone().attach(&mut patch);
    app.journaled(patch, || apply_confirmed(engine, resolved, plan, yes))?;
    Ok(Some(evidence))
}

fn verify_transaction(
    app: &super::App,
    host: &Host,
    settings: &Settings,
    engine: &dyn Engine,
    resolved: &ResolvedTx,
) -> Result<AcceptedEvidence> {
    let applicable: Vec<_> = resolved
        .changes
        .iter()
        .filter(|change| {
            change
                .repo
                .as_deref()
                .is_some_and(|repo| matches!(Tier::of_repo(repo), Tier::Opr | Tier::Custom(_)))
        })
        .collect();
    if applicable.is_empty()
        || (settings.trust_index == Enforcement::Off
            && settings.trust_provenance == Enforcement::Off)
    {
        return Ok(AcceptedEvidence::default());
    }

    let ledger = app.ledger()?;
    let mut indexes = BTreeMap::new();
    for repo in applicable
        .iter()
        .filter_map(|change| change.repo.as_deref())
        .collect::<std::collections::BTreeSet<_>>()
    {
        match app.index_readonly(host, repo, false) {
            Ok(fetched) => {
                let db = app
                    .rooted(&host.config.options.db_path())
                    .join("sync")
                    .join(&fetched.value.db.file);
                if !db.is_file() {
                    bail!("[{repo}] repository database {} is missing", db.display());
                }
                let digest = crate::trust::sha256_file(&db)?;
                if digest != fetched.value.db.sha256 {
                    bail!(
                        "[{repo}] repository database does not match signed index sequence {}",
                        fetched.value.sequence
                    );
                }
                indexes.insert(repo.to_string(), fetched);
            }
            Err(err)
                if settings.trust_index == Enforcement::Required
                    || settings.trust_provenance == Enforcement::Required =>
            {
                return Err(err.wrap_err(format!(
                    "[{repo}] required transaction evidence unavailable"
                )));
            }
            Err(err) => {
                let detail = format!("{err:#}");
                if detail.contains("signature")
                    || detail.contains("does not verify")
                    || detail.contains("parsing pacvamp-index.json")
                    || detail.contains("different repository")
                    || detail.contains("older than")
                    || detail.contains("rolled-back")
                {
                    return Err(err.wrap_err(format!("[{repo}] transaction index is invalid")));
                }
                if settings.trust_no_downgrade
                    && let Some((change, previous)) = applicable.iter().find_map(|change| {
                        (change.repo.as_deref() == Some(repo))
                            .then(|| {
                                ledger
                                    .packages
                                    .get(&change.name)
                                    .and_then(|entry| entry.verification.as_ref())
                                    .map(|previous| (*change, previous))
                            })
                            .flatten()
                    })
                {
                    bail!(
                        "{} evidence would downgrade from {} because [{repo}] index is unavailable",
                        change.name,
                        previous.level
                    );
                }
                eprintln!("warning: [{repo}] transaction index could not be verified: {err:#}");
            }
        }
    }

    // pacman downloads the already-resolved transaction without installing
    // it. The subsequent apply consumes these same named cache files.
    if !indexes.is_empty() {
        engine.download(
            resolved,
            ApplyOpts {
                dry_run: false,
                no_confirm: true,
            },
        )?;
    }

    let mut accepted = AcceptedEvidence::default();
    for change in applicable {
        let repo = change.repo.as_deref().expect("filtered above");
        let Some(fetched) = indexes.get(repo) else {
            continue;
        };
        let (_, package) = host.find_sync_in(repo, &change.name)?.ok_or_else(|| {
            eyre::eyre!(
                "{} from [{repo}] disappeared from its repository database",
                change.name
            )
        })?;
        if package.version != change.version {
            bail!(
                "{} plan selected {} from [{repo}], but its database now selects {}",
                change.name,
                change.version,
                package.version
            );
        }
        let location_file = change
            .location
            .as_deref()
            .and_then(|url| url.rsplit('/').next());
        if location_file != Some(package.filename.as_str()) {
            bail!(
                "{} plan location is not the exact file named by [{repo}]",
                change.name
            );
        }
        let Some(indexed) = fetched.value.package(&package.filename) else {
            if settings.trust_index == Enforcement::Required {
                bail!(
                    "{} is not in required [{repo}] index sequence {}",
                    package.filename,
                    fetched.value.sequence
                );
            }
            if settings.trust_no_downgrade
                && let Some(previous) = ledger
                    .packages
                    .get(&change.name)
                    .and_then(|entry| entry.verification.as_ref())
            {
                bail!(
                    "{} evidence would downgrade from {} because it is absent from [{repo}] index sequence {}",
                    change.name,
                    previous.level,
                    fetched.value.sequence
                );
            }
            eprintln!(
                "warning: {} is not in [{repo}] index sequence {}",
                package.filename, fetched.value.sequence
            );
            continue;
        };
        let file = host
            .config
            .options
            .cache_dirs()
            .into_iter()
            .map(|dir| app.rooted(&dir).join(&package.filename))
            .find(|path| path.is_file())
            .ok_or_else(|| {
                eyre::eyre!("pacman did not cache {} for verification", package.filename)
            })?;
        let (digest, size) = packslip::digest_file(&file)?;
        if digest != indexed.sha256 || size != indexed.size {
            bail!(
                "{} cached package does not match [{repo}] index sequence {}",
                package.filename,
                fetched.value.sequence
            );
        }

        let provenance_name = format!("{}.provenance.json", package.filename);
        let publishes_provenance = indexed.evidence.build_provenance
            && indexed
                .sidecars
                .iter()
                .any(|sidecar| sidecar == &provenance_name);
        let build_key = if publishes_provenance && settings.trust_provenance != Enforcement::Off {
            let source = app.feed_source(host, repo).expect("index source exists");
            let (report, _) = super::verify::check_provenance(
                &source,
                &package.filename,
                &indexed.sha256,
                &fetched.value.build_keys,
            );
            if !report.verified {
                bail!(
                    "{} provenance failed: {}",
                    package.filename,
                    report.error.as_deref().unwrap_or("unknown error")
                );
            }
            report.build_key
        } else {
            if settings.trust_provenance == Enforcement::Required {
                bail!(
                    "{} has no required build provenance in [{repo}] index sequence {}",
                    package.filename,
                    fetched.value.sequence
                );
            }
            if settings.trust_provenance == Enforcement::Verify {
                eprintln!(
                    "warning: {} publishes no build provenance",
                    package.filename
                );
            }
            None
        };
        let level = if build_key.is_some() {
            pacvamp_policy::Level::L3
        } else {
            pacvamp_policy::Level::L2
        };
        if settings.trust_no_downgrade
            && let Some(previous) = ledger
                .packages
                .get(&change.name)
                .and_then(|entry| entry.verification.as_ref())
            && level < previous.level
        {
            bail!(
                "{} evidence would downgrade from {} to {}",
                change.name,
                previous.level,
                level
            );
        }
        accepted
            .index_sequences
            .insert(repo.to_string(), fetched.value.sequence);
        accepted.packages.insert(
            change.name.clone(),
            Verification {
                index_sequence: fetched.value.sequence,
                index_key: fetched.key_id.clone(),
                sha256: indexed.sha256.clone(),
                level,
                build_key,
            },
        );
    }
    Ok(accepted)
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
                verification: None,
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
                verification: None,
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
