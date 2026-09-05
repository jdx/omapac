use eyre::{Result, bail};
use serde::Serialize;
use usage_rs::RunWith;

use super::{App, print_json};
use crate::aur::rpc::Rpc;
use crate::manifest::{PackageToml, Source, edit};

/// Preview a manifest from explicitly installed packages
///
/// Matches current repositories and queries AUR metadata for foreign packages.
/// Existing declarations are preserved. Unknown foreign packages are skipped;
/// an AUR match is a candidate source, not proof of the installed build's origin.
/// No packages are installed and no approvals or provenance are created.
#[derive(Debug, usage_rs::Args)]
pub struct Import {
    /// Save the proposed additions to the user manifest without installing anything
    #[usage(long)]
    write: bool,
    /// Do not query the AUR; foreign packages remain unresolved
    #[usage(long)]
    offline: bool,
    /// Print the preview as JSON; incompatible with --write
    #[usage(short = 'J', long)]
    json: bool,
}

#[derive(Serialize)]
struct Entry {
    name: String,
    installed: String,
    source: Option<Source>,
    repo: Option<String>,
    action: &'static str,
    review: &'static str,
    evidence: &'static str,
    detail: String,
}

#[derive(Serialize)]
struct Preview {
    manifest_path: std::path::PathBuf,
    entries: Vec<Entry>,
    warnings: Vec<String>,
    manifest: String,
}

impl RunWith<&App> for Import {
    type Output = Result<()>;

    fn run_with(self, app: &App) -> Result<()> {
        if self.json && self.write {
            bail!("--json is a preview; use --write separately to save the additions");
        }
        let host = app.host()?;
        let manifest = app.manifest()?;
        let ledger = app.ledger()?;
        let paths = app.manifest_paths();
        let mut installed: Vec<_> = host.installed()?.iter().collect();
        installed.retain(|p| p.reason == alpm_db::InstallReason::Explicit);
        installed.sort_by(|a, b| a.name.cmp(&b.name));
        let mut foreign = Vec::new();
        for package in &installed {
            if !manifest.packages.contains_key(&package.name)
                && host.find_sync(&package.name)?.is_none()
            {
                foreign.push(package.name.as_str());
            }
        }
        let mut warnings = Vec::new();
        let aur = if self.offline || foreign.is_empty() {
            Vec::new()
        } else {
            match app.aur_rpc().info(&foreign) {
                Ok(packages) => packages,
                Err(err) => {
                    warnings.push(format!(
                        "AUR lookup failed; foreign packages remain unresolved: {err:#}"
                    ));
                    Vec::new()
                }
            }
        };
        let mut entries = Vec::new();
        let mut additions = Vec::new();
        for package in installed {
            let recorded = ledger
                .packages
                .get(&package.name)
                .filter(|entry| entry.version == package.version);
            let mut entry = Entry {
                name: package.name.clone(),
                installed: package.version.clone(),
                source: None,
                repo: None,
                action: "skip",
                review: "unreviewed",
                evidence: if recorded.is_some_and(|entry| entry.verification.is_some()) {
                    "recorded for this version; not reverified by import"
                } else {
                    "no repository provenance recorded for this version"
                },
                detail: String::new(),
            };
            if let Some(declared) = manifest.packages.get(&package.name) {
                entry.action = "preserve";
                entry.source = Some(declared.package.source);
                entry.repo = declared.package.repo.clone();
                entry.detail = format!(
                    "already declared in {}; existing state and policy preserved",
                    declared.declared_in.display()
                );
            } else if let Some((source, _)) = host.find_sync(&package.name)? {
                entry.action = "add";
                entry.source = Some(Source::Repo);
                entry.repo = Some(source.name.clone());
                entry.detail =
                    "name matches a current repository; installed origin is not inferred".into();
            } else if aur.iter().any(|candidate| candidate.name == package.name) {
                entry.action = "add";
                entry.source = Some(Source::Aur);
                entry.detail = format!(
                    "AUR candidate; review with `pacvamp aur review -- {}` before approving a build",
                    crate::engine::sudo::quote(&package.name)
                );
            } else {
                entry.detail = if self.offline {
                    "foreign package; AUR lookup disabled by --offline"
                } else {
                    "unknown foreign package; select its source manually"
                }
                .into();
            }
            if entry.action == "add" {
                additions.push((
                    package.name.clone(),
                    PackageToml {
                        source: entry.source.expect("an addition has a source"),
                        repo: entry.repo.clone(),
                        ..Default::default()
                    },
                ));
            }
            entries.push(entry);
        }
        let preview = Preview {
            manifest: edit::import_packages(&paths.user, &additions, false)?,
            manifest_path: paths.user.clone(),
            entries,
            warnings,
        };
        if self.json {
            return print_json(&preview);
        }
        for warning in &preview.warnings {
            eprintln!("warning: {warning}");
        }
        for entry in &preview.entries {
            println!(
                "{} {} {}: {}; {}; {}",
                entry.action,
                entry.name,
                entry.installed,
                entry.detail,
                entry.review,
                entry.evidence
            );
        }
        println!("\nProposed {}:\n{}", paths.user.display(), preview.manifest);
        if self.write {
            edit::import_packages(&paths.user, &additions, true)?;
            println!(
                "Saved {} addition(s). No packages installed or commits approved.",
                additions.len()
            );
        } else {
            println!(
                "Preview only. Run `pacvamp import --write{}` to save additions.",
                if self.offline { " --offline" } else { "" }
            );
        }
        Ok(())
    }
}
