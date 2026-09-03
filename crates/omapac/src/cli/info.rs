use std::fmt::Write as _;

use alpm_db::{Dependency, LocalPackage, SyncPackage};
use eyre::{Context as _, Result, bail};
use serde::Serialize;
use usage_rs::RunWith;

use super::search::AurMeta;
use super::{App, format_size, format_time, print_json};
use crate::aur::rpc::Rpc;
use crate::host::Host;
use crate::resolve::Tier;

/// Show what is known about packages
///
/// Looks each name up in the sync databases in repository order and in the
/// local database, and shows the repository, trust tier, metadata, and
/// installed state. A name no repository carries is looked up on the AUR,
/// where the maintainer, votes, and ages are what matter.
#[derive(Debug, usage_rs::Args)]
pub struct Info {
    /// Package names
    #[usage(required = true)]
    packages: Vec<String>,
    /// Look on the AUR even when a repository carries the name
    #[usage(short = 'a', long)]
    aur: bool,
    /// Never consult the AUR
    #[usage(long)]
    no_aur: bool,
    /// Print as JSON
    #[usage(short = 'J', long)]
    json: bool,
}

#[derive(Debug, Serialize)]
pub struct PackageInfo {
    pub name: String,
    /// The source package, which is what the release train tests name.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub pkgbase: String,
    pub tier: Tier,
    pub repo: Option<String>,
    pub version: Option<String>,
    pub description: Option<String>,
    pub url: Option<String>,
    pub licenses: Vec<String>,
    pub groups: Vec<String>,
    pub provides: Vec<String>,
    pub depends: Vec<String>,
    pub optdepends: Vec<String>,
    pub conflicts: Vec<String>,
    pub replaces: Vec<String>,
    pub download_size: Option<u64>,
    pub installed_size: Option<u64>,
    pub packager: Option<String>,
    pub build_date: Option<i64>,
    pub sha256sum: Option<String>,
    pub signed: bool,
    pub installed: Option<Installed>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aur: Option<AurMeta>,
    /// Where the package stands in the release train, for the Arch tier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub train: Option<Train>,
}

/// The tested-versus-snapshot label from the channel's release manifest.
#[derive(Debug, Clone, Serialize)]
pub struct Train {
    pub snapshot: String,
    /// Whether the suite exercised this package's pkgbase.
    pub tested: bool,
}

#[derive(Debug, Serialize)]
pub struct Installed {
    pub version: String,
    pub install_date: Option<i64>,
    pub reason: String,
    pub validation: Vec<String>,
}

impl RunWith<&App> for Info {
    type Output = Result<()>;

    fn run_with(self, app: &App) -> Self::Output {
        let host = app.host()?;
        let mut infos = Vec::new();
        let mut missing = Vec::new();
        for name in &self.packages {
            let found = if self.aur { None } else { info(&host, name)? };
            let found = match found {
                Some(found) if found.tier == Tier::Foreign && !self.no_aur => {
                    match info_aur(&host, &app.aur_rpc(), name) {
                        Ok(aur) => aur.or(Some(found)),
                        Err(err) => {
                            eprintln!(
                                "warning: AUR metadata unavailable for installed package {name}: {err:#}"
                            );
                            Some(found)
                        }
                    }
                }
                Some(found) => Some(found),
                None if self.no_aur => None,
                None => info_aur(&host, &app.aur_rpc(), name)?,
            };
            match found {
                Some(found) => infos.push(found),
                None => missing.push(name.clone()),
            }
        }
        // The release train label for Arch-tier packages, from the cached
        // release manifest when there is one.
        if infos.iter().any(|i| matches!(i.tier, Tier::Arch))
            && let Ok(Some(release)) = app.release(&host, true)
        {
            for found in infos.iter_mut().filter(|i| matches!(i.tier, Tier::Arch)) {
                found.train = Some(Train {
                    snapshot: release.id.clone(),
                    tested: release.is_tested(&found.pkgbase),
                });
            }
        }
        if self.json {
            print_json(&infos)?;
        } else {
            let now = crate::ledger::now();
            for (i, found) in infos.iter().enumerate() {
                if i > 0 {
                    println!();
                }
                print!("{}", render(found, now));
            }
        }
        if !missing.is_empty() {
            bail!("package not found: {}", missing.join(", "));
        }
        Ok(())
    }
}

fn names(deps: &[Dependency]) -> Vec<String> {
    deps.iter().map(ToString::to_string).collect()
}

fn installed_info(p: &LocalPackage) -> Installed {
    Installed {
        version: p.version.clone(),
        install_date: p.install_date,
        reason: match p.reason {
            alpm_db::InstallReason::Explicit => "explicit".to_string(),
            alpm_db::InstallReason::Dependency => "dependency".to_string(),
        },
        validation: p.validation.clone(),
    }
}

pub fn info(host: &Host, name: &str) -> Result<Option<PackageInfo>> {
    let installed_package = host.installed_package(name)?;
    let installed = installed_package.map(installed_info);
    if let Some((source, package)) = host.find_sync(name)? {
        let p: &SyncPackage = package;
        return Ok(Some(PackageInfo {
            name: p.name.clone(),
            pkgbase: p.base.clone().unwrap_or_else(|| p.name.clone()),
            tier: source.tier.clone(),
            train: None,
            repo: Some(source.name.clone()),
            version: Some(p.version.clone()),
            description: p.desc.clone(),
            url: p.url.clone(),
            licenses: p.licenses.clone(),
            groups: p.groups.clone(),
            provides: names(&p.provides),
            depends: names(&p.depends),
            optdepends: names(&p.optdepends),
            conflicts: names(&p.conflicts),
            replaces: names(&p.replaces),
            download_size: p.csize,
            installed_size: p.isize,
            packager: p.packager.clone(),
            build_date: p.build_date,
            sha256sum: p.sha256sum.clone(),
            signed: p.pgpsig.is_some(),
            installed,
            aur: None,
        }));
    }
    let Some(p) = installed_package else {
        return Ok(None);
    };
    Ok(Some(PackageInfo {
        name: p.name.clone(),
        pkgbase: p.base.clone().unwrap_or_else(|| p.name.clone()),
        tier: Tier::Foreign,
        train: None,
        repo: None,
        version: Some(p.version.clone()),
        description: p.desc.clone(),
        url: p.url.clone(),
        licenses: p.licenses.clone(),
        groups: p.groups.clone(),
        provides: names(&p.provides),
        depends: names(&p.depends),
        optdepends: names(&p.optdepends),
        conflicts: names(&p.conflicts),
        replaces: names(&p.replaces),
        download_size: None,
        installed_size: p.size,
        packager: p.packager.clone(),
        build_date: p.build_date,
        sha256sum: None,
        signed: false,
        installed,
        aur: None,
    }))
}

/// What the AUR knows about `name`.
pub fn info_aur(host: &Host, rpc: &dyn Rpc, name: &str) -> Result<Option<PackageInfo>> {
    let packages = rpc.info(&[name]).wrap_err("asking the AUR")?;
    let Some(p) = packages.into_iter().find(|p| p.name == name) else {
        return Ok(None);
    };
    let installed = host.installed_package(name)?.map(installed_info);
    Ok(Some(PackageInfo {
        name: p.name.clone(),
        pkgbase: p.package_base.clone(),
        tier: Tier::Aur,
        train: None,
        repo: Some("aur".to_string()),
        version: Some(p.version.clone()),
        description: p.description.clone(),
        url: p.url.clone(),
        licenses: p.license.clone(),
        groups: p.groups.clone(),
        provides: p.provides.clone(),
        depends: p.depends.clone(),
        optdepends: p.opt_depends.clone(),
        conflicts: p.conflicts.clone(),
        replaces: p.replaces.clone(),
        download_size: None,
        installed_size: None,
        packager: None,
        build_date: None,
        sha256sum: None,
        signed: false,
        installed,
        aur: Some(AurMeta::from_rpc(&p)),
    }))
}

pub fn render(info: &PackageInfo, now: i64) -> String {
    let mut out = String::new();
    let mut row = |label: &str, value: String| {
        if !value.is_empty() {
            let _ = writeln!(out, "{label:<16} {value}");
        }
    };
    row("Name", info.name.clone());
    row(
        "Repository",
        match &info.repo {
            Some(repo) => format!("{repo} [{}]", info.tier),
            None => format!("none [{}]", info.tier),
        },
    );
    if let Some(train) = &info.train {
        row(
            "Release Train",
            if train.tested {
                format!("tested in snapshot {}", train.snapshot)
            } else {
                format!("in snapshot {}, not exercised by the suite", train.snapshot)
            },
        );
    }
    row("Version", info.version.clone().unwrap_or_default());
    row("Description", info.description.clone().unwrap_or_default());
    row("URL", info.url.clone().unwrap_or_default());
    if let Some(aur) = &info.aur {
        row(
            "Maintainer",
            aur.maintainer
                .clone()
                .unwrap_or_else(|| "none (orphan)".to_string()),
        );
        if let Some(submitter) = &aur.submitter {
            let hands = match &aur.maintainer {
                Some(m) if m != submitter => " (package changed hands)",
                _ => "",
            };
            row("Submitter", format!("{submitter}{hands}"));
        }
        row(
            "Votes",
            format!("{} (popularity {:.2})", aur.votes, aur.popularity),
        );
        row(
            "First Submitted",
            format!(
                "{} ({})",
                format_time(aur.first_submitted),
                crate::aur::format_age(aur.first_submitted, now)
            ),
        );
        row(
            "Last Modified",
            format!(
                "{} ({})",
                format_time(aur.last_modified),
                crate::aur::format_age(aur.last_modified, now)
            ),
        );
        row(
            "Out Of Date",
            aur.out_of_date
                .map(|t| format!("yes, since {}", format_time(t)))
                .unwrap_or_else(|| "no".to_string()),
        );
    }
    row("Licenses", info.licenses.join("  "));
    row("Groups", info.groups.join("  "));
    row("Provides", info.provides.join("  "));
    row("Depends On", info.depends.join("  "));
    row("Optional Deps", info.optdepends.join("\n                 "));
    row("Conflicts With", info.conflicts.join("  "));
    row("Replaces", info.replaces.join("  "));
    row(
        "Download Size",
        info.download_size.map(format_size).unwrap_or_default(),
    );
    row(
        "Installed Size",
        info.installed_size.map(format_size).unwrap_or_default(),
    );
    row("Packager", info.packager.clone().unwrap_or_default());
    row(
        "Build Date",
        info.build_date.map(format_time).unwrap_or_default(),
    );
    row(
        "Signature",
        if info.repo.is_some() && info.aur.is_none() {
            if info.signed { "present" } else { "absent" }.to_string()
        } else {
            String::new()
        },
    );
    match &info.installed {
        Some(installed) => {
            row(
                "Installed",
                format!(
                    "{} ({}){}",
                    installed.version,
                    installed.reason,
                    installed
                        .install_date
                        .map(|d| format!(", {}", format_time(d)))
                        .unwrap_or_default()
                ),
            );
            row("Validated By", installed.validation.join("  "));
        }
        None => row("Installed", "no".to_string()),
    }
    out
}
