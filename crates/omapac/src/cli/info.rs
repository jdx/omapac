use std::fmt::Write as _;

use alpm_db::{Dependency, LocalPackage, SyncPackage};
use eyre::{Result, bail};
use serde::Serialize;
use usage_rs::RunWith;

use super::{App, format_size, format_time, print_json};
use crate::host::Host;
use crate::resolve::Tier;

/// Show what is known about packages
///
/// Looks each name up in the sync databases in repository order and in the
/// local database, and shows the repository, trust tier, metadata, and
/// installed state.
#[derive(Debug, usage_rs::Args)]
pub struct Info {
    /// Package names
    #[usage(required = true)]
    packages: Vec<String>,
    /// Print as JSON
    #[usage(short = 'J', long)]
    json: bool,
}

#[derive(Debug, Serialize)]
pub struct PackageInfo {
    pub name: String,
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
            match info(&host, name)? {
                Some(found) => infos.push(found),
                None => missing.push(name.clone()),
            }
        }
        if self.json {
            print_json(&infos)?;
        } else {
            for (i, found) in infos.iter().enumerate() {
                if i > 0 {
                    println!();
                }
                print!("{}", render(found));
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

pub fn info(host: &Host, name: &str) -> Result<Option<PackageInfo>> {
    let installed = host.installed_package(name)?;
    let installed_info = installed.map(|p: &LocalPackage| Installed {
        version: p.version.clone(),
        install_date: p.install_date,
        reason: match p.reason {
            alpm_db::InstallReason::Explicit => "explicit".to_string(),
            alpm_db::InstallReason::Dependency => "dependency".to_string(),
        },
        validation: p.validation.clone(),
    });
    if let Some((source, package)) = host.find_sync(name)? {
        let p: &SyncPackage = package;
        return Ok(Some(PackageInfo {
            name: p.name.clone(),
            tier: source.tier.clone(),
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
            installed: installed_info,
        }));
    }
    let Some(p) = installed else {
        return Ok(None);
    };
    Ok(Some(PackageInfo {
        name: p.name.clone(),
        tier: Tier::Foreign,
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
        installed: installed_info,
    }))
}

pub fn render(info: &PackageInfo) -> String {
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
    row("Version", info.version.clone().unwrap_or_default());
    row("Description", info.description.clone().unwrap_or_default());
    row("URL", info.url.clone().unwrap_or_default());
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
        if info.repo.is_some() {
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
