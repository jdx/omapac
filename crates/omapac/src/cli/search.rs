use eyre::Result;
use serde::Serialize;
use usage_rs::RunWith;

use super::{App, print_json};
use crate::host::Host;
use crate::resolve::Tier;

/// Search the sync databases by name and description
///
/// Every term must match, case-insensitively, in the package name or
/// description. Results are grouped by repository in pacman.conf order,
/// with the trust tier of each repository.
#[derive(Debug, usage_rs::Args)]
pub struct Search {
    /// Words to look for
    #[usage(required = true)]
    terms: Vec<String>,
    /// Only show packages that are installed
    #[usage(short = 'i', long)]
    installed: bool,
    /// Print as JSON
    #[usage(short = 'J', long)]
    json: bool,
}

#[derive(Debug, Serialize)]
pub struct Hit {
    pub repo: String,
    pub tier: Tier,
    pub name: String,
    pub version: String,
    pub description: Option<String>,
    /// The installed version, when installed.
    pub installed: Option<String>,
}

impl RunWith<&App> for Search {
    type Output = Result<()>;

    fn run_with(self, app: &App) -> Self::Output {
        let host = app.host()?;
        let hits = search(&host, &self.terms, self.installed)?;
        if self.json {
            return print_json(&hits);
        }
        print!("{}", render(&hits));
        Ok(())
    }
}

pub fn search(host: &Host, terms: &[String], only_installed: bool) -> Result<Vec<Hit>> {
    let terms: Vec<String> = terms.iter().map(|t| t.to_lowercase()).collect();
    let installed = host.installed_by_name()?;
    let mut hits = Vec::new();
    for source in &host.sources {
        let Some(db) = source.db()? else {
            continue;
        };
        for package in &db.packages {
            let haystack = format!(
                "{}\n{}",
                package.name.to_lowercase(),
                package.desc.as_deref().unwrap_or_default().to_lowercase()
            );
            if !terms.iter().all(|term| haystack.contains(term.as_str())) {
                continue;
            }
            let installed_version = installed
                .get(package.name.as_str())
                .map(|p| p.version.clone());
            if only_installed && installed_version.is_none() {
                continue;
            }
            hits.push(Hit {
                repo: source.name.clone(),
                tier: source.tier.clone(),
                name: package.name.clone(),
                version: package.version.clone(),
                description: package.desc.clone(),
                installed: installed_version,
            });
        }
    }
    Ok(hits)
}

pub fn render(hits: &[Hit]) -> String {
    let mut out = String::new();
    for hit in hits {
        let installed = match &hit.installed {
            Some(v) if *v == hit.version => " [installed]".to_string(),
            Some(v) => format!(" [installed: {v}]"),
            None => String::new(),
        };
        out.push_str(&format!(
            "{}/{} {} [{}]{}\n    {}\n",
            hit.repo,
            hit.name,
            hit.version,
            hit.tier,
            installed,
            hit.description.as_deref().unwrap_or("")
        ));
    }
    out
}
