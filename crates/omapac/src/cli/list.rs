use eyre::Result;
use serde::Serialize;
use usage_rs::RunWith;

use super::{App, print_json};
use crate::host::Host;
use crate::resolve::Tier;

/// List installed packages with their trust tier
#[derive(Debug, usage_rs::Args)]
pub struct List {
    /// Only packages installed explicitly
    #[usage(short = 'e', long)]
    explicit: bool,
    /// Only packages installed as dependencies
    #[usage(short = 'd', long)]
    deps: bool,
    /// Only packages no sync database carries (usually AUR builds)
    #[usage(short = 'f', long)]
    foreign: bool,
    /// Only packages a sync database carries
    #[usage(short = 'n', long)]
    native: bool,
    /// Only dependencies nothing installed needs any more
    #[usage(short = 'o', long)]
    orphans: bool,
    /// Print as JSON
    #[usage(short = 'J', long)]
    json: bool,
}

#[derive(Debug, Serialize)]
pub struct Entry {
    pub name: String,
    pub version: String,
    pub tier: Tier,
    pub repo: Option<String>,
    pub reason: String,
}

impl RunWith<&App> for List {
    type Output = Result<()>;

    fn run_with(self, app: &App) -> Self::Output {
        let host = app.host()?;
        let entries = list(&host, &self)?;
        if self.json {
            return print_json(&entries);
        }
        print!("{}", render(&entries));
        Ok(())
    }
}

pub fn list(host: &Host, filter: &List) -> Result<Vec<Entry>> {
    let orphans: Vec<String> = if filter.orphans {
        host.orphans()?.iter().map(|p| p.name.clone()).collect()
    } else {
        Vec::new()
    };
    let mut entries = Vec::new();
    for package in host.installed()? {
        let explicit = package.reason == alpm_db::InstallReason::Explicit;
        if filter.explicit && !explicit || filter.deps && explicit {
            continue;
        }
        if filter.orphans && !orphans.contains(&package.name) {
            continue;
        }
        let (tier, repo) = match host.find_sync(&package.name)? {
            Some((source, _)) => (source.tier.clone(), Some(source.name.clone())),
            None => (Tier::Foreign, None),
        };
        let foreign = repo.is_none();
        if filter.foreign && !foreign || filter.native && foreign {
            continue;
        }
        entries.push(Entry {
            name: package.name.clone(),
            version: package.version.clone(),
            tier,
            repo,
            reason: if explicit { "explicit" } else { "dependency" }.to_string(),
        });
    }
    Ok(entries)
}

pub fn render(entries: &[Entry]) -> String {
    let origin = |entry: &Entry| match &entry.repo {
        Some(repo) => format!("{repo} [{}]", entry.tier),
        None => format!("[{}]", entry.tier),
    };
    let name_width = entries.iter().map(|e| e.name.len()).max().unwrap_or(0);
    let version_width = entries.iter().map(|e| e.version.len()).max().unwrap_or(0);
    let origin_width = entries.iter().map(|e| origin(e).len()).max().unwrap_or(0);
    let mut out = String::new();
    for entry in entries {
        out.push_str(&format!(
            "{:<name_width$}  {:<version_width$}  {:<origin_width$}  {}\n",
            entry.name,
            entry.version,
            origin(entry),
            entry.reason
        ));
    }
    out
}
