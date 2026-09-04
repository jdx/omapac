use eyre::Result;
use serde::Serialize;
use usage_rs::RunWith;

use super::{App, print_json};
use crate::host::Host;
use crate::ledger::Ledger;
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
    /// Only packages pacvamp installed, with what it recorded
    #[usage(short = 'l', long)]
    ledger: bool,
    /// Only packages pacvamp installed whose state changed outside pacvamp
    #[usage(long)]
    drift: bool,
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
    /// What the ledger recorded, when pacvamp installed the package.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recorded: Option<Recorded>,
    /// How the machine differs from the ledger, for --drift.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub drift: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct Recorded {
    pub version: String,
    pub by: String,
    pub at: i64,
}

impl RunWith<&App> for List {
    type Output = Result<()>;

    fn run_with(self, app: &App) -> Self::Output {
        let host = app.host()?;
        let ledger = if self.ledger || self.drift {
            app.ledger()?
        } else {
            Ledger::default()
        };
        let entries = list(&host, &ledger, &self)?;
        if self.json {
            return print_json(&entries);
        }
        print!("{}", render(&entries));
        Ok(())
    }
}

pub fn list(host: &Host, ledger: &Ledger, filter: &List) -> Result<Vec<Entry>> {
    let orphans: Vec<String> = if filter.orphans {
        host.orphans()?.iter().map(|p| p.name.clone()).collect()
    } else {
        Vec::new()
    };
    let mut entries = Vec::new();
    if filter.drift {
        // Recorded but gone: only the ledger knows about these.
        for (name, recorded) in &ledger.packages {
            if host.installed_package(name)?.is_none() {
                let foreign = recorded.repo.is_none();
                if filter.explicit && !recorded.explicit
                    || filter.deps && recorded.explicit
                    || filter.orphans
                    || filter.foreign && !foreign
                    || filter.native && foreign
                {
                    continue;
                }
                entries.push(Entry {
                    name: name.clone(),
                    version: recorded.version.clone(),
                    tier: recorded.tier.clone(),
                    repo: recorded.repo.clone(),
                    reason: if recorded.explicit {
                        "explicit"
                    } else {
                        "dependency"
                    }
                    .to_string(),
                    recorded: Some(Recorded {
                        version: recorded.version.clone(),
                        by: recorded.by.clone(),
                        at: recorded.at,
                    }),
                    drift: Some("removed outside pacvamp".to_string()),
                });
            }
        }
    }
    for package in host.installed()? {
        let recorded = ledger.packages.get(&package.name);
        if (filter.ledger || filter.drift) && recorded.is_none() {
            continue;
        }
        let drift = recorded.and_then(|r| {
            (r.version != package.version)
                .then(|| format!("recorded {}, installed {}", r.version, package.version))
        });
        if filter.drift && drift.is_none() {
            continue;
        }
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
            recorded: recorded.map(|r| Recorded {
                version: r.version.clone(),
                by: r.by.clone(),
                at: r.at,
            }),
            drift,
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
        let mut extra = String::new();
        if let Some(recorded) = &entry.recorded {
            extra.push_str(&format!(
                "  by pacvamp {} {}",
                recorded.by,
                super::format_time(recorded.at)
            ));
        }
        if let Some(drift) = &entry.drift {
            extra.push_str(&format!("  drift: {drift}"));
        }
        out.push_str(&format!(
            "{:<name_width$}  {:<version_width$}  {:<origin_width$}  {}{extra}\n",
            entry.name,
            entry.version,
            origin(entry),
            entry.reason
        ));
    }
    out
}
