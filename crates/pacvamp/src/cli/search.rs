use eyre::{Context as _, Result};
use serde::Serialize;
use usage_rs::RunWith;

use super::{App, print_json};
use crate::aur::rpc::Rpc;
use crate::host::Host;
use crate::resolve::Tier;

/// Search the sync databases, or the AUR, by name and description
///
/// Every term must match, case-insensitively, in the package name or
/// description. Repository results are grouped in pacman.conf order with
/// the trust tier of each repository. With --aur the AUR is searched
/// instead, and each hit shows its votes, maintainer, and age.
#[derive(Debug, usage_rs::Args)]
pub struct Search {
    /// Words to look for
    #[usage(required = true)]
    terms: Vec<String>,
    /// Search the AUR instead of the repositories
    #[usage(short = 'a', long)]
    aur: bool,
    /// Only show packages that are installed
    #[usage(short = 'i', long)]
    installed: bool,
    /// Print as JSON
    #[usage(short = 'J', long)]
    json: bool,
    /// Choose hits in a picker and install them
    #[usage(short = 'p', long)]
    pick: bool,
}

/// What the AUR knows about a hit, beyond name and description.
#[derive(Debug, Clone, Serialize)]
pub struct AurMeta {
    pub package_base: String,
    pub maintainer: Option<String>,
    pub submitter: Option<String>,
    pub votes: u64,
    pub popularity: f64,
    pub first_submitted: i64,
    pub last_modified: i64,
    pub out_of_date: Option<i64>,
}

impl AurMeta {
    pub fn from_rpc(package: &crate::aur::rpc::Package) -> AurMeta {
        AurMeta {
            package_base: package.package_base.clone(),
            maintainer: package.maintainer.clone(),
            submitter: package.submitter.clone(),
            votes: package.num_votes,
            popularity: package.popularity,
            first_submitted: package.first_submitted,
            last_modified: package.last_modified,
            out_of_date: package.out_of_date,
        }
    }
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aur: Option<AurMeta>,
}

impl RunWith<&App> for Search {
    type Output = Result<()>;

    fn run_with(self, app: &App) -> Self::Output {
        let host = app.host()?;
        let hits = if self.aur {
            search_aur(&host, &app.aur_rpc(), &self.terms, self.installed)?
        } else {
            search(&host, &self.terms, self.installed)?
        };
        if self.json {
            return print_json(&hits);
        }
        if self.pick {
            return pick_and_install(app, &hits, self.aur);
        }
        print!("{}", render(&hits, crate::ledger::now()));
        Ok(())
    }
}

/// Open the picker over `hits` and install what was chosen.
fn pick_and_install(app: &App, hits: &[Hit], aur: bool) -> Result<()> {
    crate::tui::require_terminal("search --pick", "run without --pick")?;
    if hits.is_empty() {
        eprintln!("nothing matched");
        return Ok(());
    }
    let items: Vec<crate::tui::Item> = hits
        .iter()
        .map(|hit| {
            let mut note = hit.tier.to_string();
            if hit.installed.is_some() {
                note.push_str(", installed");
            }
            crate::tui::Item::new(
                hit.name.clone(),
                format!(
                    "{} {}  {}",
                    hit.version,
                    hit.repo,
                    hit.description.as_deref().unwrap_or_default()
                ),
                note,
            )
        })
        .collect();
    let Some(chosen) = crate::tui::pick("Install", items, true)? else {
        eprintln!("nothing chosen");
        return Ok(());
    };
    let packages: Vec<String> = chosen
        .iter()
        .map(|&i| {
            if aur {
                hits[i].name.clone()
            } else {
                format!("{}/{}", hits[i].repo, hits[i].name)
            }
        })
        .collect();
    super::install::Install::for_packages(packages, aur).run_with(app)
}

fn matches(terms: &[String], name: &str, description: Option<&str>) -> bool {
    let haystack = format!(
        "{}\n{}",
        name.to_lowercase(),
        description.unwrap_or_default().to_lowercase()
    );
    terms.iter().all(|term| haystack.contains(term.as_str()))
}

pub fn search(host: &Host, terms: &[String], only_installed: bool) -> Result<Vec<Hit>> {
    let terms: Vec<String> = terms.iter().map(|t| t.to_lowercase()).collect();
    let installed = host.installed_by_name()?;
    let mut hits = Vec::new();
    for source in &host.sources {
        for package in crate::search_cache::packages(source)? {
            if !matches(&terms, &package.name, package.desc.as_deref()) {
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
                aur: None,
            });
        }
    }
    Ok(hits)
}

/// The RPC searches by one keyword; the rest are matched here.
pub fn search_aur(
    host: &Host,
    rpc: &dyn Rpc,
    terms: &[String],
    only_installed: bool,
) -> Result<Vec<Hit>> {
    let terms: Vec<String> = terms.iter().map(|t| t.to_lowercase()).collect();
    let keyword = terms
        .iter()
        .max_by_key(|t| t.len())
        .cloned()
        .unwrap_or_default();
    let mut packages = rpc.search(&keyword).wrap_err("searching the AUR")?;
    packages.sort_by(|a, b| {
        b.popularity
            .partial_cmp(&a.popularity)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.name.cmp(&b.name))
    });
    let installed = host.installed_by_name()?;
    let mut hits = Vec::new();
    for package in &packages {
        if !matches(&terms, &package.name, package.description.as_deref()) {
            continue;
        }
        let installed_version = installed
            .get(package.name.as_str())
            .map(|p| p.version.clone());
        if only_installed && installed_version.is_none() {
            continue;
        }
        hits.push(Hit {
            repo: "aur".to_string(),
            tier: Tier::Aur,
            name: package.name.clone(),
            version: package.version.clone(),
            description: package.description.clone(),
            installed: installed_version,
            aur: Some(AurMeta::from_rpc(package)),
        });
    }
    Ok(hits)
}

pub fn render(hits: &[Hit], now: i64) -> String {
    let mut out = String::new();
    for hit in hits {
        let installed = match &hit.installed {
            Some(v) if *v == hit.version => " [installed]".to_string(),
            Some(v) => format!(" [installed: {v}]"),
            None => String::new(),
        };
        let aur = match &hit.aur {
            Some(meta) => format!(
                " (votes {}, {}, updated {}{})",
                meta.votes,
                match &meta.maintainer {
                    Some(m) => format!("maintainer {m}"),
                    None => "orphan".to_string(),
                },
                crate::aur::format_age(meta.last_modified, now),
                if meta.out_of_date.is_some() {
                    ", flagged out of date"
                } else {
                    ""
                }
            ),
            None => String::new(),
        };
        out.push_str(&format!(
            "{}/{} {} [{}]{}{}\n    {}\n",
            hit.repo,
            hit.name,
            hit.version,
            hit.tier,
            installed,
            aur,
            hit.description.as_deref().unwrap_or("")
        ));
    }
    out
}
