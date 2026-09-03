use eyre::Result;
use serde::Serialize;
use usage_rs::RunWith;

use super::{App, print_json};
use crate::audit::{Source, Vulnerability, evaluate};

/// List installed packages with open security issues
///
/// Joins the local database against Arch's security tracker: a package
/// is listed when a tracker group names it, the group is not "Not
/// affected", and the installed version is below the fixed one (or no
/// fix exists yet). Versions compare the way pacman compares them.
#[derive(Debug, usage_rs::Args)]
pub struct Audit {
    /// Only issues an upgrade would fix
    #[usage(short = 'u', long)]
    upgradable: bool,
    /// Use the cached tracker only
    #[usage(long)]
    offline: bool,
    /// Exit 1 when any issue is listed
    #[usage(long)]
    fail: bool,
    /// Print as JSON
    #[usage(short = 'J', long)]
    json: bool,
}

#[derive(Debug, Serialize)]
pub struct Report {
    pub from_cache: bool,
    pub vulnerabilities: Vec<Vulnerability>,
}

impl RunWith<&App> for Audit {
    type Output = Result<()>;

    fn run_with(self, app: &App) -> Self::Output {
        let host = app.host()?;
        let installed: Vec<(String, String)> = host
            .installed()?
            .iter()
            .map(|p| (p.name.clone(), p.version.clone()))
            .collect();
        let (groups, from_cache) = Source::default_source().load(self.offline)?;
        let mut vulnerabilities = evaluate(&installed, &groups);
        let open_count = vulnerabilities.len();
        if self.upgradable {
            vulnerabilities.retain(|v| v.fix_available);
        }
        let report = Report {
            from_cache,
            vulnerabilities,
        };
        if self.json {
            print_json(&report)?;
        } else {
            if report.from_cache {
                eprintln!("note: tracker read from the cache");
            }
            if report.vulnerabilities.is_empty() {
                if self.upgradable && open_count > 0 {
                    println!(
                        "no open security issues with an available upgrade; {open_count} open issue(s) have no fix yet"
                    );
                } else {
                    println!("no open security issues among installed packages");
                }
            }
            for v in &report.vulnerabilities {
                println!(
                    "{:<9} {} {} ({}) {}: {}{}",
                    v.severity,
                    v.package,
                    v.installed,
                    v.group,
                    v.kind,
                    match &v.fixed {
                        Some(fixed) => format!("fixed in {fixed}"),
                        None => "no fix yet".to_string(),
                    },
                    if v.issues.is_empty() {
                        String::new()
                    } else {
                        format!("  [{}]", v.issues.join(", "))
                    }
                );
            }
        }
        if self.fail && !report.vulnerabilities.is_empty() {
            std::process::exit(1);
        }
        Ok(())
    }
}
