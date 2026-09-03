//! `omapac audit`: installed packages joined against Arch's security
//! tracker. A package is vulnerable when a tracker group lists it, the
//! group is not "Not affected", and the installed version is below the
//! fixed version (or nothing is fixed yet).

use std::cmp::Ordering;
use std::path::PathBuf;

use eyre::{Context as _, Result};
use serde::{Deserialize, Serialize};

pub const TRACKER_URL: &str = "https://security.archlinux.org/all.json";

/// One AVG group as the tracker publishes it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Group {
    pub name: String,
    #[serde(default)]
    pub packages: Vec<String>,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub severity: String,
    #[serde(default, rename = "type")]
    pub kind: String,
    #[serde(default)]
    pub affected: Option<String>,
    #[serde(default)]
    pub fixed: Option<String>,
    #[serde(default)]
    pub ticket: Option<String>,
    #[serde(default)]
    pub issues: Vec<String>,
    #[serde(default)]
    pub advisories: Vec<String>,
}

/// Severity order, worst first.
pub fn severity_rank(severity: &str) -> u8 {
    match severity.to_ascii_lowercase().as_str() {
        "critical" => 0,
        "high" => 1,
        "medium" => 2,
        "low" => 3,
        _ => 4,
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Vulnerability {
    pub package: String,
    pub installed: String,
    pub group: String,
    pub severity: String,
    pub status: String,
    pub kind: String,
    pub fixed: Option<String>,
    /// Whether an upgrade would resolve it: a fixed version exists.
    pub fix_available: bool,
    pub issues: Vec<String>,
    pub advisories: Vec<String>,
}

/// Where the tracker comes from and where it is cached.
pub struct Source {
    pub url: String,
    pub cache: PathBuf,
}

impl Source {
    pub fn default_source() -> Source {
        let url =
            std::env::var("OMAPAC_SECURITY_TRACKER_URL").unwrap_or_else(|_| TRACKER_URL.into());
        Source {
            url,
            cache: crate::aur::cache_dir()
                .parent()
                .unwrap_or_else(|| std::path::Path::new("."))
                .join("audit/all.json"),
        }
    }

    /// Fetch the tracker, falling back to the cache when the network
    /// fails; `offline` reads the cache only. Returns the groups and
    /// whether they came from the cache.
    pub fn load(&self, offline: bool) -> Result<(Vec<Group>, bool)> {
        if !offline {
            let live = (|| -> Result<Vec<Group>> {
                let bytes = fetch(&self.url)?;
                let groups: Vec<Group> =
                    serde_json::from_slice(&bytes).wrap_err("parsing the security tracker")?;
                if let Some(parent) = self.cache.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                let temp = self.cache.with_extension("tmp");
                std::fs::write(&temp, &bytes)?;
                std::fs::rename(&temp, &self.cache)?;
                Ok(groups)
            })();
            match live {
                Ok(groups) => return Ok((groups, false)),
                Err(err) => {
                    if !self.cache.is_file() {
                        return Err(err);
                    }
                    eprintln!("warning: {err:#}; using the cached tracker");
                }
            }
        }
        let bytes = std::fs::read(&self.cache).wrap_err_with(|| {
            format!(
                "no cached security tracker at {}; run without --offline once",
                self.cache.display()
            )
        })?;
        let groups =
            serde_json::from_slice(&bytes).wrap_err("parsing the cached security tracker")?;
        Ok((groups, true))
    }
}

fn fetch(url: &str) -> Result<Vec<u8>> {
    let mut response = ureq::get(url)
        .call()
        .wrap_err_with(|| format!("fetching {url}"))?;
    response
        .body_mut()
        .with_config()
        .limit(64 * 1024 * 1024)
        .read_to_vec()
        .wrap_err_with(|| format!("reading {url}"))
}

/// Join installed `(name, version)` pairs against the groups.
pub fn evaluate(installed: &[(String, String)], groups: &[Group]) -> Vec<Vulnerability> {
    let mut out = Vec::new();
    for group in groups {
        if group.status.eq_ignore_ascii_case("not affected") {
            continue;
        }
        for (name, version) in installed {
            if !group.packages.iter().any(|p| p == name) {
                continue;
            }
            let vulnerable = match &group.fixed {
                Some(fixed) => alpm_db::vercmp::vercmp(version, fixed) == Ordering::Less,
                None => true,
            };
            if !vulnerable {
                continue;
            }
            out.push(Vulnerability {
                package: name.clone(),
                installed: version.clone(),
                group: group.name.clone(),
                severity: group.severity.clone(),
                status: group.status.clone(),
                kind: group.kind.clone(),
                fixed: group.fixed.clone(),
                fix_available: group.fixed.is_some(),
                issues: group.issues.clone(),
                advisories: group.advisories.clone(),
            });
        }
    }
    out.sort_by(|a, b| {
        severity_rank(&a.severity)
            .cmp(&severity_rank(&b.severity))
            .then_with(|| a.package.cmp(&b.package))
            .then_with(|| a.group.cmp(&b.group))
    });
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn group(
        name: &str,
        package: &str,
        status: &str,
        severity: &str,
        fixed: Option<&str>,
    ) -> Group {
        Group {
            name: name.into(),
            packages: vec![package.into()],
            status: status.into(),
            severity: severity.into(),
            kind: "arbitrary code execution".into(),
            affected: Some("1-1".into()),
            fixed: fixed.map(str::to_string),
            ticket: None,
            issues: vec!["CVE-2026-0001".into()],
            advisories: Vec::new(),
        }
    }

    #[test]
    fn joins_by_pacman_version_order() {
        let installed = vec![
            ("pacman".to_string(), "7.1.0-2".to_string()),
            ("glibc".to_string(), "2.41+r7+g1234-1".to_string()),
            ("zlib".to_string(), "1:1.3.1-2".to_string()),
        ];
        let groups = vec![
            group("AVG-1", "pacman", "Vulnerable", "High", Some("7.1.1-1")),
            group("AVG-2", "glibc", "Fixed", "Medium", Some("2.40-1")),
            group("AVG-3", "zlib", "Vulnerable", "Critical", None),
            group("AVG-4", "zlib", "Not affected", "Critical", None),
            group("AVG-5", "pacman", "Fixed", "Low", Some("7.1.0-2")),
            group("AVG-6", "other", "Vulnerable", "High", None),
        ];
        let found = evaluate(&installed, &groups);
        let names: Vec<(&str, &str)> = found
            .iter()
            .map(|v| (v.group.as_str(), v.package.as_str()))
            .collect();
        assert_eq!(names, vec![("AVG-3", "zlib"), ("AVG-1", "pacman")]);
        assert!(!found[0].fix_available);
        assert!(found[1].fix_available);
    }

    #[test]
    fn severities_rank_worst_first() {
        assert!(severity_rank("Critical") < severity_rank("High"));
        assert!(severity_rank("high") < severity_rank("Medium"));
        assert!(severity_rank("Low") < severity_rank("Unknown"));
    }
}
