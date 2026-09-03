//! The feed documents. Each is a JSON file with a detached minisign
//! signature beside it, signed with a distro trust key.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// `omapac-index.json`: what the repository currently serves.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Index {
    pub version: u32,
    pub repo: String,
    /// Monotonically increasing; a client refuses a lower one.
    pub sequence: u64,
    pub generated_at: String,
    /// The pacman database file and its digest.
    pub db: IndexDb,
    /// By package file name.
    pub packages: BTreeMap<String, IndexPackage>,
    /// Public keys (minisign format) of the build hosts whose provenance
    /// statements this repository accepts.
    #[serde(default)]
    pub build_keys: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndexDb {
    pub file: String,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct IndexPackage {
    pub sha256: String,
    pub size: u64,
    /// RFC 3339.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub published_at: Option<String>,
    /// File names next to the package: `.sig`, `.sigstore.json`,
    /// `.vendor.sigstore.json`, `.scan.sigstore.json`.
    #[serde(default)]
    pub sidecars: Vec<String>,
    #[serde(default)]
    pub evidence: Evidence,
}

/// What the repository claims it holds for a package.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct Evidence {
    /// A build provenance statement from an accepted build key.
    #[serde(default)]
    pub build_provenance: bool,
    /// A verified vendor packslip chained in.
    #[serde(default)]
    pub vendor_manifest: bool,
    /// How many reviewer verdicts cover the package digest.
    #[serde(default)]
    pub verdicts: u32,
    /// Whether a second builder reproduced it.
    #[serde(default)]
    pub reproducible: Option<bool>,
}

impl Index {
    /// The entry for a package file name.
    pub fn package(&self, filename: &str) -> Option<&IndexPackage> {
        self.packages.get(filename)
    }

    /// The publish time of a package as unix seconds, when recorded.
    pub fn published_at(&self, filename: &str) -> Option<i64> {
        self.package(filename)?
            .published_at
            .as_deref()?
            .parse::<jiff::Timestamp>()
            .ok()
            .map(|t| t.as_second())
    }
}

/// `advisories.json`: the kill list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Advisories {
    pub version: u32,
    pub sequence: u64,
    pub issued_at: String,
    pub advisories: Vec<Advisory>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Advisory {
    pub id: String,
    pub pkgbase: String,
    /// Affected AUR commits; empty means every commit.
    #[serde(default)]
    pub commits: Vec<String>,
    /// Affected versions; empty means every version.
    #[serde(default)]
    pub versions: Vec<String>,
    /// `aur`, `opr`, or `arch`.
    #[serde(default)]
    pub tier: Option<String>,
    pub action: AdvisoryAction,
    pub reason: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    pub issued_at: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AdvisoryAction {
    /// Never install or build.
    Block,
    /// Do not move to it automatically; a human may.
    Hold,
}

impl Advisories {
    /// Advisories that name `pkgbase` at `commit` or `version`.
    pub fn matching<'a>(
        &'a self,
        pkgbase: &str,
        commit: Option<&str>,
        version: Option<&str>,
    ) -> Vec<&'a Advisory> {
        self.advisories
            .iter()
            .filter(|a| a.pkgbase == pkgbase)
            .filter(|a| {
                let commit_hit = a.commits.is_empty()
                    || commit.is_some_and(|c| a.commits.iter().any(|x| c.starts_with(x.as_str())));
                let version_hit = a.versions.is_empty()
                    || version.is_some_and(|v| a.versions.iter().any(|x| x == v));
                commit_hit && version_hit
            })
            .collect()
    }
}

/// `verdicts.json`: reviewer verdicts the repository republishes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Verdicts {
    pub version: u32,
    pub sequence: u64,
    pub issued_at: String,
    pub verdicts: Vec<Verdict>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Verdict {
    pub subject: VerdictSubject,
    pub reviewer: Reviewer,
    pub verdict: VerdictKind,
    #[serde(default)]
    pub summary: String,
    #[serde(default)]
    pub findings: Vec<String>,
    pub issued_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum VerdictSubject {
    /// An AUR recipe at a commit.
    Commit { pkgbase: String, commit: String },
    /// A built package file.
    Digest { sha256: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Reviewer {
    /// `static`, `av`, `ai`, `human`, `reproducible`, or a vendor's kind.
    pub kind: String,
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum VerdictKind {
    Pass,
    Flag,
    Block,
}

impl Verdicts {
    /// Verdicts on an AUR pkgbase at a commit.
    pub fn for_commit<'a>(&'a self, pkgbase: &str, commit: &str) -> Vec<&'a Verdict> {
        self.verdicts
            .iter()
            .filter(|v| match &v.subject {
                VerdictSubject::Commit {
                    pkgbase: p,
                    commit: c,
                } => p == pkgbase && commit.starts_with(c.as_str()),
                VerdictSubject::Digest { .. } => false,
            })
            .collect()
    }

    /// Verdicts on a package file digest.
    pub fn for_digest<'a>(&'a self, sha256: &str) -> Vec<&'a Verdict> {
        self.verdicts
            .iter()
            .filter(|v| matches!(&v.subject, VerdictSubject::Digest { sha256: s } if s == sha256))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn advisories_match_by_commit_and_version() {
        let feed: Advisories = serde_json::from_str(
            r#"{"version":1,"sequence":3,"issued_at":"2026-09-03T00:00:00Z","advisories":[
              {"id":"OPR-2026-001","pkgbase":"yay","commits":["abcdef12"],"action":"block","reason":"takeover","issued_at":"2026-09-03T00:00:00Z"},
              {"id":"OPR-2026-002","pkgbase":"chrome","versions":["1.0-1"],"tier":"aur","action":"hold","reason":"bad build","issued_at":"2026-09-03T00:00:00Z"},
              {"id":"OPR-2026-003","pkgbase":"evil","action":"block","reason":"malware","issued_at":"2026-09-03T00:00:00Z"}
            ]}"#,
        )
        .unwrap();
        assert_eq!(
            feed.matching("yay", Some("abcdef1234567890"), None).len(),
            1
        );
        assert!(feed.matching("yay", Some("ffffffff"), None).is_empty());
        assert_eq!(feed.matching("chrome", None, Some("1.0-1")).len(), 1);
        assert!(feed.matching("chrome", None, Some("1.0-2")).is_empty());
        assert_eq!(
            feed.matching("evil", None, None).len(),
            1,
            "no filters means everything"
        );
        assert_eq!(feed.matching("evil", Some("x"), Some("y")).len(), 1);
    }

    #[test]
    fn verdict_subjects_are_untagged() {
        let feed: Verdicts = serde_json::from_str(
            r#"{"version":1,"sequence":1,"issued_at":"2026-09-03T00:00:00Z","verdicts":[
              {"subject":{"pkgbase":"yay","commit":"abc"},"reviewer":{"kind":"ai","id":"opr-reviewer","version":"2"},"verdict":"block","summary":"exfiltrates","issued_at":"2026-09-03T00:00:00Z"},
              {"subject":{"sha256":"ff"},"reviewer":{"kind":"av","id":"clamav"},"verdict":"pass","issued_at":"2026-09-03T00:00:00Z"}
            ]}"#,
        )
        .unwrap();
        assert_eq!(feed.for_commit("yay", "abcdef").len(), 1);
        assert!(feed.for_commit("yay", "xyz").is_empty());
        assert_eq!(feed.for_digest("ff").len(), 1);
        assert_eq!(feed.verdicts[0].verdict, VerdictKind::Block);
    }

    #[test]
    fn index_published_at() {
        let index: Index = serde_json::from_str(
            r#"{"version":1,"repo":"omarchy","sequence":9,"generated_at":"2026-09-03T00:00:00Z",
                "db":{"file":"omarchy.db","sha256":"00"},
                "packages":{"a-1-1-x86_64.pkg.tar.zst":{"sha256":"aa","size":1,"published_at":"2026-09-01T00:00:00Z","sidecars":["a-1-1-x86_64.pkg.tar.zst.sig"],"evidence":{"build_provenance":true,"verdicts":2}}}}"#,
        )
        .unwrap();
        assert_eq!(
            index.published_at("a-1-1-x86_64.pkg.tar.zst"),
            Some(1_788_220_800)
        );
        assert_eq!(index.published_at("nope"), None);
        assert!(
            index
                .package("a-1-1-x86_64.pkg.tar.zst")
                .unwrap()
                .evidence
                .build_provenance
        );
        assert!(index.build_keys.is_empty());
    }
}
