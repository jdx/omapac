//! Plain facts about an AUR package at a candidate commit. The client
//! fills these from the RPC, a git checkout, and `.SRCINFO`; the server
//! fills them from the same sources on its side. Nothing here knows how.

use serde::{Deserialize, Serialize};

/// What the AUR RPC says about the package now.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Rpc {
    pub maintainer: Option<String>,
    pub submitter: Option<String>,
    pub first_submitted: i64,
    pub last_modified: i64,
    pub num_votes: u64,
    pub popularity: f64,
    pub out_of_date: Option<i64>,
    pub pending_requests: u64,
}

/// The candidate commit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Commit {
    pub hash: String,
    /// Committer time, unix seconds.
    pub time: i64,
}

/// What was approved last time, from the lockfile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Approved {
    pub commit: String,
    pub maintainer: Option<String>,
    /// Hosts of every remote source at the approved commit.
    pub source_hosts: Vec<String>,
    /// Install scriptlets at the approved commit.
    pub install_files: Vec<String>,
}

/// One `source` entry of the recipe.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Source {
    pub url: String,
    pub host: Option<String>,
    pub is_vcs: bool,
    pub is_local: bool,
}

/// The recipe at the candidate commit, from `.SRCINFO`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Recipe {
    pub version: String,
    pub sources: Vec<Source>,
    pub skipped_checksum: bool,
    pub install_files: Vec<String>,
}

/// The change from the approved commit to the candidate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Diff {
    pub lines_changed: usize,
    pub changed_files: Vec<String>,
    /// How long the package had been untouched before this change.
    pub quiet_secs_before: Option<i64>,
}

/// A reviewer's verdict on this pkgbase and commit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Verdict {
    /// `static`, `av`, `ai`, `human`, `reproducible`, or a vendor's kind.
    pub reviewer_kind: String,
    pub reviewer: String,
    pub verdict: VerdictKind,
    pub summary: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum VerdictKind {
    Pass,
    Flag,
    Block,
}

/// An advisory that names the package or its upstream.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Advisory {
    /// Where it came from: `osv`, `opr`, `arch-news`.
    pub source: String,
    pub summary: String,
}

/// Everything the engine looks at.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Evidence {
    pub pkgbase: String,
    /// Unix seconds, so evaluation is reproducible.
    pub now: i64,
    pub rpc: Option<Rpc>,
    pub target: Commit,
    pub approved: Option<Approved>,
    /// Whether the caller pinned a commit; drift only matters then.
    pub pinned: bool,
    /// Whether this package has never been installed here.
    pub first_install: bool,
    pub recipe: Recipe,
    pub diff: Option<Diff>,
    /// The PKGBUILD text at the candidate commit.
    pub pkgbuild: Option<String>,
    /// Install scriptlet texts at the candidate commit, by file name.
    pub install_scripts: Vec<(String, String)>,
    /// Names this pkgbase resembles, computed by the caller.
    pub similar_names: Vec<String>,
    pub verdicts: Vec<Verdict>,
    pub advisories: Vec<Advisory>,
}

impl Evidence {
    /// Every text the sniff catalogue scans, with its file name.
    pub fn texts(&self) -> Vec<(&str, &str)> {
        let mut texts = Vec::new();
        if let Some(pkgbuild) = &self.pkgbuild {
            texts.push(("PKGBUILD", pkgbuild.as_str()));
        }
        for (name, text) in &self.install_scripts {
            texts.push((name.as_str(), text.as_str()));
        }
        texts
    }
}
