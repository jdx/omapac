use serde::{Deserialize, Serialize};

use crate::{Decision, Mode};

/// The catalogue of findings. Ids are stable strings in kebab-case, used
/// in config overrides, JSON, and verdict statements.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FindingId {
    /// First submitted more recently than the minimum package age.
    NewPackage,
    /// The target commit is younger than the minimum commit age.
    RecentCommit,
    /// The maintainer differs from the approved commit's, the package
    /// changed hands before a first install, or requests are pending.
    MaintainerChanged,
    /// No maintainer.
    Orphaned,
    /// Votes below the floor on a first install.
    LowReputation,
    /// The name resembles a repository or popular package.
    SimilarName,
    /// A source host that the approved commit did not use.
    SourceDomainChanged,
    /// A non-VCS source with checksum `SKIP`.
    ChecksumSkip,
    /// Builds from a version-control source.
    VcsSource,
    /// An install scriptlet was added or changed.
    InstallScript,
    /// A pattern from the sniff catalogue in the PKGBUILD or a scriptlet.
    SuspiciousContent,
    /// A language package manager install inside the recipe.
    LanguageDep,
    /// A large diff after a long quiet period.
    PkgbuildLargeDiff,
    /// The target commit differs from the locked commit.
    CommitDrift,
    /// A reviewer's flag or block verdict.
    Verdict,
    /// An advisory names the package or its upstream.
    UpstreamAdvisory,
    /// Flagged out of date on the AUR.
    OutOfDate,
}

impl FindingId {
    /// The decision the mode makes for this finding when no override says
    /// otherwise. See the table in `PLAN.md`, "Client-side features".
    pub fn default_decision(self, mode: Mode) -> Decision {
        match (self, mode) {
            (FindingId::OutOfDate, _) => Decision::Allow,
            (FindingId::VcsSource, Mode::Interactive) => Decision::Allow,
            (FindingId::VcsSource, Mode::Unattended) => Decision::Warn,
            (_, Mode::Interactive) => Decision::Warn,
            (_, Mode::Unattended) => Decision::Deny,
        }
    }

    /// The stable string form.
    pub fn as_str(self) -> &'static str {
        match self {
            FindingId::NewPackage => "new-package",
            FindingId::RecentCommit => "recent-commit",
            FindingId::MaintainerChanged => "maintainer-changed",
            FindingId::Orphaned => "orphaned",
            FindingId::LowReputation => "low-reputation",
            FindingId::SimilarName => "similar-name",
            FindingId::SourceDomainChanged => "source-domain-changed",
            FindingId::ChecksumSkip => "checksum-skip",
            FindingId::VcsSource => "vcs-source",
            FindingId::InstallScript => "install-script",
            FindingId::SuspiciousContent => "suspicious-content",
            FindingId::LanguageDep => "language-dep",
            FindingId::PkgbuildLargeDiff => "pkgbuild-large-diff",
            FindingId::CommitDrift => "commit-drift",
            FindingId::Verdict => "verdict",
            FindingId::UpstreamAdvisory => "upstream-advisory",
            FindingId::OutOfDate => "out-of-date",
        }
    }

    /// Every id, for documentation and config validation.
    pub const ALL: [FindingId; 17] = [
        FindingId::NewPackage,
        FindingId::RecentCommit,
        FindingId::MaintainerChanged,
        FindingId::Orphaned,
        FindingId::LowReputation,
        FindingId::SimilarName,
        FindingId::SourceDomainChanged,
        FindingId::ChecksumSkip,
        FindingId::VcsSource,
        FindingId::InstallScript,
        FindingId::SuspiciousContent,
        FindingId::LanguageDep,
        FindingId::PkgbuildLargeDiff,
        FindingId::CommitDrift,
        FindingId::Verdict,
        FindingId::UpstreamAdvisory,
        FindingId::OutOfDate,
    ];
}

impl std::str::FromStr for FindingId {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        FindingId::ALL
            .into_iter()
            .find(|id| id.as_str() == s)
            .ok_or_else(|| format!("unknown finding {s:?}"))
    }
}

impl std::fmt::Display for FindingId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// How serious a finding is on its own, before policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Warn,
    High,
}

/// One finding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    pub id: FindingId,
    pub severity: Severity,
    pub message: String,
}

impl Finding {
    pub fn new(id: FindingId, severity: Severity, message: String) -> Finding {
        Finding {
            id,
            severity,
            message,
        }
    }
}

impl std::fmt::Display for Finding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.id, self.message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_round_trip() {
        for id in FindingId::ALL {
            assert_eq!(id.as_str().parse::<FindingId>().unwrap(), id);
            let json = serde_json::to_string(&id).unwrap();
            assert_eq!(json, format!("\"{}\"", id.as_str()));
        }
        assert!("nope".parse::<FindingId>().is_err());
    }

    #[test]
    fn defaults_follow_the_table() {
        assert_eq!(
            FindingId::RecentCommit.default_decision(Mode::Interactive),
            Decision::Warn
        );
        assert_eq!(
            FindingId::RecentCommit.default_decision(Mode::Unattended),
            Decision::Deny
        );
        assert_eq!(
            FindingId::VcsSource.default_decision(Mode::Unattended),
            Decision::Warn
        );
        assert_eq!(
            FindingId::OutOfDate.default_decision(Mode::Unattended),
            Decision::Allow
        );
    }
}
