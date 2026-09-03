//! The findings engine: turns evidence about an AUR package at a candidate
//! commit into findings, and applies a policy that maps each finding to
//! allow, warn, or deny.
//!
//! The client runs it before building; the server runs the same code in
//! the AUR sync gate. It takes plain facts and touches neither the network
//! nor git, so both sides gather evidence their own way and agree on the
//! verdict. See `PLAN.md`, "Client-side features" and "sync-aur".
//!
//! Findings are risk signals and policy gates, never malware verdicts.

#![forbid(unsafe_code)]

pub mod evidence;
pub mod finding;
pub mod similar;
pub mod sniff;

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

pub use evidence::{
    Advisory, Approved, Commit, Diff, Evidence, Recipe, Rpc, Source, Verdict, VerdictKind,
};
pub use finding::{Finding, FindingId, Severity};

/// What to do about a finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Decision {
    Allow,
    Warn,
    Deny,
}

/// Whether a human is present to decide.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    /// A person sees the findings and decides; most findings warn.
    Interactive,
    /// Nobody is watching; most findings deny.
    Unattended,
}

/// The numbers the rules compare against.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Thresholds {
    /// A commit younger than this is `recent-commit`.
    pub min_commit_age_secs: i64,
    /// A package first submitted less than this ago is `new-package`.
    pub min_package_age_secs: i64,
    /// Fewer votes than this on a first install is `low-reputation`.
    pub min_votes: u64,
    /// A diff with more changed lines than this is `pkgbuild-large-diff`
    /// when the history before it was quiet.
    pub large_diff_lines: usize,
    /// How long a package must have been untouched before a large diff
    /// counts as suspicious.
    pub quiet_period_secs: i64,
}

impl Default for Thresholds {
    fn default() -> Self {
        Thresholds {
            min_commit_age_secs: 48 * 3600,
            min_package_age_secs: 14 * 86_400,
            min_votes: 10,
            large_diff_lines: 40,
            quiet_period_secs: 90 * 86_400,
        }
    }
}

/// A policy: the mode, the thresholds, and per-finding overrides.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Policy {
    pub mode: Mode,
    pub thresholds: Thresholds,
    /// Explicit decisions that replace the mode's default for a finding.
    #[serde(default)]
    pub overrides: BTreeMap<FindingId, Decision>,
}

impl Policy {
    pub fn interactive() -> Policy {
        Policy {
            mode: Mode::Interactive,
            thresholds: Thresholds::default(),
            overrides: BTreeMap::new(),
        }
    }

    pub fn unattended() -> Policy {
        Policy {
            mode: Mode::Unattended,
            thresholds: Thresholds::default(),
            overrides: BTreeMap::new(),
        }
    }

    /// The decision for a finding under this policy.
    pub fn decide(&self, finding: &Finding) -> Decision {
        if let Some(decision) = self.overrides.get(&finding.id) {
            return *decision;
        }
        finding.id.default_decision(self.mode)
    }
}

/// One finding with its decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Judged {
    #[serde(flatten)]
    pub finding: Finding,
    pub decision: Decision,
}

/// The outcome of evaluating evidence under a policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Report {
    pub pkgbase: String,
    pub commit: String,
    pub mode: Mode,
    pub findings: Vec<Judged>,
}

impl Report {
    /// Whether any finding denies.
    pub fn denied(&self) -> bool {
        self.findings.iter().any(|f| f.decision == Decision::Deny)
    }

    /// Whether any finding warns or denies.
    pub fn flagged(&self) -> bool {
        self.findings.iter().any(|f| f.decision != Decision::Allow)
    }

    pub fn denials(&self) -> impl Iterator<Item = &Judged> {
        self.findings
            .iter()
            .filter(|f| f.decision == Decision::Deny)
    }

    /// The ids of every finding, for tests and logs.
    pub fn ids(&self) -> Vec<FindingId> {
        self.findings.iter().map(|f| f.finding.id).collect()
    }
}

/// Evaluate `evidence` under `policy`.
pub fn evaluate(evidence: &Evidence, policy: &Policy) -> Report {
    let mut findings = Vec::new();
    let t = &policy.thresholds;
    let now = evidence.now;

    if let Some(rpc) = &evidence.rpc {
        if now - rpc.first_submitted < t.min_package_age_secs {
            findings.push(Finding::new(
                FindingId::NewPackage,
                Severity::Warn,
                format!(
                    "first submitted {} ago, less than {}",
                    days(now - rpc.first_submitted),
                    days(t.min_package_age_secs)
                ),
            ));
        }
        if rpc.maintainer.is_none() {
            findings.push(Finding::new(
                FindingId::Orphaned,
                Severity::Warn,
                "no maintainer".to_string(),
            ));
        }
        if let Some(approved) = &evidence.approved
            && rpc.maintainer != approved.maintainer
        {
            findings.push(Finding::new(
                FindingId::MaintainerChanged,
                Severity::High,
                format!(
                    "maintainer was {} at the approved commit, now {}",
                    approved.maintainer.as_deref().unwrap_or("nobody"),
                    rpc.maintainer.as_deref().unwrap_or("nobody")
                ),
            ));
        } else if evidence.first_install
            && let (Some(m), Some(s)) = (&rpc.maintainer, &rpc.submitter)
            && m != s
        {
            findings.push(Finding::new(
                FindingId::MaintainerChanged,
                Severity::Warn,
                format!("submitted by {s}, now maintained by {m}: the package changed hands"),
            ));
        }
        if rpc.pending_requests > 0 {
            findings.push(Finding::new(
                FindingId::MaintainerChanged,
                Severity::Warn,
                format!("{} pending request(s) on the AUR", rpc.pending_requests),
            ));
        }
        if evidence.first_install && rpc.num_votes < t.min_votes {
            findings.push(Finding::new(
                FindingId::LowReputation,
                Severity::Warn,
                format!(
                    "{} vote(s), popularity {:.2}",
                    rpc.num_votes, rpc.popularity
                ),
            ));
        }
        if let Some(since) = rpc.out_of_date {
            findings.push(Finding::new(
                FindingId::OutOfDate,
                Severity::Info,
                format!("flagged out of date {} ago", days(now - since)),
            ));
        }
    }

    if now - evidence.target.time < t.min_commit_age_secs {
        findings.push(Finding::new(
            FindingId::RecentCommit,
            Severity::Warn,
            format!(
                "commit {} is {} old, less than {}",
                short(&evidence.target.hash),
                age(now - evidence.target.time),
                age(t.min_commit_age_secs)
            ),
        ));
    }

    if let Some(approved) = &evidence.approved
        && approved.commit != evidence.target.hash
        && evidence.pinned
    {
        findings.push(Finding::new(
            FindingId::CommitDrift,
            Severity::Warn,
            format!(
                "approved commit {} differs from target {}",
                short(&approved.commit),
                short(&evidence.target.hash)
            ),
        ));
    }

    if !evidence.similar_names.is_empty() {
        findings.push(Finding::new(
            FindingId::SimilarName,
            Severity::Warn,
            format!("name resembles {}", evidence.similar_names.join(", ")),
        ));
    }

    let recipe = &evidence.recipe;
    let hosts: Vec<&str> = recipe
        .sources
        .iter()
        .filter_map(|s| s.host.as_deref())
        .collect();
    if let Some(approved) = &evidence.approved {
        let new_hosts: Vec<&str> = hosts
            .iter()
            .copied()
            .filter(|h| !approved.source_hosts.iter().any(|a| a == h))
            .collect();
        if !new_hosts.is_empty() {
            findings.push(Finding::new(
                FindingId::SourceDomainChanged,
                Severity::High,
                format!(
                    "source host(s) not in the approved commit: {}",
                    new_hosts.join(", ")
                ),
            ));
        }
    }
    if recipe.skipped_checksum {
        findings.push(Finding::new(
            FindingId::ChecksumSkip,
            Severity::Warn,
            "a non-VCS source has checksum SKIP".to_string(),
        ));
    }
    if recipe.sources.iter().any(|s| s.is_vcs) || evidence.pkgbase.ends_with("-git") {
        findings.push(Finding::new(
            FindingId::VcsSource,
            Severity::Info,
            "builds from a version-control source, whose content is not pinned".to_string(),
        ));
    }
    let new_scripts: Vec<&str> = match &evidence.approved {
        Some(approved) => recipe
            .install_files
            .iter()
            .map(String::as_str)
            .filter(|f| !approved.install_files.iter().any(|a| a == f))
            .collect(),
        None => recipe.install_files.iter().map(String::as_str).collect(),
    };
    let changed_scripts: Vec<&str> = evidence
        .diff
        .as_ref()
        .map(|d| {
            d.changed_files
                .iter()
                .map(String::as_str)
                .filter(|f| {
                    (recipe.install_files.iter().any(|script| script == f)
                        || evidence.approved.as_ref().is_some_and(|approved| {
                            approved.install_files.iter().any(|script| script == f)
                        }))
                        && !new_scripts.contains(f)
                })
                .collect()
        })
        .unwrap_or_default();
    if !new_scripts.is_empty() || !changed_scripts.is_empty() {
        let mut parts = Vec::new();
        if !new_scripts.is_empty() {
            parts.push(format!("install script(s) {}", new_scripts.join(", ")));
        }
        if !changed_scripts.is_empty() {
            parts.push(format!("changed {}", changed_scripts.join(", ")));
        }
        findings.push(Finding::new(
            FindingId::InstallScript,
            Severity::High,
            parts.join("; "),
        ));
    }

    for (file, text) in evidence.texts() {
        for hit in sniff::scan(text) {
            findings.push(Finding::new(
                match hit.kind {
                    sniff::Kind::Suspicious => FindingId::SuspiciousContent,
                    sniff::Kind::LanguageDep => FindingId::LanguageDep,
                },
                Severity::Warn,
                format!("{file}:{}: {}", hit.line, hit.description),
            ));
        }
    }

    if let Some(diff) = &evidence.diff
        && diff.lines_changed > t.large_diff_lines
        && diff
            .quiet_secs_before
            .is_some_and(|q| q >= t.quiet_period_secs)
    {
        findings.push(Finding::new(
            FindingId::PkgbuildLargeDiff,
            Severity::Warn,
            format!(
                "{} lines changed after {} of no changes",
                diff.lines_changed,
                age(diff.quiet_secs_before.unwrap_or_default())
            ),
        ));
    }

    for verdict in &evidence.verdicts {
        let severity = match verdict.verdict {
            evidence::VerdictKind::Pass => continue,
            evidence::VerdictKind::Flag => Severity::Warn,
            evidence::VerdictKind::Block => Severity::High,
        };
        findings.push(Finding::new(
            FindingId::Verdict,
            severity,
            format!(
                "{} reviewer {} says {:?}: {}",
                verdict.reviewer_kind, verdict.reviewer, verdict.verdict, verdict.summary
            ),
        ));
    }
    for advisory in &evidence.advisories {
        findings.push(Finding::new(
            FindingId::UpstreamAdvisory,
            Severity::High,
            format!("{}: {}", advisory.source, advisory.summary),
        ));
    }

    let findings = findings
        .into_iter()
        .map(|finding| {
            let decision = policy.decide(&finding);
            Judged { finding, decision }
        })
        .collect();
    Report {
        pkgbase: evidence.pkgbase.clone(),
        commit: evidence.target.hash.clone(),
        mode: policy.mode,
        findings,
    }
}

fn short(hash: &str) -> &str {
    hash.char_indices()
        .nth(12)
        .map_or(hash, |(boundary, _)| &hash[..boundary])
}

fn days(secs: i64) -> String {
    format!("{} day(s)", secs.max(0) / 86_400)
}

fn age(secs: i64) -> String {
    let secs = secs.max(0);
    if secs >= 86_400 {
        format!("{} day(s)", secs / 86_400)
    } else if secs >= 3600 {
        format!("{} hour(s)", secs / 3600)
    } else {
        format!("{} minute(s)", secs / 60)
    }
}

#[cfg(test)]
mod tests {
    use super::evidence::VerdictKind;
    use super::*;

    const NOW: i64 = 1_756_800_000;
    const DAY: i64 = 86_400;

    fn rpc() -> Rpc {
        Rpc {
            maintainer: Some("alice".into()),
            submitter: Some("alice".into()),
            first_submitted: NOW - 900 * DAY,
            last_modified: NOW - 30 * DAY,
            num_votes: 250,
            popularity: 12.0,
            out_of_date: None,
            pending_requests: 0,
        }
    }

    fn recipe(hosts: &[&str]) -> Recipe {
        Recipe {
            version: "1.0-1".into(),
            sources: hosts
                .iter()
                .map(|h| Source {
                    url: format!("https://{h}/x.tar.gz"),
                    host: Some(h.to_string()),
                    is_vcs: false,
                    is_local: false,
                })
                .collect(),
            skipped_checksum: false,
            install_files: vec![],
        }
    }

    fn evidence() -> Evidence {
        Evidence {
            pkgbase: "helix-bin".into(),
            now: NOW,
            rpc: Some(rpc()),
            target: Commit {
                hash: "b".repeat(40),
                time: NOW - 30 * DAY,
            },
            approved: None,
            pinned: false,
            first_install: false,
            recipe: recipe(&["github.com"]),
            diff: None,
            pkgbuild: None,
            install_scripts: vec![],
            similar_names: vec![],
            verdicts: vec![],
            advisories: vec![],
        }
    }

    fn approved(hosts: &[&str]) -> Approved {
        Approved {
            commit: "a".repeat(40),
            maintainer: Some("alice".into()),
            source_hosts: hosts.iter().map(|h| h.to_string()).collect(),
            install_files: vec![],
        }
    }

    #[test]
    fn a_quiet_mature_package_has_no_findings() {
        let report = evaluate(&evidence(), &Policy::interactive());
        assert!(report.findings.is_empty(), "{report:?}");
        assert!(!report.denied() && !report.flagged());
    }

    #[test]
    fn atomic_arch_shape_is_denied_unattended() {
        // An adopted package whose new commit swaps the source host, adds an
        // install script, and pulls an npm dependency during build.
        let mut e = evidence();
        e.rpc.as_mut().unwrap().maintainer = Some("mallory".into());
        e.approved = Some(approved(&["github.com"]));
        e.target.time = NOW - 3600;
        e.recipe = recipe(&["github.com", "evil.example"]);
        e.recipe.install_files = vec!["helix-bin.install".into()];
        e.pkgbuild = Some("build() {\n  npm install atomic-lockfile\n}\n".into());
        e.diff = Some(Diff {
            lines_changed: 120,
            changed_files: vec!["PKGBUILD".into(), "helix-bin.install".into()],
            quiet_secs_before: Some(200 * DAY),
        });
        let report = evaluate(&e, &Policy::unattended());
        let ids = report.ids();
        for expected in [
            FindingId::MaintainerChanged,
            FindingId::RecentCommit,
            FindingId::SourceDomainChanged,
            FindingId::InstallScript,
            FindingId::LanguageDep,
            FindingId::PkgbuildLargeDiff,
        ] {
            assert!(ids.contains(&expected), "missing {expected:?} in {ids:?}");
        }
        assert!(report.denied());
        assert!(report.denials().count() >= 5);

        let interactive = evaluate(&e, &Policy::interactive());
        assert!(!interactive.denied(), "a human decides: {interactive:?}");
        assert!(interactive.flagged());
    }

    #[test]
    fn first_install_gates() {
        let mut e = evidence();
        e.first_install = true;
        e.rpc = Some(Rpc {
            maintainer: Some("bob".into()),
            submitter: Some("alice".into()),
            first_submitted: NOW - 3 * DAY,
            num_votes: 2,
            ..rpc()
        });
        e.similar_names = vec!["helix".into()];
        let report = evaluate(&e, &Policy::unattended());
        let ids = report.ids();
        assert!(ids.contains(&FindingId::NewPackage));
        assert!(ids.contains(&FindingId::LowReputation));
        assert!(ids.contains(&FindingId::SimilarName));
        assert!(
            ids.contains(&FindingId::MaintainerChanged),
            "changed hands: {ids:?}"
        );
        assert!(report.denied());
        // Not a first install: reputation and changed-hands do not apply.
        e.first_install = false;
        let ids = evaluate(&e, &Policy::unattended()).ids();
        assert!(!ids.contains(&FindingId::LowReputation));
        assert!(!ids.contains(&FindingId::MaintainerChanged));
    }

    #[test]
    fn adopting_an_approved_orphan_is_a_maintainer_change() {
        let mut e = evidence();
        let mut previous = approved(&["github.com"]);
        previous.maintainer = None;
        e.approved = Some(previous);

        assert!(
            evaluate(&e, &Policy::unattended())
                .ids()
                .contains(&FindingId::MaintainerChanged)
        );
    }

    #[test]
    fn changed_nonstandard_install_script_is_reported() {
        let mut e = evidence();
        let mut previous = approved(&["github.com"]);
        previous.install_files = vec!["setup-hooks".into()];
        e.approved = Some(previous);
        e.recipe.install_files = vec!["setup-hooks".into()];
        e.diff = Some(Diff {
            lines_changed: 1,
            changed_files: vec!["setup-hooks".into()],
            quiet_secs_before: None,
        });

        assert!(
            evaluate(&e, &Policy::unattended())
                .ids()
                .contains(&FindingId::InstallScript)
        );
    }

    #[test]
    fn checksum_vcs_orphan_and_out_of_date() {
        let mut e = evidence();
        e.recipe.skipped_checksum = true;
        e.recipe.sources.push(Source {
            url: "git+https://github.com/o/r.git".into(),
            host: Some("github.com".into()),
            is_vcs: true,
            is_local: false,
        });
        let rpc = e.rpc.as_mut().unwrap();
        rpc.maintainer = None;
        rpc.out_of_date = Some(NOW - 10 * DAY);
        let report = evaluate(&e, &Policy::unattended());
        let by_id: BTreeMap<FindingId, Decision> = report
            .findings
            .iter()
            .map(|f| (f.finding.id, f.decision))
            .collect();
        assert_eq!(by_id[&FindingId::ChecksumSkip], Decision::Deny);
        assert_eq!(by_id[&FindingId::Orphaned], Decision::Deny);
        assert_eq!(
            by_id[&FindingId::VcsSource],
            Decision::Warn,
            "vcs is only warned unattended"
        );
        assert_eq!(
            by_id[&FindingId::OutOfDate],
            Decision::Allow,
            "informational"
        );
        let interactive = evaluate(&e, &Policy::interactive());
        assert!(
            interactive
                .findings
                .iter()
                .all(|f| f.decision != Decision::Deny)
        );
    }

    #[test]
    fn drift_verdicts_advisories_and_overrides() {
        let mut e = evidence();
        e.approved = Some(approved(&["github.com"]));
        e.pinned = true;
        e.verdicts = vec![
            Verdict {
                reviewer_kind: "static".into(),
                reviewer: "omapac-policy".into(),
                verdict: VerdictKind::Pass,
                summary: "clean".into(),
            },
            Verdict {
                reviewer_kind: "ai".into(),
                reviewer: "opr-reviewer".into(),
                verdict: VerdictKind::Block,
                summary: "downloads and executes a payload".into(),
            },
        ];
        e.advisories = vec![Advisory {
            source: "osv".into(),
            summary: "MAL-2026-0001 upstream repository is malicious".into(),
        }];
        let report = evaluate(&e, &Policy::unattended());
        let ids = report.ids();
        assert!(ids.contains(&FindingId::CommitDrift));
        assert_eq!(
            ids.iter().filter(|i| **i == FindingId::Verdict).count(),
            1,
            "pass is silent"
        );
        assert!(ids.contains(&FindingId::UpstreamAdvisory));
        assert!(report.denied());

        let mut lenient = Policy::interactive();
        lenient
            .overrides
            .insert(FindingId::CommitDrift, Decision::Allow);
        lenient.overrides.insert(FindingId::Verdict, Decision::Deny);
        let report = evaluate(&e, &lenient);
        let drift = report
            .findings
            .iter()
            .find(|f| f.finding.id == FindingId::CommitDrift)
            .unwrap();
        assert_eq!(drift.decision, Decision::Allow);
        let verdict = report
            .findings
            .iter()
            .find(|f| f.finding.id == FindingId::Verdict)
            .unwrap();
        assert_eq!(verdict.decision, Decision::Deny);

        // Not pinned: a different commit is just the newer version.
        e.pinned = false;
        assert!(
            !evaluate(&e, &Policy::unattended())
                .ids()
                .contains(&FindingId::CommitDrift)
        );
    }

    #[test]
    fn reports_serialize() {
        let mut e = evidence();
        e.recipe.skipped_checksum = true;
        let report = evaluate(&e, &Policy::unattended());
        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(json["findings"][0]["id"], "checksum-skip");
        assert_eq!(json["findings"][0]["decision"], "deny");
        assert_eq!(json["mode"], "unattended");
    }

    #[test]
    fn short_hashes_respect_utf8_boundaries() {
        assert_eq!(short("0123456789éérest"), "0123456789éé");
        assert_eq!(short("短い"), "短い");
    }
}
