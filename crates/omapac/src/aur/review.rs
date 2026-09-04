//! Gathering evidence for the policy engine: the RPC, a git checkout, the
//! `.SRCINFO`, the lockfile, and the host, turned into plain facts.

use std::collections::BTreeMap;

use eyre::{Context as _, Result, bail};
use omapac_policy::{self as policy, Evidence, Policy, Report};

use super::git::{Checkout, Remote};
use super::rpc::{self, Rpc};
use super::srcinfo::SrcInfo;
use crate::host::Host;
use crate::lockfile::AurEntry;
use crate::manifest::Settings;
use crate::manifest::settings::Mode;

/// Everything `review`, `approve`, and `build` share about one package.
pub struct Reviewed {
    pub pkgbase: String,
    pub pkgname: String,
    pub checkout: Checkout,
    pub target: String,
    pub srcinfo: SrcInfo,
    pub evidence: Evidence,
    pub report: Report,
    /// Verdicts from reviewers weighted `warn`: shown, never gating.
    pub notes: Vec<String>,
}

/// How to review.
pub struct Request<'a> {
    pub host: &'a Host,
    pub rpc: &'a dyn Rpc,
    pub remote: &'a Remote,
    pub cache_dir: &'a std::path::Path,
    pub settings: &'a Settings,
    /// Approved entries, keyed by AUR pkgbase.
    pub locked: &'a BTreeMap<String, AurEntry>,
    /// A commit to review instead of the remote head.
    pub commit: Option<&'a str>,
    /// Whether selecting that commit is itself drift to report.
    pub pinned: bool,
    /// Whether a human is present.
    pub interactive: bool,
    pub arch: &'a str,
    /// The repository's advisory feed, when it could be fetched.
    pub advisories: Option<&'a crate::trust::Advisories>,
    /// The repository's verdict feed, when it could be fetched.
    pub verdicts: Option<&'a crate::trust::Verdicts>,
}

/// Resolve `name` to its pkgbase, sync the checkout, and evaluate.
pub fn review(name: &str, request: &Request<'_>) -> Result<Reviewed> {
    let packages = request.rpc.info(&[name]).wrap_err("asking the AUR")?;
    let Some(package) = packages.into_iter().find(|p| p.name == name) else {
        bail!("{name} is not on the AUR");
    };
    let pkgbase = package.package_base.clone();
    let checkout = Checkout::sync(request.remote, request.cache_dir, &pkgbase)?;
    let target = match request.commit {
        Some(commit) => {
            if !checkout.has_commit(commit) {
                bail!("{pkgbase} has no commit {commit}");
            }
            checkout
                .log(commit, 1)?
                .first()
                .map(|c| c.hash.clone())
                .ok_or_else(|| eyre::eyre!("{pkgbase}: cannot resolve {commit}"))?
        }
        None => checkout.remote_head()?,
    };
    let srcinfo = checkout.srcinfo(&target)?;
    if !srcinfo.pkgnames().contains(&name) {
        bail!(
            "{pkgbase} at {} does not build {name} (it builds {})",
            &target[..12],
            srcinfo.pkgnames().join(", ")
        );
    }
    let (evidence, notes) = gather(name, &package, &checkout, &target, &srcinfo, request)?;
    let policy = policy_for(request.settings, request.interactive);
    let report = policy::evaluate(&evidence, &policy);
    Ok(Reviewed {
        pkgbase,
        pkgname: name.to_string(),
        checkout,
        target,
        srcinfo,
        evidence,
        report,
        notes,
    })
}

/// The policy the settings describe.
pub fn policy_for(settings: &Settings, interactive: bool) -> Policy {
    let mode = if interactive && settings.mode != Mode::Deny {
        policy::Mode::Interactive
    } else {
        policy::Mode::Unattended
    };
    let mut policy = match mode {
        policy::Mode::Interactive => Policy::interactive(),
        policy::Mode::Unattended => Policy::unattended(),
    };
    policy.thresholds.min_commit_age_secs = settings.aur_min_commit_age.0.as_secs() as i64;
    policy.thresholds.min_package_age_secs = settings.aur_min_package_age.0.as_secs() as i64;
    policy.thresholds.min_votes = u64::from(settings.aur_min_votes);
    policy
}

fn gather(
    name: &str,
    package: &rpc::Package,
    checkout: &Checkout,
    target: &str,
    srcinfo: &SrcInfo,
    request: &Request<'_>,
) -> Result<(Evidence, Vec<String>)> {
    let now = crate::ledger::now();
    let log = checkout.log(target, 2)?;
    let target_time = log.first().map(|c| c.time).unwrap_or(now);
    // Lock entries are shared by every split package produced by this pkgbase.
    // Fall back to the old pkgname key so existing lockfiles migrate on approval.
    let approved = request
        .locked
        .get(&package.package_base)
        .or_else(|| request.locked.get(name))
        .map(|entry| policy::Approved {
            commit: entry.commit.clone(),
            maintainer: entry.maintainer.clone(),
            source_hosts: entry.source_hosts.clone(),
            install_files: entry.install_files.clone(),
        });
    let diff = match &approved {
        Some(approved) if approved.commit != target => {
            if checkout.has_commit(&approved.commit) {
                let approved_time = checkout.log(&approved.commit, 1)?.first().map(|c| c.time);
                Some(policy::Diff {
                    lines_changed: checkout.diff_size(&approved.commit, target)?,
                    changed_files: checkout.changed_files(Some(&approved.commit), target)?,
                    quiet_secs_before: approved_time.map(|t| target_time - t),
                })
            } else {
                // Rewritten history is itself a reason to treat the entire
                // current recipe as changed, never as an absent diff.
                Some(policy::Diff {
                    lines_changed: checkout.tree_size(target)?,
                    changed_files: checkout.changed_files(None, target)?,
                    quiet_secs_before: None,
                })
            }
        }
        _ => None,
    };
    let mut install_scripts = Vec::new();
    for file in srcinfo.install_files() {
        if let Some(text) = checkout.show(target, file)? {
            install_scripts.push((file.to_string(), text));
        }
    }
    let known: Vec<String> = request
        .host
        .sources
        .iter()
        .filter_map(|s| s.db().ok().flatten())
        .flat_map(|db| db.packages.iter().map(|p| p.name.clone()))
        .collect();
    let similar_names = policy::similar::similar(name, known.iter().map(String::as_str), 2);
    let (verdicts, notes) = feed_verdicts(request, &checkout.pkgbase, target);
    let advisories = feed_advisories(request, &checkout.pkgbase, target, &srcinfo.version());
    let evidence = Evidence {
        pkgbase: checkout.pkgbase.clone(),
        now,
        rpc: Some(policy::Rpc {
            maintainer: package.maintainer.clone(),
            submitter: package.submitter.clone(),
            first_submitted: package.first_submitted,
            last_modified: package.last_modified,
            num_votes: package.num_votes,
            popularity: package.popularity,
            out_of_date: package.out_of_date,
            pending_requests: package.pending_requests,
        }),
        target: policy::Commit {
            hash: target.to_string(),
            time: target_time,
        },
        approved,
        pinned: request.pinned,
        first_install: request.host.installed_package(name)?.is_none(),
        recipe: policy::Recipe {
            version: srcinfo.version(),
            sources: srcinfo
                .sources(request.arch)
                .into_iter()
                .map(|s| policy::Source {
                    host: s.host().map(str::to_string),
                    is_vcs: s.is_vcs(),
                    is_local: s.is_local(),
                    url: s.url,
                })
                .collect(),
            skipped_checksum: srcinfo.has_skipped_checksum(request.arch),
            install_files: srcinfo
                .install_files()
                .into_iter()
                .map(str::to_string)
                .collect(),
        },
        diff,
        pkgbuild: checkout.show(target, "PKGBUILD")?,
        install_scripts,
        similar_names,
        verdicts,
        advisories,
    };
    Ok((evidence, notes))
}

/// Feed verdicts on this commit, split by the reviewer kind's weight:
/// gating kinds become findings, warn kinds become notes, ignored kinds
/// vanish.
fn feed_verdicts(
    request: &Request<'_>,
    pkgbase: &str,
    target: &str,
) -> (Vec<policy::Verdict>, Vec<String>) {
    use crate::manifest::settings::ReviewerWeight;
    use crate::trust::feeds::VerdictKind;
    let mut findings = Vec::new();
    let mut notes = Vec::new();
    let Some(feed) = request.verdicts else {
        return (findings, notes);
    };
    for verdict in feed.for_commit(pkgbase, target) {
        let weight = request
            .settings
            .trust_reviewers
            .get(&verdict.reviewer.kind)
            .copied()
            .unwrap_or(ReviewerWeight::Warn);
        let kind = match verdict.verdict {
            VerdictKind::Pass => policy::evidence::VerdictKind::Pass,
            VerdictKind::Flag => policy::evidence::VerdictKind::Flag,
            VerdictKind::Block => policy::evidence::VerdictKind::Block,
        };
        match weight {
            ReviewerWeight::Ignore => continue,
            ReviewerWeight::Warn => {
                if verdict.verdict != VerdictKind::Pass {
                    notes.push(format!(
                        "{} reviewer {} says {:?}: {}",
                        verdict.reviewer.kind,
                        verdict.reviewer.id,
                        verdict.verdict,
                        verdict.summary
                    ));
                }
            }
            ReviewerWeight::Gate => findings.push(policy::Verdict {
                reviewer_kind: verdict.reviewer.kind.clone(),
                reviewer: verdict.reviewer.id.clone(),
                verdict: kind,
                summary: verdict.summary.clone(),
            }),
        }
    }
    (findings, notes)
}

/// Advisories naming this pkgbase at this commit or version.
fn feed_advisories(
    request: &Request<'_>,
    pkgbase: &str,
    target: &str,
    version: &str,
) -> Vec<policy::Advisory> {
    let Some(feed) = request.advisories else {
        return Vec::new();
    };
    feed.matching(pkgbase, Some(target), Some(version))
        .into_iter()
        .map(|a| policy::Advisory {
            source: "advisory".to_string(),
            summary: format!("{} ({:?}): {}", a.id, a.action, a.reason),
        })
        .collect()
}

impl Reviewed {
    /// The lock entry approving the reviewed commit.
    pub fn lock_entry(&self) -> AurEntry {
        AurEntry {
            commit: self.target.clone(),
            pkgver: self.srcinfo.version(),
            approved_at: crate::ledger::now(),
            maintainer: self
                .evidence
                .rpc
                .as_ref()
                .and_then(|r| r.maintainer.clone()),
            source_hosts: self
                .evidence
                .recipe
                .sources
                .iter()
                .filter_map(|s| s.host.clone())
                .collect(),
            install_files: self.evidence.recipe.install_files.clone(),
            findings: (!self.report.findings.is_empty()).then(|| findings_digest(&self.report)),
        }
    }

    /// The diff a reviewer reads: PKGBUILD and scriptlets since approval,
    /// or the whole PKGBUILD on a first review.
    pub fn review_text(&self) -> Result<String> {
        let mut paths = vec!["PKGBUILD".to_string()];
        paths.extend(self.evidence.recipe.install_files.iter().cloned());
        if let Some(approved) = &self.evidence.approved {
            if approved.commit == self.target {
                return Ok(String::new());
            }
            if !self.checkout.has_commit(&approved.commit) {
                return self.full_review_text(&paths);
            }
            for file in &approved.install_files {
                if !paths.contains(file) {
                    paths.push(file.clone());
                }
            }
            let paths: Vec<&str> = paths.iter().map(String::as_str).collect();
            return self.checkout.diff(&approved.commit, &self.target, &paths);
        }
        self.full_review_text(&paths)
    }

    fn full_review_text(&self, paths: &[String]) -> Result<String> {
        let mut text = String::new();
        for path in paths {
            if let Some(content) = self.checkout.show(&self.target, path)? {
                text.push_str(&format!("==> {path}\n{content}"));
                if !content.ends_with('\n') {
                    text.push('\n');
                }
            }
        }
        Ok(text)
    }
}

/// A digest over stable finding identities.
pub fn findings_digest(report: &Report) -> String {
    use sha2::Digest as _;
    let mut hasher = sha2::Sha256::new();
    let mut ids: Vec<_> = report
        .findings
        .iter()
        .map(|judged| judged.finding.id.as_str())
        .collect();
    ids.sort_unstable();
    ids.dedup();
    for id in ids {
        hasher.update(id.as_bytes());
        hasher.update(b"\n");
    }
    format!("sha256:{:x}", hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use omapac_policy::{Decision, Finding, FindingId, Judged, Mode, Severity};

    fn report(message: &str) -> Report {
        Report {
            pkgbase: "demo".into(),
            commit: "a".repeat(40),
            mode: Mode::Interactive,
            findings: vec![Judged {
                finding: Finding::new(FindingId::RecentCommit, Severity::Warn, message.into()),
                decision: Decision::Warn,
            }],
        }
    }

    #[test]
    fn findings_digest_ignores_presentation_text() {
        assert_eq!(
            findings_digest(&report("old wording")),
            findings_digest(&report("new wording"))
        );
    }
}
