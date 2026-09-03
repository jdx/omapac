//! Gathering evidence for the policy engine: the RPC, a git checkout, the
//! `.SRCINFO`, the lockfile, and the host, turned into plain facts.

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
}

/// How to review.
pub struct Request<'a> {
    pub host: &'a Host,
    pub rpc: &'a dyn Rpc,
    pub remote: &'a Remote,
    pub cache_dir: &'a std::path::Path,
    pub settings: &'a Settings,
    pub locked: Option<&'a AurEntry>,
    /// A commit to review instead of the remote head.
    pub commit: Option<&'a str>,
    /// Whether a human is present.
    pub interactive: bool,
    pub arch: &'a str,
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
    let evidence = gather(name, &package, &checkout, &target, &srcinfo, request)?;
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
) -> Result<Evidence> {
    let now = crate::ledger::now();
    let log = checkout.log(target, 2)?;
    let target_time = log.first().map(|c| c.time).unwrap_or(now);
    let approved = request.locked.map(|entry| policy::Approved {
        commit: entry.commit.clone(),
        maintainer: entry.maintainer.clone(),
        source_hosts: entry.source_hosts.clone(),
        install_files: entry.install_files.clone(),
    });
    let diff = match &approved {
        Some(approved) if approved.commit != target && checkout.has_commit(&approved.commit) => {
            let approved_time = checkout.log(&approved.commit, 1)?.first().map(|c| c.time);
            Some(policy::Diff {
                lines_changed: checkout.diff_size(&approved.commit, target)?,
                changed_files: checkout.changed_files(Some(&approved.commit), target)?,
                quiet_secs_before: approved_time.map(|t| target_time - t),
            })
        }
        _ => None,
    };
    let install_scripts = srcinfo
        .install_files()
        .into_iter()
        .filter_map(|file| {
            checkout
                .show(target, file)
                .ok()
                .flatten()
                .map(|text| (file.to_string(), text))
        })
        .collect();
    let known: Vec<String> = request
        .host
        .sources
        .iter()
        .filter_map(|s| s.db().ok().flatten())
        .flat_map(|db| db.packages.iter().map(|p| p.name.clone()))
        .collect();
    let similar_names = policy::similar::similar(name, known.iter().map(String::as_str), 2);
    Ok(Evidence {
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
        pinned: request.locked.is_some(),
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
        verdicts: Vec::new(),
        advisories: Vec::new(),
    })
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
        if let Some(approved) = &self.evidence.approved
            && approved.commit != self.target
            && self.checkout.has_commit(&approved.commit)
        {
            for file in &approved.install_files {
                if !paths.contains(file) {
                    paths.push(file.clone());
                }
            }
            let paths: Vec<&str> = paths.iter().map(String::as_str).collect();
            return self.checkout.diff(&approved.commit, &self.target, &paths);
        }
        let mut text = String::new();
        for path in &paths {
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

/// A digest over the findings' ids and messages.
pub fn findings_digest(report: &Report) -> String {
    use sha2::Digest as _;
    let mut hasher = sha2::Sha256::new();
    for judged in &report.findings {
        hasher.update(judged.finding.id.as_str().as_bytes());
        hasher.update(b"\n");
        hasher.update(judged.finding.message.as_bytes());
        hasher.update(b"\n");
    }
    format!("sha256:{:x}", hasher.finalize())
}
