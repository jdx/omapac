//! `omapac-repo sync-aur`: the sync gate. Every AUR commit the repository
//! would pull goes through the shared policy engine; only a clean version
//! bump by a trusted maintainer merges on its own. See
//! `docs/spec/sync-gate.md`.

use std::collections::BTreeMap;
use std::path::PathBuf;

use eyre::{Context as _, Result, bail};
use omapac::aur::git::Remote;
use omapac::aur::review::{Request, Reviewed, review};
use omapac::aur::rpc::Client;
use omapac::host::{Host, HostPaths};
use omapac::lockfile::AurEntry;
use omapac::manifest::settings::Settings;
use omapac::trust::Advisories;
use omapac::trust::feeds::{Reviewer, Verdict, VerdictKind, VerdictSubject, Verdicts};
use omapac_policy::evidence::Approved;
use omapac_policy::{Policy, Report};
use serde::{Deserialize, Serialize};
use usage_rs::RunWith;

/// The sync state: what the repository last merged per package.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct State {
    #[serde(default)]
    pub packages: BTreeMap<String, Synced>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Synced {
    pub commit: String,
    pub pkgver: String,
    pub synced_at: String,
    /// The AUR maintainer when the commit was merged, for change checks.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maintainer: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Outcome {
    Unchanged,
    AutoMerge,
    NeedsReview,
    Blocked,
    Error,
}

#[derive(Debug, Clone, Serialize)]
pub struct Result1 {
    pub package: String,
    pub pkgbase: String,
    pub outcome: Outcome,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub to: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pkgver: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub maintainer: Option<String>,
    pub reasons: Vec<String>,
    pub findings: Vec<String>,
}

/// Gate AUR commits before the repository pulls them
///
/// For each package, syncs the AUR checkout, reviews the remote head with
/// the unattended policy against the commit last merged, and decides:
/// unchanged, auto-merge (a clean version bump by a trusted maintainer),
/// needs-review, or blocked (a finding the unattended policy denies). A
/// static verdict per reviewed commit can be appended to the verdict
/// feed. With --write, auto-merged commits are recorded in the state.
#[derive(Debug, usage_rs::Args)]
pub struct SyncAur {
    /// The sync state file (created when missing)
    #[usage(short = 's', long, value_hint = usage_rs::ValueHint::FilePath)]
    state: PathBuf,
    /// Packages to sync; default every package in the state
    #[usage(long)]
    package: Vec<String>,
    /// AUR maintainers whose clean bumps merge on their own
    #[usage(long)]
    trusted_maintainer: Vec<String>,
    /// Where AUR checkouts live
    #[usage(long, value_hint = usage_rs::ValueHint::DirPath)]
    cache: Option<PathBuf>,
    /// The pacman.conf for similar-name checks against the repositories
    #[usage(long, value_hint = usage_rs::ValueHint::FilePath)]
    config: Option<PathBuf>,
    /// An alternative root for pacman's files
    #[usage(long, value_hint = usage_rs::ValueHint::DirPath)]
    sysroot: Option<PathBuf>,
    /// The architecture to evaluate sources for
    #[usage(long, default = "x86_64")]
    arch: String,
    /// Append a static verdict per reviewed commit to this feed
    #[usage(long, value_hint = usage_rs::ValueHint::FilePath)]
    verdicts: Option<PathBuf>,
    /// Advisory kill list to enforce while gating commits
    #[usage(long, value_hint = usage_rs::ValueHint::FilePath)]
    advisories: Option<PathBuf>,
    /// The feed signing key (with --verdicts)
    #[usage(short = 'k', long, value_hint = usage_rs::ValueHint::FilePath)]
    key: Option<PathBuf>,
    /// Record auto-merged commits in the state
    #[usage(short = 'w', long)]
    write: bool,
    /// Print the results as JSON
    #[usage(short = 'J', long)]
    json: bool,
}

impl RunWith<()> for SyncAur {
    type Output = Result<()>;

    fn run_with(self, _: ()) -> Self::Output {
        let mut state: State = crate::feed::load(&self.state)?.unwrap_or_default();
        let packages: Vec<String> = if self.package.is_empty() {
            state.packages.keys().cloned().collect()
        } else {
            self.package.clone()
        };
        if packages.is_empty() {
            bail!("no packages: give --package or a state file with entries");
        }
        let host = Host::load(HostPaths {
            config: self.config.clone(),
            sysroot: self.sysroot.clone(),
        })?;
        let rpc = match std::env::var("OMAPAC_AUR_RPC_BASE") {
            Ok(base) => Client::with_base(&base),
            Err(_) => Client::new(),
        };
        let remote = match std::env::var("OMAPAC_AUR_GIT_BASE") {
            Ok(base) => Remote { base },
            Err(_) => Remote::aur(),
        };
        let cache = self.cache.clone().unwrap_or_else(|| {
            let base = std::env::var_os("XDG_CACHE_HOME")
                .map(PathBuf::from)
                .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".cache")))
                .unwrap_or_else(|| PathBuf::from("/tmp"));
            base.join("omapac-repo/aur")
        });
        std::fs::create_dir_all(&cache)
            .wrap_err_with(|| format!("creating {}", cache.display()))?;
        let settings = Settings::default();
        let now = crate::feed::now();
        let advisories: Option<Advisories> = match &self.advisories {
            Some(path) => crate::feed::load(path)?,
            None => None,
        };

        let mut results = Vec::new();
        let mut verdicts = Vec::new();
        for package in &packages {
            let previous = state.packages.get(package).cloned();
            let locked = previous.as_ref().map(|p| AurEntry {
                commit: p.commit.clone(),
                pkgver: p.pkgver.clone(),
                approved_at: 0,
                maintainer: None,
                source_hosts: Vec::new(),
                install_files: Vec::new(),
                findings: None,
            });
            let request = Request {
                host: &host,
                rpc: &rpc,
                remote: &remote,
                cache_dir: &cache,
                settings: &settings,
                locked: locked.as_ref(),
                commit: None,
                pinned: false,
                interactive: false,
                arch: &self.arch,
                advisories: advisories.as_ref(),
                verdicts: None,
            };
            let result = match review(package, &request) {
                Ok(reviewed) => {
                    let report = gate_report(&reviewed, previous.as_ref(), &self.arch);
                    let result = decide(
                        package,
                        &reviewed,
                        &report,
                        previous.as_ref(),
                        &self.trusted_maintainer,
                    );
                    if result.outcome != Outcome::Unchanged {
                        verdicts.push(static_verdict(&reviewed, &report, &now));
                    }
                    if result.outcome == Outcome::AutoMerge && self.write {
                        state.packages.insert(
                            package.clone(),
                            Synced {
                                commit: reviewed.target.clone(),
                                pkgver: reviewed.srcinfo.version(),
                                synced_at: now.clone(),
                                maintainer: result.maintainer.clone(),
                            },
                        );
                    }
                    result
                }
                Err(err) => Result1 {
                    package: package.clone(),
                    pkgbase: package.clone(),
                    outcome: Outcome::Error,
                    from: previous.as_ref().map(|p| p.commit.clone()),
                    to: None,
                    pkgver: None,
                    maintainer: None,
                    reasons: vec![format!("{err:#}")],
                    findings: Vec::new(),
                },
            };
            results.push(result);
        }

        if let Some(feed_path) = &self.verdicts
            && !verdicts.is_empty()
        {
            let Some(key_path) = &self.key else {
                bail!("--verdicts needs --key");
            };
            let key = crate::feed::secret_key(key_path)?;
            let mut feed: Verdicts = crate::feed::load(feed_path)?.unwrap_or(Verdicts {
                version: 1,
                sequence: 0,
                issued_at: now.clone(),
                verdicts: Vec::new(),
            });
            feed.sequence += 1;
            feed.issued_at = now.clone();
            feed.verdicts.extend(verdicts);
            crate::feed::write_signed(
                feed_path,
                &feed,
                &key,
                &format!("verdicts sequence {}", feed.sequence),
            )?;
        }
        if self.write {
            crate::feed::write_atomic(&self.state, &serde_json::to_vec_pretty(&state)?)?;
        }

        if self.json {
            println!("{}", serde_json::to_string_pretty(&results)?);
        } else {
            for r in &results {
                let label = match r.outcome {
                    Outcome::Unchanged => "unchanged   ",
                    Outcome::AutoMerge => "auto-merge  ",
                    Outcome::NeedsReview => "needs-review",
                    Outcome::Blocked => "BLOCKED     ",
                    Outcome::Error => "error       ",
                };
                let range = match (&r.from, &r.to) {
                    (Some(from), Some(to)) => format!("{}..{}", short(from), short(to)),
                    (None, Some(to)) => format!("new at {}", short(to)),
                    _ => String::new(),
                };
                println!(
                    "{label} {} {}{}",
                    r.package,
                    range,
                    r.pkgver
                        .as_ref()
                        .map(|v| format!(" ({v})"))
                        .unwrap_or_default()
                );
                for reason in &r.reasons {
                    println!("             {reason}");
                }
            }
        }
        let blocked = results
            .iter()
            .filter(|r| matches!(r.outcome, Outcome::Blocked | Outcome::Error))
            .count();
        if blocked > 0 {
            bail!("{blocked} package(s) blocked or failed");
        }
        Ok(())
    }
}

fn short(commit: &str) -> &str {
    &commit[..commit.len().min(12)]
}

/// Re-evaluate the review for the gate: the recorded commit is what was
/// last merged, not a pin, so drift is expected, and the approved
/// evidence (source hosts, install files, maintainer) comes from that
/// commit rather than from a client lock entry.
pub fn gate_report(reviewed: &Reviewed, previous: Option<&Synced>, arch: &str) -> Report {
    let mut evidence = reviewed.evidence.clone();
    evidence.pinned = false;
    evidence.approved = previous.map(|prev| {
        let srcinfo = reviewed.checkout.srcinfo(&prev.commit).ok();
        let source_hosts = srcinfo
            .as_ref()
            .map(|s| {
                s.sources(arch)
                    .iter()
                    .filter_map(|src| src.host().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();
        let install_files = srcinfo
            .as_ref()
            .map(|s| s.install_files().iter().map(|f| f.to_string()).collect())
            .unwrap_or_default();
        Approved {
            commit: prev.commit.clone(),
            // Older state files did not record a maintainer. Bootstrap that
            // evidence from the current RPC response so an absent historical
            // value is not mistaken for a takeover; a successful write then
            // persists it for subsequent comparisons.
            maintainer: prev.maintainer.clone().or_else(|| {
                reviewed
                    .evidence
                    .rpc
                    .as_ref()
                    .and_then(|rpc| rpc.maintainer.clone())
            }),
            source_hosts,
            install_files,
        }
    });
    omapac_policy::evaluate(&evidence, &Policy::unattended())
}

/// The gate decision for one reviewed package.
pub fn decide(
    package: &str,
    reviewed: &Reviewed,
    report: &Report,
    previous: Option<&Synced>,
    trusted: &[String],
) -> Result1 {
    let maintainer = reviewed
        .evidence
        .rpc
        .as_ref()
        .and_then(|r| r.maintainer.clone());
    let findings: Vec<String> = report.ids().iter().map(|id| id.to_string()).collect();
    let mut result = Result1 {
        package: package.to_string(),
        pkgbase: reviewed.pkgbase.clone(),
        outcome: Outcome::NeedsReview,
        from: previous.map(|p| p.commit.clone()),
        to: Some(reviewed.target.clone()),
        pkgver: Some(reviewed.srcinfo.version()),
        maintainer: maintainer.clone(),
        reasons: Vec::new(),
        findings,
    };
    if previous.is_some_and(|p| p.commit == reviewed.target) {
        result.outcome = Outcome::Unchanged;
        return result;
    }
    if report.denied() {
        result.outcome = Outcome::Blocked;
        for judged in report.denials() {
            result
                .reasons
                .push(format!("{}: {}", judged.finding.id, judged.finding.message));
        }
        return result;
    }
    if report.flagged() {
        for judged in &report.findings {
            result
                .reasons
                .push(format!("{}: {}", judged.finding.id, judged.finding.message));
        }
        return result;
    }
    let Some(previous) = previous else {
        result
            .reasons
            .push("new package: a human must approve the first commit".into());
        return result;
    };
    let Some(maintainer) = maintainer else {
        result
            .reasons
            .push("orphaned: no maintainer to trust".into());
        return result;
    };
    if !trusted.iter().any(|t| t == &maintainer) {
        result.reasons.push(format!(
            "maintainer {maintainer} is not on the trusted list"
        ));
        return result;
    }
    match pure_bump(&reviewed.checkout, &previous.commit, &reviewed.target) {
        Ok(true) => {
            result.outcome = Outcome::AutoMerge;
            result.reasons.push(format!(
                "clean version bump by trusted maintainer {maintainer}"
            ));
        }
        Ok(false) => result
            .reasons
            .push("the diff changes more than the version and checksums".into()),
        Err(err) => result.reasons.push(format!("diff: {err:#}")),
    }
    result
}

/// Whether the change between two commits is only a version or checksum
/// bump: no files beyond PKGBUILD and .SRCINFO, and every changed line is
/// a version, release, or checksum line. Expanded source lines may change
/// in .SRCINFO, but the executable PKGBUILD source expressions may not.
pub fn pure_bump(checkout: &omapac::aur::git::Checkout, from: &str, to: &str) -> Result<bool> {
    let files = checkout.changed_files(Some(from), to)?;
    if files.iter().any(|f| f != "PKGBUILD" && f != ".SRCINFO") {
        return Ok(false);
    }
    let diff = checkout.diff(from, to, &["PKGBUILD", ".SRCINFO"])?;
    Ok(diff_is_bump(&diff))
}

pub fn diff_is_bump(diff: &str) -> bool {
    let mut saw_change = false;
    let mut old_array = None;
    let mut new_array = None;
    let mut allow_sources = false;
    for line in diff.lines() {
        if let Some(path) = line.strip_prefix("+++ b/") {
            allow_sources = path == ".SRCINFO";
        } else if line.starts_with("@@") {
            old_array = None;
            new_array = None;
        } else if let Some(changed) = line.strip_prefix('+') {
            if !changed.starts_with("++ ") {
                saw_change = true;
                if !bump_line(changed.trim(), &mut new_array, allow_sources) {
                    return false;
                }
            }
        } else if let Some(changed) = line.strip_prefix('-') {
            if !changed.starts_with("-- ") {
                saw_change = true;
                if !bump_line(changed.trim(), &mut old_array, allow_sources) {
                    return false;
                }
            }
        } else if let Some(context) = line.strip_prefix(' ') {
            update_array(context.trim(), &mut old_array);
            update_array(context.trim(), &mut new_array);
        }
    }
    saw_change
}

fn bump_line(line: &str, array: &mut Option<&'static str>, allow_sources: bool) -> bool {
    if line.is_empty() || line == ")" {
        update_array(line, array);
        return true;
    }
    let name = line.split(['=', ' ']).next().unwrap_or_default();
    let stem = name.split('_').next().unwrap_or_default();
    let assignment = matches!(stem, "pkgver" | "pkgrel")
        || (allow_sources && matches!(stem, "source" | "noextract"))
        || matches!(
            stem,
            "md5sums"
                | "sha1sums"
                | "sha224sums"
                | "sha256sums"
                | "sha384sums"
                | "sha512sums"
                | "b2sums"
                | "cksums"
        );
    if assignment {
        update_array(line, array);
        return true;
    }
    if allow_sources
        && matches!(array, Some("source" | "noextract"))
        && (line.starts_with('\'') || line.starts_with('"'))
    {
        update_array(line, array);
        return true;
    }
    // A bare checksum or SKIP inside a multi-line array.
    let bare = line.trim_matches(['\'', '"', ')', '(']);
    let allowed = matches!(array, Some("checksum"))
        && (bare == "SKIP" || (bare.len() >= 32 && bare.chars().all(|c| c.is_ascii_hexdigit())));
    update_array(line, array);
    allowed
}

fn update_array(line: &str, array: &mut Option<&'static str>) {
    let name = line.split(['=', ' ']).next().unwrap_or_default();
    let stem = name.split('_').next().unwrap_or_default();
    if line.contains("=(") {
        *array = match stem {
            "source" => Some("source"),
            "noextract" => Some("noextract"),
            "md5sums" | "sha1sums" | "sha224sums" | "sha256sums" | "sha384sums" | "sha512sums"
            | "b2sums" | "cksums" => Some("checksum"),
            _ => None,
        };
    }
    if line.trim_end().ends_with(')') {
        *array = None;
    }
}

fn static_verdict(reviewed: &Reviewed, report: &Report, now: &str) -> Verdict {
    let verdict = if report.denied() {
        VerdictKind::Block
    } else if report.flagged() {
        VerdictKind::Flag
    } else {
        VerdictKind::Pass
    };
    let findings: Vec<String> = report.ids().iter().map(|id| id.to_string()).collect();
    Verdict {
        subject: VerdictSubject::Commit {
            pkgbase: reviewed.pkgbase.clone(),
            commit: reviewed.target.clone(),
        },
        reviewer: Reviewer {
            kind: "static".into(),
            id: "omapac-policy".into(),
            version: Some(env!("CARGO_PKG_VERSION").to_string()),
        },
        verdict,
        summary: if findings.is_empty() {
            "no findings".to_string()
        } else {
            findings.join(", ")
        },
        findings,
        issued_at: now.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bump_diffs() {
        let bump = "diff --git a/PKGBUILD b/PKGBUILD\n--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -2,3 +2,3 @@\n-pkgver=13.0.1\n+pkgver=13.0.2\n-sha256sums=('b77454bce87110180a1b6664c2d260de78124c9894b71101610ba84f551eb0d0')\n+sha256sums=('0000000000000000000000000000000000000000000000000000000000000000')\n--- a/.SRCINFO\n+++ b/.SRCINFO\n-\tpkgver = 13.0.1\n+\tpkgver = 13.0.2\n-\tsource = yay-13.0.1.tar.gz::https://github.com/Jguer/yay/archive/v13.0.1.tar.gz\n+\tsource = yay-13.0.2.tar.gz::https://github.com/Jguer/yay/archive/v13.0.2.tar.gz\n-\tsha256sums = b774\n+\tsha256sums = 0000\n";
        assert!(diff_is_bump(bump));
        let multiline = "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,4 +1,4 @@\n sha256sums=(\n-  'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'\n+  'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'\n )\n-pkgrel=1\n+pkgrel=2\n";
        assert!(diff_is_bump(multiline));
        let multiline_source = "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,4 +1,4 @@\n source=(\n-  'app-1.tar.gz::https://example.com/app-1.tar.gz'\n+  'app-2.tar.gz::https://example.com/app-2.tar.gz'\n )\n-pkgver=1\n+pkgver=2\n";
        assert!(!diff_is_bump(multiline_source));
        let unrelated_array = "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,3 +1,3 @@\n depends=(\n-  'safe'\n+  'hostile'\n )\n";
        assert!(!diff_is_bump(unrelated_array));
        let hostile =
            "--- a/PKGBUILD\n+++ b/PKGBUILD\n-pkgver=1\n+pkgver=2\n+install=yay.install\n";
        assert!(!diff_is_bump(hostile));
        let build = "--- a/PKGBUILD\n+++ b/PKGBUILD\n+  npm install atomic-lockfile\n";
        assert!(!diff_is_bump(build));
        assert!(!diff_is_bump("--- a/PKGBUILD\n+++ b/PKGBUILD\n"));
    }
}
