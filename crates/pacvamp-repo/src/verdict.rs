//! `pacvamp-repo verdict`: append a reviewer's verdict to the signed
//! verdict feed. See `docs/spec/repository-feeds.md`.

use std::path::PathBuf;

use eyre::{Context as _, Result, bail};
use pacvamp::trust::feeds::{Reviewer, Verdict, VerdictKind, VerdictSubject, Verdicts};
use usage_rs::RunWith;

/// Append a verdict to the signed verdict feed
///
/// One verdict is one reviewer's judgement of an AUR recipe at a commit or
/// of a built package by digest. Every reviewer, static rules, an
/// antivirus scan, a human, or an AI, writes the same document; clients
/// weight them by kind. The feed's sequence advances and it is re-signed.
#[derive(Debug, usage_rs::Args)]
pub struct VerdictCmd {
    /// The verdicts.json to update (created when missing)
    #[usage(short = 'f', long, value_hint = usage_rs::ValueHint::FilePath)]
    feed: PathBuf,
    /// The feed signing key
    #[usage(short = 'k', long, value_hint = usage_rs::ValueHint::FilePath)]
    key: PathBuf,
    /// The AUR pkgbase the verdict is about (with --commit)
    #[usage(long)]
    pkgbase: Option<String>,
    /// The commit reviewed
    #[usage(long)]
    commit: Option<String>,
    /// The built package digest reviewed instead
    #[usage(long)]
    sha256: Option<String>,
    /// The reviewer kind: static, av, ai, human, reproducible
    #[usage(long)]
    kind: Option<String>,
    /// The reviewer id, such as a username or tool name
    #[usage(long)]
    reviewer: Option<String>,
    /// The reviewer's version, model, or rules hash
    #[usage(long)]
    reviewer_version: Option<String>,
    /// pass, flag, or block
    #[usage(long)]
    verdict: Option<String>,
    /// A one-line summary
    #[usage(long, default = "")]
    summary: String,
    /// A finding id, repeatable
    #[usage(long)]
    finding: Vec<String>,
    /// Append every verdict in this JSON array instead
    #[usage(long, value_hint = usage_rs::ValueHint::FilePath)]
    from: Option<PathBuf>,
}

impl RunWith<()> for VerdictCmd {
    type Output = Result<()>;

    fn run_with(self, _: ()) -> Self::Output {
        let key = crate::feed::secret_key(&self.key)?;
        let now = crate::feed::now();
        let new: Vec<Verdict> = match &self.from {
            Some(path) => serde_json::from_slice(
                &std::fs::read(path).wrap_err_with(|| format!("reading {}", path.display()))?,
            )
            .wrap_err_with(|| format!("parsing {}", path.display()))?,
            None => vec![self.single(&now)?],
        };
        let added = new.len();
        let mut feed: Verdicts = crate::feed::load_signed(&self.feed, &key.public_key())?
            .unwrap_or(Verdicts {
                version: 1,
                sequence: 0,
                issued_at: now.clone(),
                verdicts: Vec::new(),
            });
        feed.sequence += 1;
        feed.issued_at = now;
        feed.verdicts.extend(new);
        crate::feed::write_signed(
            &self.feed,
            &feed,
            &key,
            &format!("verdicts sequence {}", feed.sequence),
        )?;
        println!(
            "wrote {} (sequence {}, {} verdict(s), {added} added)",
            self.feed.display(),
            feed.sequence,
            feed.verdicts.len()
        );
        Ok(())
    }
}

impl VerdictCmd {
    fn single(&self, now: &str) -> Result<Verdict> {
        let subject = match (&self.pkgbase, &self.commit, &self.sha256) {
            (Some(pkgbase), Some(commit), None) => VerdictSubject::Commit {
                pkgbase: pkgbase.clone(),
                commit: commit.clone(),
            },
            (None, None, Some(sha256)) => VerdictSubject::Digest {
                sha256: sha256.clone(),
            },
            _ => bail!("give --pkgbase with --commit, or --sha256"),
        };
        let Some(kind) = &self.kind else {
            bail!("--kind is required");
        };
        let Some(id) = &self.reviewer else {
            bail!("--reviewer is required");
        };
        let verdict = parse_kind(self.verdict.as_deref().unwrap_or_default())?;
        Ok(Verdict {
            subject,
            reviewer: Reviewer {
                kind: kind.clone(),
                id: id.clone(),
                version: self.reviewer_version.clone(),
            },
            verdict,
            summary: self.summary.clone(),
            findings: self.finding.clone(),
            issued_at: now.to_string(),
        })
    }
}

pub fn parse_kind(s: &str) -> Result<VerdictKind> {
    match s {
        "pass" => Ok(VerdictKind::Pass),
        "flag" => Ok(VerdictKind::Flag),
        "block" => Ok(VerdictKind::Block),
        other => bail!("--verdict {other:?}: expected pass, flag or block"),
    }
}
