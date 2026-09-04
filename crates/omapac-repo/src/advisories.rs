//! `omapac-repo advisories`: maintain the signed kill list. See
//! `docs/spec/repository-feeds.md`.

use std::path::PathBuf;

use eyre::{Result, bail};
use omapac::trust::feeds::{Advisories as Feed, Advisory, AdvisoryAction};
use usage_rs::RunWith;

/// Add or remove advisories in the signed advisory feed
///
/// An advisory blocks or holds a pkgbase, narrowed to commits or versions
/// when given. Clients cache the feed and deny AUR operations unattended
/// once it is stale, so publish promptly and keep the feed reachable.
#[derive(Debug, usage_rs::Args)]
pub struct Advisories {
    #[usage(subcommand)]
    command: AdvisoriesCommands,
    /// The advisories.json to update (created when missing)
    #[usage(short = 'f', long, global, value_hint = usage_rs::ValueHint::FilePath)]
    feed: Option<PathBuf>,
    /// The feed signing key
    #[usage(short = 'k', long, global, value_hint = usage_rs::ValueHint::FilePath)]
    key: Option<PathBuf>,
}

#[derive(Debug, usage_rs::Subcommands)]
enum AdvisoriesCommands {
    Add(Add),
    Remove(Remove),
}

/// Add an advisory
#[derive(Debug, usage_rs::Args)]
pub struct Add {
    /// The advisory id, such as OPR-2026-0007
    #[usage(long)]
    id: String,
    #[usage(long)]
    pkgbase: String,
    /// Affected commits (prefixes match); none means every commit
    #[usage(long)]
    commit: Vec<String>,
    /// Affected versions; none means every version
    #[usage(long)]
    version: Vec<String>,
    /// The tier the advisory applies to: aur, opr, arch, custom
    #[usage(long)]
    tier: Option<String>,
    /// block or hold
    #[usage(long)]
    action: String,
    #[usage(long)]
    reason: String,
    #[usage(long)]
    url: Option<String>,
}

/// Remove an advisory by id
#[derive(Debug, usage_rs::Args)]
pub struct Remove {
    #[usage(long)]
    id: String,
}

impl RunWith<()> for Advisories {
    type Output = Result<()>;

    fn run_with(self, _: ()) -> Self::Output {
        let Some(feed_path) = &self.feed else {
            bail!("--feed is required");
        };
        let Some(key_path) = &self.key else {
            bail!("--key is required");
        };
        let key = crate::feed::secret_key(key_path)?;
        let now = crate::feed::now();
        let mut feed: Feed =
            crate::feed::load_signed(feed_path, &key.public_key())?.unwrap_or(Feed {
                version: 1,
                sequence: 0,
                issued_at: now.clone(),
                advisories: Vec::new(),
            });
        match self.command {
            AdvisoriesCommands::Add(add) => {
                if feed.advisories.iter().any(|a| a.id == add.id) {
                    bail!("advisory {} already exists; remove it first", add.id);
                }
                let action = match add.action.as_str() {
                    "block" => AdvisoryAction::Block,
                    "hold" => AdvisoryAction::Hold,
                    other => bail!("--action {other:?}: expected block or hold"),
                };
                feed.advisories.push(Advisory {
                    id: add.id.clone(),
                    pkgbase: add.pkgbase,
                    commits: add.commit,
                    versions: add.version,
                    tier: add.tier,
                    action,
                    reason: add.reason,
                    url: add.url,
                    issued_at: now.clone(),
                });
                println!("added {}", add.id);
            }
            AdvisoriesCommands::Remove(remove) => {
                let before = feed.advisories.len();
                feed.advisories.retain(|a| a.id != remove.id);
                if feed.advisories.len() == before {
                    bail!("no advisory {}", remove.id);
                }
                println!("removed {}", remove.id);
            }
        }
        feed.sequence += 1;
        feed.issued_at = now;
        crate::feed::write_signed(
            feed_path,
            &feed,
            &key,
            &format!("advisories sequence {}", feed.sequence),
        )?;
        println!(
            "wrote {} (sequence {}, {} advisor{})",
            feed_path.display(),
            feed.sequence,
            feed.advisories.len(),
            if feed.advisories.len() == 1 {
                "y"
            } else {
                "ies"
            }
        );
        Ok(())
    }
}
