use std::io::Read as _;

use eyre::{Context as _, Result, bail};
use serde::Serialize;
use usage_rs::RunWith;

use super::{App, print_json};
use crate::channel::{self, Release, WriteRequest};
use crate::engine::{ApplyOpts, Engine, Operation, Transaction};
use crate::host::Host;

/// Show the channel and snapshot this machine follows, or pin one
///
/// The channel comes from the Omarchy repository's server URL. Its signed
/// release manifest says which snapshot the channel points at, whether it
/// passed the test suite, when it was promoted, and which packages were
/// exercised. `pin` freezes the Arch mirror on a snapshot; `unpin`
/// restores the mirrorlist that was in place before.
#[derive(Debug, usage_rs::Args)]
pub struct Channel {
    #[usage(subcommand)]
    command: Option<ChannelCommands>,
    /// Use the cached feeds only
    #[usage(long, global)]
    offline: bool,
    /// Print as JSON
    #[usage(short = 'J', long, global)]
    json: bool,
}

#[derive(Debug, usage_rs::Subcommands)]
enum ChannelCommands {
    Pin(Pin),
    Unpin(Unpin),
}

/// Pin the Arch mirror to a snapshot
#[derive(Debug, usage_rs::Args)]
pub struct Pin {
    /// The snapshot id, such as 2026-09-03T06
    id: String,
    /// Pin even if the snapshot never reached rc or stable
    #[usage(long)]
    force: bool,
}

/// Restore the mirrorlist from before the pin
#[derive(Debug, usage_rs::Args)]
pub struct Unpin {}

#[derive(Debug, Serialize)]
pub struct ChannelStatus {
    pub channel: Option<String>,
    pub release: Option<Release>,
    pub pinned: Option<String>,
    pub last_converged: Option<String>,
}

impl App {
    /// The channel the OPR server URL names.
    pub fn channel_name(&self, host: &Host) -> Option<String> {
        host.sources
            .iter()
            .find(|s| matches!(s.tier, crate::resolve::Tier::Opr))
            .and_then(|s| s.repo.servers.first())
            .and_then(|url| channel::channel_of_url(url))
    }

    /// The channel's current release manifest.
    pub fn release(&self, host: &Host, offline: bool) -> Result<Option<Release>> {
        let Some(source) = host
            .sources
            .iter()
            .find(|s| matches!(s.tier, crate::resolve::Tier::Opr))
        else {
            return Ok(None);
        };
        let Some(feed) = self.feed_source(host, &source.name) else {
            return Ok(None);
        };
        let keyring = crate::trust::Keyring::load(self.paths.sysroot.as_deref())?;
        let cache = crate::trust::Cache::for_repo(&source.name);
        let fetched: crate::trust::Fetched<Release> =
            crate::trust::fetch(&feed, "release.json", &keyring, &cache, offline)?;
        Ok(Some(fetched.value))
    }

    /// A snapshot's own release manifest from the snapshot store.
    pub fn snapshot_release(
        &self,
        snapshot_base: &str,
        id: &str,
        offline: bool,
    ) -> Result<Release> {
        let keyring = crate::trust::Keyring::load(self.paths.sysroot.as_deref())?;
        let cache = crate::trust::Cache::for_repo(&format!("snapshots/{id}"));
        let feed = crate::trust::FeedSource {
            repo: format!("snapshot {id}"),
            base: format!("{}/{id}", snapshot_base.trim_end_matches('/')),
        };
        let fetched: crate::trust::Fetched<Release> =
            crate::trust::fetch(&feed, "release.json", &keyring, &cache, offline)?;
        if fetched.value.id != id {
            bail!("snapshot {id}'s manifest says it is {}", fetched.value.id);
        }
        Ok(fetched.value)
    }

    pub fn mirrorlist_path(&self) -> std::path::PathBuf {
        self.rooted(std::path::Path::new(channel::MIRRORLIST))
    }

    /// Pin the mirrorlist to `id`, checking the snapshot exists and was
    /// promoted unless forced, and record it in the ledger.
    pub fn pin(&self, id: &str, force: bool, offline: bool) -> Result<Release> {
        let manifest = self.manifest()?;
        let Some(base) = manifest.settings.channel_snapshot_base.clone() else {
            bail!(
                "no snapshot store configured; set [channel] snapshot_base in the manifest (the distro layer normally ships it)"
            );
        };
        let release = self.snapshot_release(&base, id, offline)?;
        if !release.was_promoted() && !force {
            bail!(
                "snapshot {id} never reached rc or stable{}; pass --force to pin it anyway",
                release
                    .tests
                    .as_ref()
                    .map(|t| format!(" (tests: {:?})", t.result))
                    .unwrap_or_default()
            );
        }
        let path = self.mirrorlist_path();
        channel::write_privileged(
            &path,
            &channel::pin_text(&base, id),
            true,
            self.paths.sysroot.as_deref(),
        )?;
        let patch = crate::ledger::Patch {
            snapshot: Some(id.to_string()),
            ..Default::default()
        };
        self.record(&patch)?;
        Ok(release)
    }
}

impl RunWith<&App> for Channel {
    type Output = Result<()>;

    fn run_with(self, app: &App) -> Self::Output {
        match self.command {
            Some(ChannelCommands::Pin(pin)) => {
                let release = app.pin(&pin.id, pin.force, self.offline)?;
                println!(
                    "pinned the Arch mirror to snapshot {} ({}); run `omapac update` or `omapac rollback --snapshot {}` to move to it",
                    release.id,
                    describe(&release),
                    release.id
                );
                Ok(())
            }
            Some(ChannelCommands::Unpin(_)) => {
                let path = app.mirrorlist_path();
                let backup = channel::backup_path(&path);
                if channel::current_pin(&path).is_none() {
                    println!("the mirrorlist is not pinned");
                    return Ok(());
                }
                let original = std::fs::read_to_string(&backup)
                    .wrap_err_with(|| format!("reading {}", backup.display()))?;
                channel::write_privileged(&path, &original, false, app.paths.sysroot.as_deref())?;
                let patch = crate::ledger::Patch {
                    snapshot: Some(String::new()),
                    ..Default::default()
                };
                app.record(&patch)?;
                println!("restored {} from {}", path.display(), backup.display());
                Ok(())
            }
            None => {
                let host = app.host()?;
                let status = ChannelStatus {
                    channel: app.channel_name(&host),
                    release: match app.release(&host, self.offline) {
                        Ok(release) => release,
                        Err(err) => {
                            eprintln!("warning: release manifest unavailable: {err:#}");
                            None
                        }
                    },
                    pinned: channel::current_pin(&app.mirrorlist_path()),
                    last_converged: app.ledger()?.snapshot.filter(|s| !s.is_empty()),
                };
                if self.json {
                    return print_json(&status);
                }
                println!(
                    "channel: {}",
                    status
                        .channel
                        .as_deref()
                        .unwrap_or("unknown (no Omarchy repository in pacman.conf)")
                );
                match &status.release {
                    Some(release) => {
                        println!("snapshot: {} ({})", release.id, describe(release));
                        println!(
                            "tested packages: {}{}",
                            release.tested_pkgbases.len(),
                            if release.expedited { ", expedited" } else { "" }
                        );
                    }
                    None => println!("snapshot: unknown (no release manifest)"),
                }
                match &status.pinned {
                    Some(id) => println!(
                        "pinned: {id} (mirrorlist frozen; `omapac channel unpin` to follow the channel again)"
                    ),
                    None => println!("pinned: no"),
                }
                if let Some(last) = &status.last_converged {
                    println!("last converged: {last}");
                }
                Ok(())
            }
        }
    }
}

fn describe(release: &Release) -> String {
    let tests = match &release.tests {
        Some(t) => format!("tests {:?}", t.result).to_lowercase(),
        None => "untested".to_string(),
    };
    let promoted = match (&release.promoted.stable, &release.promoted.rc) {
        (Some(at), _) => format!("stable since {at}"),
        (None, Some(at)) => format!("rc since {at}"),
        (None, None) => "not promoted".to_string(),
    };
    let held = if release.held { ", HELD" } else { "" };
    format!("{tests}, {promoted}{held}")
}

/// Move the machine to an archived snapshot
///
/// Pins the mirror to the snapshot, then runs a full sync that allows
/// downgrades so every package matches what the snapshot carried. Pair it
/// with the filesystem snapshot Omarchy takes before updates.
#[derive(Debug, usage_rs::Args)]
pub struct Rollback {
    /// The snapshot id to move to
    #[usage(long)]
    snapshot: String,
    /// Proceed without asking
    #[usage(short = 'y', long)]
    yes: bool,
    /// Show the plan and the command, run nothing
    #[usage(short = 'n', long)]
    dry_run: bool,
    /// Roll back to a snapshot that never reached rc or stable
    #[usage(long)]
    force: bool,
}

impl RunWith<&App> for Rollback {
    type Output = Result<()>;

    fn run_with(self, app: &App) -> Self::Output {
        let manifest = app.manifest()?;
        let Some(base) = manifest.settings.channel_snapshot_base.clone() else {
            bail!("no snapshot store configured; set [channel] snapshot_base in the manifest");
        };
        let release = app.snapshot_release(&base, &self.snapshot, false)?;
        if !release.was_promoted() && !self.force {
            bail!(
                "snapshot {} never reached rc or stable; pass --force",
                release.id
            );
        }
        if self.dry_run {
            println!(
                "would pin to snapshot {} ({})",
                release.id,
                describe(&release)
            );
            let host = app.host()?;
            let engine = app.engine()?;
            let mut tx = Transaction::new(Operation::Upgrade {
                allow_downgrade: true,
            })
            .ignoring(manifest.settings.update_ignore.iter().cloned())
            .overwriting(manifest.settings.update_overwrite.iter().cloned());
            tx.ignore_group
                .extend(manifest.settings.update_ignore_group.iter().cloned());
            let resolved = engine.plan(&tx)?;
            let command = engine
                .apply_invocation(
                    &tx,
                    ApplyOpts {
                        dry_run: true,
                        no_confirm: true,
                    },
                )
                .display();
            let plan = super::transaction::plan(&host, &resolved, command);
            super::transaction::confirm_and_apply(
                &engine,
                &resolved,
                &plan,
                "roll back",
                self.yes,
                true,
            )?;
            return Ok(());
        }
        let mirrorlist = app.mirrorlist_path();
        let original_mirrorlist = std::fs::read_to_string(&mirrorlist)
            .wrap_err_with(|| format!("reading {}", mirrorlist.display()))?;
        let previous_snapshot = app.ledger()?.snapshot.unwrap_or_default();
        let release = app.pin(&self.snapshot, self.force, false)?;
        println!("pinned to snapshot {} ({})", release.id, describe(&release));
        let engine = app.engine()?;
        let mut applied = false;
        let result = (|| -> Result<()> {
            engine.refresh(
                crate::engine::RefreshOpts { force: true },
                ApplyOpts {
                    dry_run: false,
                    no_confirm: true,
                },
            )?;
            let host = app.host()?;
            let mut tx = Transaction::new(Operation::Upgrade {
                allow_downgrade: true,
            })
            .ignoring(manifest.settings.update_ignore.iter().cloned())
            .overwriting(manifest.settings.update_overwrite.iter().cloned());
            tx.ignore_group
                .extend(manifest.settings.update_ignore_group.iter().cloned());
            let resolved = engine.plan(&tx)?;
            let command = engine
                .apply_invocation(
                    &tx,
                    ApplyOpts {
                        dry_run: true,
                        no_confirm: true,
                    },
                )
                .display();
            let plan = super::transaction::plan(&host, &resolved, command);
            let performed = super::transaction::confirm_and_apply(
                &engine,
                &resolved,
                &plan,
                "roll back",
                self.yes,
                false,
            )?;
            if performed {
                applied = true;
                app.record(&super::transaction::ledger_patch(
                    &plan,
                    &[],
                    "rollback",
                    false,
                ))?;
            }
            Ok(())
        })();
        if let Err(err) = result {
            if applied {
                return Err(err.wrap_err(
                    "packages were rolled back; retaining the snapshot pin after a later bookkeeping failure",
                ));
            }
            channel::write_privileged(
                &mirrorlist,
                &original_mirrorlist,
                false,
                app.paths.sysroot.as_deref(),
            )?;
            app.record(&crate::ledger::Patch {
                snapshot: Some(previous_snapshot),
                ..Default::default()
            })?;
            engine.refresh(
                crate::engine::RefreshOpts { force: true },
                ApplyOpts {
                    dry_run: false,
                    no_confirm: true,
                },
            )?;
            return Err(err);
        }
        Ok(())
    }
}

/// Write a pacman configuration file per a JSON request on stdin; omapac
/// runs this elevated
#[derive(Debug, usage_rs::Args)]
pub struct WriteExec {}

impl RunWith<&App> for WriteExec {
    type Output = Result<()>;

    fn run_with(self, app: &App) -> Self::Output {
        let mut json = String::new();
        std::io::stdin()
            .read_to_string(&mut json)
            .wrap_err("reading the write request from stdin")?;
        let request: WriteRequest =
            serde_json::from_str(&json).wrap_err("parsing the write request")?;
        request
            .apply(app.paths.sysroot.as_deref())
            .wrap_err_with(|| format!("writing {}", request.path.display()))?;
        Ok(())
    }
}
