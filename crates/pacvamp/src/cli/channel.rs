use std::io::Read as _;

use eyre::{Context as _, Result, bail};
use serde::Serialize;
use usage_rs::RunWith;

use super::{App, print_json};
use crate::channel::{self, Release, WriteRequest};
use crate::engine::{ApplyOpts, Engine, Operation, Transaction};
use crate::host::{Host, HostPaths};

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
        if keyring.is_empty() {
            // Nothing could verify a manifest, so do not fetch one.
            return Ok(None);
        }
        let cache = crate::trust::Cache::for_repo(&source.name, self.paths.sysroot.as_deref())?;
        let fetched: crate::trust::Fetched<Release> =
            crate::trust::fetch(&feed, "release.json", &keyring, &cache, offline)?;
        Ok(Some(fetched.value))
    }

    /// The release manifest for the repositories the host is actually using.
    pub fn active_release(&self, host: &Host, offline: bool) -> Result<Option<Release>> {
        let Some(id) = channel::current_pin(&self.mirrorlist_path()) else {
            return self.release(host, offline);
        };
        let manifest = self.manifest()?;
        let base = manifest
            .settings
            .channel_snapshot_base
            .as_deref()
            .ok_or_else(|| {
                eyre::eyre!(
                    "mirrorlist is pinned to {id}, but channel.snapshot_base is not configured"
                )
            })?;
        self.snapshot_release(base, &id, offline).map(Some)
    }

    /// A snapshot's own release manifest from the snapshot store.
    pub fn snapshot_release(
        &self,
        snapshot_base: &str,
        id: &str,
        offline: bool,
    ) -> Result<Release> {
        let keyring = crate::trust::Keyring::load(self.paths.sysroot.as_deref())?;
        let cache = crate::trust::Cache::for_repo(
            &format!("snapshots/{id}"),
            self.paths.sysroot.as_deref(),
        )?;
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
    /// promoted unless forced.
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
        Ok(release)
    }
}

fn restore_mirrorlist(
    app: &App,
    path: &std::path::Path,
    contents: &str,
    was_pinned: bool,
) -> Result<()> {
    if was_pinned {
        channel::write_privileged(path, contents, false, app.paths.sysroot.as_deref())
    } else {
        channel::restore_privileged(path, contents, app.paths.sysroot.as_deref())
    }
}

impl RunWith<&App> for Channel {
    type Output = Result<()>;

    fn run_with(self, app: &App) -> Self::Output {
        match self.command {
            Some(ChannelCommands::Pin(pin)) => {
                let release = app.pin(&pin.id, pin.force, self.offline)?;
                println!(
                    "pinned the Arch mirror to snapshot {} ({}); run `pacvamp update` or `pacvamp rollback --snapshot {}` to move to it",
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
                channel::restore_privileged(&path, &original, app.paths.sysroot.as_deref())?;
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
                        "pinned: {id} (mirrorlist frozen; `pacvamp channel unpin` to follow the channel again)"
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

pub(crate) fn describe(release: &Release) -> String {
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
            let (_staging, host, engine) = staged_snapshot(app, &base, &release.id)?;
            let mut tx = Transaction::new(Operation::Upgrade {
                allow_downgrade: true,
            })
            .ignoring(manifest.settings.update_ignore.iter().cloned())
            .overwriting(manifest.settings.update_overwrite.iter().cloned());
            tx.ignore_group
                .extend(manifest.settings.update_ignore_group.iter().cloned());
            let resolved = engine.plan(&tx)?;
            let command = app
                .engine()?
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
                app,
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
        let was_pinned = channel::current_pin(&mirrorlist).is_some();
        let release = app.pin(&self.snapshot, self.force, false)?;
        println!("pinned to snapshot {} ({})", release.id, describe(&release));
        let engine = match app.engine() {
            Ok(engine) => engine,
            Err(err) => {
                restore_mirrorlist(app, &mirrorlist, &original_mirrorlist, was_pinned)?;
                return Err(err);
            }
        };
        let mut retain_pin = false;
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
            let already_converged = plan.changes.is_empty();
            let mut explicit = Vec::new();
            for change in &plan.changes {
                if host
                    .installed_package(&change.name)?
                    .is_some_and(|package| {
                        package.reason == alpm_db::local::InstallReason::Explicit
                    })
                {
                    explicit.push(change.name.clone());
                }
            }
            let performed = super::transaction::confirm_and_apply(
                app,
                &engine,
                &resolved,
                &plan,
                "roll back",
                self.yes,
                false,
            )?;
            retain_pin = performed || already_converged;
            let mut patch = if performed {
                super::transaction::ledger_patch(&plan, &explicit, "rollback", false)
            } else {
                crate::ledger::Patch::default()
            };
            patch.snapshot = Some(release.id.clone());
            app.record(&patch)?;
            Ok(())
        })();
        if let Err(err) = result {
            if retain_pin {
                return Err(err.wrap_err(
                    "the machine reached the snapshot; retaining its pin after a later bookkeeping failure",
                ));
            }
            if let Err(recovery) =
                restore_mirrorlist(app, &mirrorlist, &original_mirrorlist, was_pinned)
            {
                return Err(err.wrap_err(format!(
                    "rollback also failed to restore the mirrorlist: {recovery:#}"
                )));
            }
            if let Err(recovery) = engine.refresh(
                crate::engine::RefreshOpts { force: true },
                ApplyOpts {
                    dry_run: false,
                    no_confirm: true,
                },
            ) {
                return Err(err.wrap_err(format!(
                    "mirrorlist restored, but rollback recovery failed to refresh databases: {recovery:#}"
                )));
            }
            return Err(err);
        }
        Ok(())
    }
}

/// Build a disposable pacman database with the host's installed database and
/// a generated snapshot configuration, then refresh only that database.
/// Planning against it matches the live rollback without copying the host's
/// keyring or changing its mirrorlist and sync databases.
fn staged_snapshot(
    app: &App,
    snapshot_base: &str,
    id: &str,
) -> Result<(tempfile::TempDir, Host, crate::engine::pacman::PacmanCli)> {
    let live = app.host()?;
    let staging = tempfile::tempdir().wrap_err("creating rollback planning root")?;
    let root = staging.path();

    let staged_db = root.join("db");
    copy_tree_if_exists(&live.db_path().join("local"), &staged_db.join("local"))?;
    // Pacman may run elevated to read the live keyring. Keep its sync
    // directory owned by the invoking user so TempDir can remove the
    // root-owned database files it creates inside that directory.
    std::fs::create_dir_all(staged_db.join("sync"))?;

    let staged_config = root.join("pacman.conf");
    let gpg_dir = app.rooted(&live.config.options.gpg_dir());
    std::fs::write(
        &staged_config,
        staged_pacman_config(&live, &staged_db, &gpg_dir, snapshot_base, id),
    )?;

    let paths = HostPaths {
        config: Some(staged_config),
        sysroot: None,
    };
    let mut engine = app.engine()?;
    engine.config = paths.config.clone();
    engine.sysroot = None;
    engine.refresh(
        crate::engine::RefreshOpts { force: true },
        ApplyOpts {
            dry_run: false,
            no_confirm: true,
        },
    )?;
    let host = Host::load(paths)?;
    Ok((staging, host, engine))
}

fn staged_pacman_config(
    live: &Host,
    db_path: &std::path::Path,
    gpg_dir: &std::path::Path,
    snapshot_base: &str,
    id: &str,
) -> String {
    use std::fmt::Write as _;

    let mut config = format!(
        "[options]\nArchitecture = {}\nDBPath = {}\nGPGDir = {}\nSigLevel = {}\nDisableSandbox\n",
        live.config
            .options
            .arch()
            .unwrap_or_else(|| alpm_db::conf::host_arch().to_string()),
        db_path.display(),
        gpg_dir.display(),
        live.config.options.sig_level,
    );
    for (name, values) in [
        ("HoldPkg", &live.config.options.hold_pkg),
        ("IgnorePkg", &live.config.options.ignore_pkg),
        ("IgnoreGroup", &live.config.options.ignore_group),
    ] {
        if !values.is_empty() {
            let _ = writeln!(config, "{name} = {}", values.join(" "));
        }
    }
    for source in &live.sources {
        let repo = &source.repo;
        let _ = write!(config, "\n[{}]\nSigLevel = {}\n", repo.name, repo.sig_level);
        if repo.usage != alpm_db::conf::Usage::ALL {
            let mut usage = Vec::new();
            if repo.usage.sync {
                usage.push("Sync");
            }
            if repo.usage.search {
                usage.push("Search");
            }
            if repo.usage.install {
                usage.push("Install");
            }
            if repo.usage.upgrade {
                usage.push("Upgrade");
            }
            let _ = writeln!(config, "Usage = {}", usage.join(" "));
        }
        if source.tier == crate::resolve::Tier::Arch {
            let _ = writeln!(config, "{}", channel::pinned_server(snapshot_base, id));
        } else {
            for server in &repo.servers {
                let _ = writeln!(config, "Server = {server}");
            }
            for server in &repo.cache_servers {
                let _ = writeln!(config, "CacheServer = {server}");
            }
        }
    }
    config
}

fn copy_tree_if_exists(from: &std::path::Path, to: &std::path::Path) -> Result<()> {
    let Ok(metadata) = std::fs::symlink_metadata(from) else {
        return Ok(());
    };
    if metadata.is_dir() {
        std::fs::create_dir_all(to)?;
        for entry in std::fs::read_dir(from)? {
            let entry = entry?;
            copy_tree_if_exists(&entry.path(), &to.join(entry.file_name()))?;
        }
    } else if metadata.is_file() {
        if let Some(parent) = to.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::copy(from, to)?;
    } else if metadata.file_type().is_symlink() {
        if let Some(parent) = to.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::os::unix::fs::symlink(std::fs::read_link(from)?, to)?;
    }
    Ok(())
}

/// Write a pacman configuration file per a JSON request on stdin; pacvamp
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
