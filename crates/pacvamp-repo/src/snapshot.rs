//! `pacvamp-repo snapshot`: the snapshot store and channel pointers. See
//! `docs/spec/snapshot-store.md`.

use std::io::{BufRead as _, BufReader, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::str::FromStr as _;

use alpm_db::sync::SyncDb;
use eyre::{Context as _, Result, bail};
use packslip::minisign::SecretKey;
use pacvamp::channel::{Promoted, Release, TestResult, Tests};
use serde::Serialize;
use usage_rs::RunWith;

pub const CHANNELS: &[&str] = &["edge", "rc", "stable"];

/// Cut, test, promote, hold, and prune snapshots
///
/// The mirror is a store of immutable snapshots; edge, rc and stable are
/// pointers into it. Every change to a snapshot's release manifest is
/// re-signed with the index key.
#[derive(Debug, usage_rs::Args)]
pub struct Snapshot {
    #[usage(subcommand)]
    command: SnapshotCommands,
    /// The snapshot store root
    #[usage(short = 's', long, global, value_hint = usage_rs::ValueHint::DirPath)]
    store: Option<PathBuf>,
    /// The release manifest signing key
    #[usage(short = 'k', long, global, value_hint = usage_rs::ValueHint::FilePath)]
    key: Option<PathBuf>,
    /// Print as JSON
    #[usage(short = 'J', long, global)]
    json: bool,
}

#[derive(Debug, usage_rs::Subcommands)]
enum SnapshotCommands {
    Check(Check),
    Cut(Cut),
    Hold(Hold),
    Promote(Promote),
    Prune(Prune),
    Status(Status),
    Test(Test),
    Unhold(Unhold),
}

/// Copy a synced mirror into a new snapshot and point edge at it
#[derive(Debug, usage_rs::Args)]
pub struct Cut {
    /// The synced mirror: <from>/<repo>/os/<arch>/<repo>.db
    #[usage(long, value_hint = usage_rs::ValueHint::DirPath)]
    from: PathBuf,
    /// The snapshot id; defaults to the current hour in UTC
    #[usage(long)]
    id: Option<String>,
    /// A signed repository index included in this snapshot; repeatable
    #[usage(long, value_hint = usage_rs::ValueHint::FilePath)]
    repo_index: Vec<PathBuf>,
}

/// Run the test suite on a snapshot and record the result
#[derive(Debug, usage_rs::Args)]
pub struct Test {
    #[usage(long)]
    id: String,
    /// The suite command; the built-in consistency check when omitted
    #[usage(long)]
    suite: Option<String>,
    /// Let the built-in check pass with package files missing
    #[usage(long)]
    allow_missing: bool,
    /// Record the suite's git commit
    #[usage(long)]
    commit: Option<String>,
    /// Where the log was published
    #[usage(long)]
    log_url: Option<String>,
}

/// Move a channel pointer
#[derive(Debug, usage_rs::Args)]
pub struct Promote {
    /// rc or stable
    #[usage(long)]
    channel: String,
    /// Promote this snapshot; default the current rc when it soaked
    #[usage(long)]
    id: Option<String>,
    /// How long rc must have soaked before it becomes stable
    #[usage(long, default = "3d")]
    soak: String,
    /// Mark the snapshot as an expedited security release
    #[usage(long)]
    expedited: bool,
}

/// Hold a snapshot and move pointers off it
#[derive(Debug, usage_rs::Args)]
pub struct Hold {
    #[usage(long)]
    id: String,
    #[usage(long)]
    reason: String,
}

/// Clear a hold; pointers do not move forward on their own
#[derive(Debug, usage_rs::Args)]
pub struct Unhold {
    #[usage(long)]
    id: String,
}

/// List snapshots and channel pointers
#[derive(Debug, usage_rs::Args)]
pub struct Status {}

/// Delete snapshots past their retention
#[derive(Debug, usage_rs::Args)]
pub struct Prune {
    #[usage(long, default = "90d")]
    retain: String,
    /// Retention for snapshots that were ever stable
    #[usage(long, default = "365d")]
    stable_retain: String,
    /// Report without deleting
    #[usage(short = 'n', long)]
    dry_run: bool,
}

/// Verify a snapshot's databases and package files
#[derive(Debug, usage_rs::Args)]
pub struct Check {
    #[usage(long)]
    id: String,
    /// Pass with package files missing (a partial mirror)
    #[usage(long)]
    allow_missing: bool,
}

/// The store on disk.
pub struct Store {
    pub root: PathBuf,
}

impl Store {
    pub fn open(root: &Path) -> Result<Store> {
        std::fs::create_dir_all(root.join("snapshots"))
            .wrap_err_with(|| format!("creating {}", root.display()))?;
        std::fs::create_dir_all(root.join("channels"))?;
        Ok(Store {
            root: root.to_path_buf(),
        })
    }

    pub fn snapshot_dir(&self, id: &str) -> PathBuf {
        self.root.join("snapshots").join(id)
    }

    /// Snapshot ids, oldest first. Ids are `YYYY-MM-DDTHH`, so text order
    /// is time order.
    pub fn ids(&self) -> Result<Vec<String>> {
        let mut ids: Vec<String> = std::fs::read_dir(self.root.join("snapshots"))?
            .filter_map(Result::ok)
            .filter(|e| e.path().join("release.json").is_file())
            .filter_map(|e| e.file_name().to_str().map(str::to_string))
            .collect();
        ids.sort();
        Ok(ids)
    }

    pub fn release(&self, id: &str) -> Result<Release> {
        let path = self.snapshot_dir(id).join("release.json");
        let bytes = std::fs::read(&path).wrap_err_with(|| format!("reading {}", path.display()))?;
        serde_json::from_slice(&bytes).wrap_err_with(|| format!("parsing {}", path.display()))
    }

    /// Load a release only when its existing signature matches `key`.
    pub fn signed_release(&self, id: &str, key: &SecretKey) -> Result<Release> {
        let path = self.snapshot_dir(id).join("release.json");
        crate::feed::load_signed(&path, &key.public_key())?
            .ok_or_else(|| eyre::eyre!("no snapshot {id}"))
    }

    pub fn write_release(&self, release: &Release, key: &SecretKey) -> Result<()> {
        crate::feed::write_signed(
            &self.snapshot_dir(&release.id).join("release.json"),
            release,
            key,
            &format!("release {}", release.id),
        )
    }

    /// The snapshot a channel points at.
    pub fn target(&self, channel: &str) -> Option<String> {
        let link = std::fs::read_link(self.root.join("channels").join(channel)).ok()?;
        link.file_name()?.to_str().map(str::to_string)
    }

    /// Point a channel at a snapshot, atomically.
    pub fn point(&self, channel: &str, id: &str) -> Result<()> {
        if !self.snapshot_dir(id).is_dir() {
            bail!("no snapshot {id}");
        }
        let channels = self.root.join("channels");
        let temp = channels.join(format!(".{channel}.tmp"));
        let _ = std::fs::remove_file(&temp);
        std::os::unix::fs::symlink(Path::new("../snapshots").join(id), &temp)
            .wrap_err_with(|| format!("linking {}", temp.display()))?;
        std::fs::rename(&temp, channels.join(channel))
            .wrap_err_with(|| format!("pointing {channel} at {id}"))?;
        Ok(())
    }

    pub fn clear(&self, channel: &str) -> Result<()> {
        let path = self.root.join("channels").join(channel);
        match std::fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(err) => Err(err).wrap_err_with(|| format!("clearing channel {channel}")),
        }
    }

    pub fn channels_pointing_at(&self, id: &str) -> Vec<String> {
        CHANNELS
            .iter()
            .filter(|c| self.target(c).as_deref() == Some(id))
            .map(|c| c.to_string())
            .collect()
    }
}

fn snapshot_id(at: jiff::Timestamp) -> String {
    at.to_zoned(jiff::tz::TimeZone::UTC)
        .strftime("%Y-%m-%dT%H")
        .to_string()
}

fn age_seconds(now: jiff::Timestamp, at: &str) -> Result<i64> {
    let at = jiff::Timestamp::from_str(at).wrap_err_with(|| format!("timestamp {at:?}"))?;
    Ok(now.since(at).map(|s| s.get_seconds()).unwrap_or(0))
}

impl RunWith<()> for Snapshot {
    type Output = Result<()>;

    fn run_with(self, _: ()) -> Self::Output {
        let Some(root) = &self.store else {
            bail!("--store is required");
        };
        let store = Store::open(root)?;
        let key = || -> Result<SecretKey> {
            let Some(path) = &self.key else {
                bail!("--key is required");
            };
            crate::feed::secret_key(path)
        };
        let now = crate::vendor::now()?;
        match self.command {
            SnapshotCommands::Cut(cut) => {
                let key = key()?;
                let id = cut.id.clone().unwrap_or_else(|| snapshot_id(now));
                let release = cut_snapshot(&store, &cut, &id, now, &key)?;
                store.point("edge", &id)?;
                println!(
                    "cut snapshot {id} ({} database{}), edge -> {id}",
                    release.db_digests.len(),
                    if release.db_digests.len() == 1 {
                        ""
                    } else {
                        "s"
                    }
                );
                Ok(())
            }
            SnapshotCommands::Test(test) => {
                let key = key()?;
                let mut release = store.signed_release(&test.id, &key)?;
                let (result, tested) = run_suite(&store, &test, &release)?;
                release.tests = Some(Tests {
                    suite: test.suite.clone().unwrap_or_else(|| "builtin".into()),
                    commit: test.commit.clone(),
                    result,
                    log_url: test.log_url.clone(),
                });
                release.tested_pkgbases = tested;
                let mut moved = false;
                if result == TestResult::Pass {
                    if !release.held {
                        let current = store.target("rc");
                        if current.as_deref().is_none_or(|c| c <= test.id.as_str()) {
                            release.promoted.rc.get_or_insert_with(|| now.to_string());
                            store.write_release(&release, &key)?;
                            if current.as_deref() != Some(test.id.as_str()) {
                                store.point("rc", &test.id)?;
                                moved = true;
                            }
                        } else {
                            store.write_release(&release, &key)?;
                        }
                    } else {
                        store.write_release(&release, &key)?;
                    }
                } else {
                    if store.target("rc").as_deref() == Some(test.id.as_str()) {
                        release.promoted.rc = None;
                        // A failed re-test may only retreat to an earlier rc;
                        // it must not advance across a deliberate rollback.
                        match fallback(&store, "rc", &test.id, &key)? {
                            Some(id) => store.point("rc", &id)?,
                            None => store.clear("rc")?,
                        }
                    }
                    store.write_release(&release, &key)?;
                }
                println!(
                    "snapshot {}: tests {}, {} tested pkgbase(s){}",
                    test.id,
                    match result {
                        TestResult::Pass => "pass",
                        TestResult::Fail => "fail",
                        TestResult::Pending => "pending",
                    },
                    release.tested_pkgbases.len(),
                    if moved {
                        format!(", rc -> {}", test.id)
                    } else {
                        String::new()
                    }
                );
                if result != TestResult::Pass {
                    bail!("the suite failed");
                }
                Ok(())
            }
            SnapshotCommands::Promote(promote) => {
                let key = key()?;
                if !matches!(promote.channel.as_str(), "rc" | "stable") {
                    bail!("--channel must be rc or stable");
                }
                let id = match &promote.id {
                    Some(id) => id.clone(),
                    None => {
                        if promote.channel != "stable" {
                            bail!("--id is required to promote to {}", promote.channel);
                        }
                        let Some(rc) = store.target("rc") else {
                            bail!("rc points nowhere");
                        };
                        let release = store.signed_release(&rc, &key)?;
                        if release.tests.as_ref().map(|t| t.result) != Some(TestResult::Pass) {
                            bail!("rc {rc} has not passed the suite");
                        }
                        if release.held {
                            bail!("rc {rc} is held");
                        }
                        let soak = crate::vendor::parse_age(&promote.soak)?;
                        let since = release
                            .promoted
                            .rc
                            .as_deref()
                            .ok_or_else(|| eyre::eyre!("rc {rc} has no rc promotion time"))?;
                        let soaked = age_seconds(now, since)?;
                        if soaked < soak.as_secs() as i64 {
                            bail!(
                                "rc {rc} has soaked {} of {}; not promoting",
                                format_secs(soaked),
                                promote.soak
                            );
                        }
                        if let Some(stable) = store.target("stable") {
                            if stable == rc {
                                println!("stable already points at {rc}");
                                return Ok(());
                            }
                            if stable > rc {
                                bail!(
                                    "stable {stable} is newer than rc {rc}; refusing to move stable backward"
                                );
                            }
                        }
                        rc
                    }
                };
                let mut release = store.signed_release(&id, &key)?;
                if release.held {
                    bail!("snapshot {id} is held");
                }
                let stamp = now.to_string();
                match promote.channel.as_str() {
                    "rc" => release.promoted.rc.get_or_insert(stamp),
                    _ => release.promoted.stable.get_or_insert(stamp),
                };
                if promote.expedited {
                    release.expedited = true;
                }
                store.write_release(&release, &key)?;
                store.point(&promote.channel, &id)?;
                println!("{} -> {id}", promote.channel);
                Ok(())
            }
            SnapshotCommands::Hold(hold) => {
                let key = key()?;
                let mut release = store.signed_release(&hold.id, &key)?;
                release.held = true;
                release.hold_reason = Some(hold.reason.clone());
                store.write_release(&release, &key)?;
                println!("held {}: {}", hold.id, hold.reason);
                for channel in store.channels_pointing_at(&hold.id) {
                    match fallback(&store, &channel, &hold.id, &key)? {
                        Some(previous) => {
                            store.point(&channel, &previous)?;
                            println!("{channel} -> {previous}");
                        }
                        None => eprintln!(
                            "warning: {channel} still points at {}; no earlier {channel} snapshot to fall back to",
                            hold.id
                        ),
                    }
                }
                Ok(())
            }
            SnapshotCommands::Unhold(unhold) => {
                let key = key()?;
                let mut release = store.signed_release(&unhold.id, &key)?;
                release.held = false;
                release.hold_reason = None;
                store.write_release(&release, &key)?;
                println!("unheld {}", unhold.id);
                Ok(())
            }
            SnapshotCommands::Status(_) => {
                let report = status(&store)?;
                if self.json {
                    println!("{}", serde_json::to_string_pretty(&report)?);
                    return Ok(());
                }
                for channel in CHANNELS {
                    println!(
                        "{channel:7} -> {}",
                        report
                            .channels
                            .get(*channel)
                            .cloned()
                            .flatten()
                            .unwrap_or_else(|| "(none)".into())
                    );
                }
                for s in &report.snapshots {
                    println!(
                        "{}  {}  {}{}{}",
                        s.id,
                        s.tests.as_deref().unwrap_or("untested"),
                        match (&s.stable_at, &s.rc_at) {
                            (Some(_), _) => "stable",
                            (None, Some(_)) => "rc",
                            _ => "edge",
                        },
                        if s.expedited { " expedited" } else { "" },
                        s.held
                            .as_ref()
                            .map(|r| format!("  HELD: {r}"))
                            .unwrap_or_default()
                    );
                }
                Ok(())
            }
            SnapshotCommands::Prune(prune) => {
                let retain = crate::vendor::parse_age(&prune.retain)?.as_secs() as i64;
                let stable_retain =
                    crate::vendor::parse_age(&prune.stable_retain)?.as_secs() as i64;
                let targets: Vec<String> =
                    CHANNELS.iter().filter_map(|c| store.target(c)).collect();
                let mut removed = 0;
                for id in store.ids()? {
                    if targets.contains(&id) {
                        continue;
                    }
                    let release = store.release(&id)?;
                    let age = age_seconds(now, &release.created_at)?;
                    let limit = if release.promoted.stable.is_some() {
                        stable_retain
                    } else {
                        retain
                    };
                    if age <= limit {
                        continue;
                    }
                    if prune.dry_run {
                        println!("would remove {id} ({} old)", format_secs(age));
                    } else {
                        std::fs::remove_dir_all(store.snapshot_dir(&id))
                            .wrap_err_with(|| format!("removing {id}"))?;
                        println!("removed {id} ({} old)", format_secs(age));
                    }
                    removed += 1;
                }
                println!("{removed} snapshot(s) past retention");
                Ok(())
            }
            SnapshotCommands::Check(check) => {
                let release = store.release(&check.id)?;
                let outcome = check_snapshot(&store, &release, check.allow_missing)?;
                for name in &outcome.verified {
                    println!("tested: {name}");
                }
                for problem in &outcome.problems {
                    eprintln!("problem: {problem}");
                }
                eprintln!(
                    "{} package(s) verified, {} missing, {} problem(s)",
                    outcome.verified.len(),
                    outcome.missing,
                    outcome.problems.len()
                );
                if !outcome.problems.is_empty() {
                    bail!("snapshot {} is inconsistent", check.id);
                }
                Ok(())
            }
        }
    }
}

fn format_secs(secs: i64) -> String {
    let days = secs / 86_400;
    let hours = (secs % 86_400) / 3600;
    if days > 0 {
        format!("{days}d{hours}h")
    } else {
        format!("{hours}h")
    }
}

/// The newest snapshot before `held` that was promoted to `channel` (any
/// snapshot for edge), is not held, and still has a passing suite result.
fn fallback(store: &Store, channel: &str, held: &str, key: &SecretKey) -> Result<Option<String>> {
    for id in store.ids()?.into_iter().rev() {
        if id.as_str() >= held {
            continue;
        }
        let release = store.signed_release(&id, key)?;
        if release.held {
            continue;
        }
        let passed = release.tests.as_ref().map(|tests| tests.result) == Some(TestResult::Pass);
        let eligible = match channel {
            "stable" => release.promoted.stable.is_some() && passed,
            "rc" => release.promoted.rc.is_some() && passed,
            _ => true,
        };
        if eligible {
            return Ok(Some(id));
        }
    }
    Ok(None)
}

fn cut_snapshot(
    store: &Store,
    cut: &Cut,
    id: &str,
    now: jiff::Timestamp,
    key: &SecretKey,
) -> Result<Release> {
    let final_dir = store.snapshot_dir(id);
    if final_dir.exists() {
        bail!("snapshot {id} exists");
    }
    let dir = store
        .root
        .join("snapshots")
        .join(format!(".partial-{id}-{}", std::process::id()));
    let mut partial = PartialSnapshot {
        path: dir.clone(),
        committed: false,
    };
    let previous = store.ids()?.into_iter().rev().find(|p| p.as_str() < id);
    let previous_dir = previous.as_ref().map(|p| store.snapshot_dir(p));
    std::fs::create_dir_all(&dir)?;
    let mut db_digests = std::collections::BTreeMap::new();
    let mut repos: Vec<PathBuf> = std::fs::read_dir(&cut.from)
        .wrap_err_with(|| format!("reading {}", cut.from.display()))?
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.join("os").is_dir())
        .collect();
    repos.sort();
    if repos.is_empty() {
        bail!("{} has no <repo>/os/<arch> directories", cut.from.display());
    }
    for repo_dir in repos {
        let repo = repo_dir
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default()
            .to_string();
        for arch_entry in std::fs::read_dir(repo_dir.join("os"))?.filter_map(Result::ok) {
            let arch = arch_entry
                .file_name()
                .to_str()
                .unwrap_or_default()
                .to_string();
            let src = arch_entry.path();
            let rel = Path::new(&repo).join("os").join(&arch);
            let dest = dir.join(&rel);
            std::fs::create_dir_all(&dest)?;
            for file in std::fs::read_dir(&src)?.filter_map(Result::ok) {
                if !file.path().is_file() {
                    continue;
                }
                let name = file.file_name();
                let target = dest.join(&name);
                let shared = previous_dir
                    .as_ref()
                    .map(|p| p.join(&rel).join(&name))
                    .filter(|p| {
                        p.is_file()
                            && !name.to_string_lossy().contains(".db")
                            && !name.to_string_lossy().contains(".files")
                            && p.metadata().map(|m| m.len()).ok()
                                == file.metadata().map(|m| m.len()).ok()
                    });
                match shared {
                    Some(existing) if std::fs::hard_link(&existing, &target).is_ok() => {}
                    _ => {
                        std::fs::copy(file.path(), &target)
                            .wrap_err_with(|| format!("copying {}", file.path().display()))?;
                    }
                }
            }
            let db = dest.join(format!("{repo}.db"));
            if db.is_file() {
                let (sha, _) = packslip::digest_file(&db)?;
                db_digests.insert(format!("{repo}/os/{arch}/{repo}.db"), sha);
            }
        }
    }
    let mut repository_index_sequences = std::collections::BTreeMap::new();
    for path in &cut.repo_index {
        let index: crate::index::Index = serde_json::from_slice(
            &std::fs::read(path).wrap_err_with(|| format!("reading {}", path.display()))?,
        )?;
        if repository_index_sequences
            .insert(index.repo.clone(), index.sequence)
            .is_some()
        {
            bail!("more than one index supplied for repository {}", index.repo);
        }
    }
    let release = Release {
        version: 1,
        id: id.to_string(),
        channel: "edge".into(),
        arch_snapshot: id.to_string(),
        repository_index_sequences,
        created_at: now.to_string(),
        tests: None,
        tested_pkgbases: Vec::new(),
        promoted: Promoted::default(),
        expedited: false,
        held: false,
        hold_reason: None,
        db_digests,
    };
    crate::feed::write_signed(
        &dir.join("release.json"),
        &release,
        key,
        &format!("release {}", release.id),
    )?;
    std::fs::rename(&dir, &final_dir).wrap_err_with(|| format!("committing snapshot {id}"))?;
    partial.committed = true;
    Ok(release)
}

struct PartialSnapshot {
    path: PathBuf,
    committed: bool,
}

impl Drop for PartialSnapshot {
    fn drop(&mut self) {
        if !self.committed {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }
}

fn run_suite(store: &Store, test: &Test, release: &Release) -> Result<(TestResult, Vec<String>)> {
    match &test.suite {
        None => {
            let outcome = check_snapshot(store, release, test.allow_missing)?;
            for problem in &outcome.problems {
                eprintln!("problem: {problem}");
            }
            let result = if outcome.problems.is_empty() {
                TestResult::Pass
            } else {
                TestResult::Fail
            };
            Ok((result, outcome.verified))
        }
        Some(command) => {
            let mut child = Command::new("sh")
                .arg("-c")
                .arg(command)
                .env("PACVAMP_SNAPSHOT_ID", &test.id)
                .env("PACVAMP_SNAPSHOT_DIR", store.snapshot_dir(&test.id))
                .stdout(Stdio::piped())
                .stderr(Stdio::inherit())
                .spawn()
                .wrap_err("running the suite")?;
            let stdout = child.stdout.take().expect("suite stdout was piped");
            let mut tested = Vec::new();
            for line in BufReader::new(stdout).lines() {
                let line = line.wrap_err("reading suite output")?;
                println!("{line}");
                std::io::stdout().flush()?;
                if let Some(pkgbase) = line.strip_prefix("tested:").map(str::trim)
                    && !pkgbase.is_empty()
                {
                    tested.push(pkgbase.to_string());
                }
            }
            tested.sort();
            tested.dedup();
            let status = child.wait().wrap_err("waiting for the suite")?;
            let result = if status.success() {
                TestResult::Pass
            } else {
                TestResult::Fail
            };
            Ok((result, tested))
        }
    }
}

#[derive(Debug, Default)]
pub struct CheckOutcome {
    pub verified: Vec<String>,
    pub missing: usize,
    pub problems: Vec<String>,
}

/// Every database parses and matches its recorded digest; every package
/// file present matches the size and sha256 the database records.
pub fn check_snapshot(
    store: &Store,
    release: &Release,
    allow_missing: bool,
) -> Result<CheckOutcome> {
    let dir = store.snapshot_dir(&release.id);
    let mut outcome = CheckOutcome::default();
    let mut seen_digests = std::collections::BTreeSet::new();
    let mut repos: Vec<PathBuf> = std::fs::read_dir(&dir)?
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.join("os").is_dir())
        .collect();
    repos.sort();
    for repo_dir in repos {
        let repo = repo_dir
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default()
            .to_string();
        seen_digests.insert(repo.clone());
        for arch_entry in std::fs::read_dir(repo_dir.join("os"))?.filter_map(Result::ok) {
            let arch = arch_entry.file_name().to_string_lossy().into_owned();
            let pool = arch_entry.path();
            let db_path = pool.join(format!("{repo}.db"));
            let db_key = format!("{repo}/os/{arch}/{repo}.db");
            seen_digests.insert(db_key.clone());
            if !db_path.is_file() {
                outcome
                    .problems
                    .push(format!("{repo}: no database at {}", db_path.display()));
                continue;
            }
            let (sha, _) = packslip::digest_file(&db_path)?;
            if let Some(expected) = release
                .db_digests
                .get(&db_key)
                .or_else(|| release.db_digests.get(&repo))
                && expected != &sha
            {
                outcome.problems.push(format!(
                    "{db_key}: database digest {sha} is not the recorded {expected}"
                ));
            }
            let db = match SyncDb::read(&db_path, &repo) {
                Ok(db) => db,
                Err(err) => {
                    outcome
                        .problems
                        .push(format!("{repo}: database does not parse: {err}"));
                    continue;
                }
            };
            for package in &db.packages {
                let file = pool.join(&package.filename);
                if !file.is_file() {
                    outcome.missing += 1;
                    continue;
                }
                let (file_sha, size) = packslip::digest_file(&file)?;
                if let Some(expected) = &package.sha256sum
                    && expected != &file_sha
                {
                    outcome
                        .problems
                        .push(format!("{repo}/{}: sha256 mismatch", package.filename));
                    continue;
                }
                if let Some(expected) = package.csize
                    && expected != size
                {
                    outcome
                        .problems
                        .push(format!("{repo}/{}: size mismatch", package.filename));
                    continue;
                }
                outcome
                    .verified
                    .push(package.base.clone().unwrap_or_else(|| package.name.clone()));
            }
        }
    }
    for key in release.db_digests.keys() {
        if !seen_digests.contains(key) {
            outcome
                .problems
                .push(format!("{key}: recorded database is missing"));
        }
    }
    if outcome.missing > 0 && !allow_missing {
        outcome.problems.push(format!(
            "{} package file(s) listed in the databases are missing",
            outcome.missing
        ));
    }
    outcome.verified.sort();
    outcome.verified.dedup();
    Ok(outcome)
}

#[derive(Debug, Serialize)]
pub struct StatusReport {
    pub channels: std::collections::BTreeMap<String, Option<String>>,
    pub snapshots: Vec<SnapshotRow>,
}

#[derive(Debug, Serialize)]
pub struct SnapshotRow {
    pub id: String,
    pub created_at: String,
    pub tests: Option<String>,
    pub tested_pkgbases: usize,
    pub rc_at: Option<String>,
    pub stable_at: Option<String>,
    pub expedited: bool,
    pub held: Option<String>,
}

pub fn status(store: &Store) -> Result<StatusReport> {
    let channels = CHANNELS
        .iter()
        .map(|c| (c.to_string(), store.target(c)))
        .collect();
    let mut snapshots = Vec::new();
    for id in store.ids()?.into_iter().rev() {
        let r = store.release(&id)?;
        snapshots.push(SnapshotRow {
            id,
            created_at: r.created_at.clone(),
            tests: r.tests.as_ref().map(|t| {
                format!(
                    "{}:{}",
                    t.suite,
                    match t.result {
                        TestResult::Pass => "pass",
                        TestResult::Fail => "fail",
                        TestResult::Pending => "pending",
                    }
                )
            }),
            tested_pkgbases: r.tested_pkgbases.len(),
            rc_at: r.promoted.rc.clone(),
            stable_at: r.promoted.stable.clone(),
            expedited: r.expedited,
            held: if r.held {
                Some(r.hold_reason.clone().unwrap_or_default())
            } else {
                None
            },
        });
    }
    Ok(StatusReport {
        channels,
        snapshots,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_and_ages() {
        let at = jiff::Timestamp::from_str("2026-09-03T06:30:00Z").unwrap();
        assert_eq!(snapshot_id(at), "2026-09-03T06");
        assert_eq!(age_seconds(at, "2026-09-01T06:30:00Z").unwrap(), 2 * 86_400);
        assert_eq!(format_secs(2 * 86_400 + 3600), "2d1h");
        assert_eq!(format_secs(7200), "2h");
    }
}
