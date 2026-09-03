use std::path::{Path, PathBuf};

use eyre::{Result, bail};
use serde::Serialize;
use usage_rs::RunWith;

use super::{App, print_json};
use crate::host::Host;
use crate::resolve::Tier;
use crate::trust::{self, Index};

/// Re-run the evidence chain for a package or a package file
///
/// For a repository package, checks the file in pacman's cache against
/// the repository's signed index: digest, size, sidecars, and the
/// evidence the repository claims. For a file path, matches it to the
/// index by name. Refuses an index older than the last one seen.
#[derive(Debug, usage_rs::Args)]
pub struct Verify {
    /// A package name, or a path to a .pkg.tar.* file
    target: String,
    /// Use the cached feeds only
    #[usage(long)]
    offline: bool,
    /// Print as JSON
    #[usage(short = 'J', long)]
    json: bool,
}

#[derive(Debug, Serialize)]
pub struct Report {
    pub name: String,
    pub repo: String,
    pub filename: String,
    pub index_sequence: u64,
    pub index_key: String,
    pub digest_checked: bool,
    pub digest_ok: Option<bool>,
    pub size_ok: Option<bool>,
    pub sidecars: Vec<String>,
    pub evidence: trust::feeds::Evidence,
    pub db_ok: Option<bool>,
}

impl App {
    /// The feed source for the repository named `repo`: its first server.
    pub fn feed_source(&self, host: &Host, repo: &str) -> Option<trust::FeedSource> {
        let source = host.sources.iter().find(|s| s.name == repo)?;
        let base = source.repo.servers.first()?.clone();
        Some(trust::FeedSource {
            repo: repo.to_string(),
            base,
        })
    }

    /// Fetch and verify a repository's index, enforcing rollback protection
    /// against the ledger and recording the new sequence.
    pub fn index(&self, host: &Host, repo: &str, offline: bool) -> Result<trust::Fetched<Index>> {
        let Some(source) = self.feed_source(host, repo) else {
            bail!("[{repo}] has no server to fetch feeds from");
        };
        let keyring = trust::Keyring::load(self.paths.sysroot.as_deref())?;
        let cache = trust::Cache::for_repo(repo);
        let fetched: trust::Fetched<Index> =
            trust::fetch(&source, "omapac-index.json", &keyring, &cache, offline)?;
        if fetched.value.repo != repo {
            bail!("[{repo}] index says it is for [{}]", fetched.value.repo);
        }
        let ledger = self.ledger()?;
        if let Some(seen) = ledger.index_sequences.get(repo).copied()
            && fetched.value.sequence < seen
        {
            bail!(
                "[{repo}] index sequence {} is older than the {} this machine has seen: a stale or rolled-back mirror",
                fetched.value.sequence,
                seen
            );
        }
        if fetched.fresh
            && ledger.index_sequences.get(repo).copied() != Some(fetched.value.sequence)
        {
            let mut patch = crate::ledger::Patch::default();
            patch
                .index_sequences
                .insert(repo.to_string(), fetched.value.sequence);
            self.record(&patch)?;
        }
        Ok(fetched)
    }
}

impl RunWith<&App> for Verify {
    type Output = Result<()>;

    fn run_with(self, app: &App) -> Self::Output {
        let host = app.host()?;
        let path = Path::new(&self.target);
        let (name, repo, filename, file): (String, String, String, Option<PathBuf>) = if path
            .is_file()
        {
            let filename = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or_default()
                .to_string();
            // Find which repository's database lists this file name.
            let mut found = None;
            for source in &host.sources {
                if let Some(db) = source.db()?
                    && let Some(p) = db.packages.iter().find(|p| p.filename == filename)
                {
                    found = Some((p.name.clone(), source.name.clone()));
                    break;
                }
            }
            let Some((name, repo)) = found else {
                bail!("{filename} is in no sync database; cannot tell which index to check");
            };
            (name, repo, filename, Some(path.to_path_buf()))
        } else {
            let Some((source, package)) = host.find_sync(&self.target)? else {
                bail!("{} is in no sync database", self.target);
            };
            if !matches!(source.tier, Tier::Opr) && !matches!(source.tier, Tier::Custom(_)) {
                bail!(
                    "{} comes from [{}] ({}), which publishes no omapac index; pacman's signature check is its evidence",
                    self.target,
                    source.name,
                    source.tier
                );
            }
            let cached = host
                .config
                .options
                .cache_dirs()
                .into_iter()
                .map(|dir| app.rooted(&dir).join(&package.filename))
                .find(|p| p.is_file());
            (
                package.name.clone(),
                source.name.clone(),
                package.filename.clone(),
                cached,
            )
        };
        let fetched = app.index(&host, &repo, self.offline)?;
        let index = &fetched.value;
        let Some(entry) = index.package(&filename) else {
            bail!(
                "{filename} is not in the [{repo}] index (sequence {})",
                index.sequence
            );
        };
        let (digest_ok, size_ok) = match &file {
            Some(file) => {
                let (digest, size) = packslip::digest_file(file)?;
                (Some(digest == entry.sha256), Some(size == entry.size))
            }
            None => (None, None),
        };
        let db_path = app
            .rooted(&host.config.options.db_path())
            .join("sync")
            .join(&index.db.file);
        let db_ok = db_path
            .is_file()
            .then(|| trust::sha256_file(&db_path).map(|d| d == index.db.sha256))
            .transpose()?;
        let report = Report {
            name,
            repo,
            filename,
            index_sequence: index.sequence,
            index_key: fetched.key_id.clone(),
            digest_checked: file.is_some(),
            digest_ok,
            size_ok,
            sidecars: entry.sidecars.clone(),
            evidence: entry.evidence.clone(),
            db_ok,
        };
        if self.json {
            print_json(&report)?;
        } else {
            println!(
                "{} from [{}] as {} (index sequence {}, signed by {})",
                report.name, report.repo, report.filename, report.index_sequence, report.index_key
            );
            match report.digest_ok {
                Some(true) => println!("digest: ok"),
                Some(false) => println!("digest: MISMATCH"),
                None => {
                    println!("digest: not checked (no local file; pass a path or install first)")
                }
            }
            match report.size_ok {
                Some(true) => println!("size: ok"),
                Some(false) => println!("size: MISMATCH"),
                None => println!("size: not checked"),
            }
            println!(
                "sidecars: {}",
                if report.sidecars.is_empty() {
                    "none".to_string()
                } else {
                    report.sidecars.join(", ")
                }
            );
            let e = &report.evidence;
            println!(
                "evidence: build provenance {}, vendor manifest {}, {} verdict(s), reproducible {}",
                yes_no(e.build_provenance),
                yes_no(e.vendor_manifest),
                e.verdicts,
                e.reproducible.map(yes_no).unwrap_or("unknown")
            );
            match report.db_ok {
                Some(true) => println!("database: matches the index"),
                Some(false) => {
                    println!("database: DOES NOT MATCH the index; refresh or suspect the mirror")
                }
                None => println!("database: not on disk"),
            }
        }
        let failed = report.digest_ok == Some(false)
            || report.size_ok == Some(false)
            || report.db_ok == Some(false);
        if failed {
            std::process::exit(1);
        }
        Ok(())
    }
}

fn yes_no(b: bool) -> &'static str {
    if b { "yes" } else { "no" }
}

impl App {
    /// A path under the sysroot, when one is set.
    pub fn rooted(&self, path: &Path) -> PathBuf {
        match &self.paths.sysroot {
            Some(root) => root.join(path.strip_prefix("/").unwrap_or(path)),
            None => path.to_path_buf(),
        }
    }
}
