use std::path::{Path, PathBuf};

use eyre::{Result, bail};
use serde::Serialize;
use usage_rs::RunWith;

use super::{App, print_json};
use crate::host::Host;
use crate::resolve::Tier;
use crate::trust::{self, Index};

fn require_omapac_index(source: &crate::host::Source, target: &str) -> Result<()> {
    if !matches!(source.tier, Tier::Opr | Tier::Custom(_)) {
        bail!(
            "{target} comes from [{}] ({}), which publishes no omapac index; pacman's signature check is its evidence",
            source.name,
            source.tier
        );
    }
    Ok(())
}

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
    /// The build provenance sidecar, when the index lists one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provenance: Option<Provenance>,
    /// The transparency log entry sidecar, when the index lists one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transparency: Option<Transparency>,
}

#[derive(Debug, Serialize)]
pub struct Provenance {
    pub verified: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub build_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pkgbase: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub commit: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct Transparency {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub log: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub log_index: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Fetch and verify `<file>.provenance.json` with the index's build keys:
/// a DSSE envelope whose statement names the package digest.
fn check_provenance(base: &str, filename: &str, sha256: &str, build_keys: &[String]) -> Provenance {
    let failed = |error: String| Provenance {
        verified: false,
        build_key: None,
        pkgbase: None,
        source: None,
        commit: None,
        error: Some(error),
    };
    let bytes = match super::tools::download(
        &format!("{base}/{filename}.provenance.json"),
        64 * 1024 * 1024,
    ) {
        Ok(bytes) => bytes,
        Err(err) => return failed(format!("{err:#}")),
    };
    let envelope: packslip::dsse::Envelope = match serde_json::from_slice(&bytes) {
        Ok(envelope) => envelope,
        Err(err) => return failed(format!("envelope: {err}")),
    };
    let keys: Vec<packslip::minisign::PublicKey> = build_keys
        .iter()
        .filter_map(|text| packslip::minisign::PublicKey::parse(text).ok())
        .collect();
    if keys.is_empty() {
        return failed("the index publishes no build keys".into());
    }
    let Some((payload, key)) = envelope.verify_any(keys.iter()) else {
        return failed("not signed by any build key the index publishes".into());
    };
    let statement: serde_json::Value = match serde_json::from_slice(&payload) {
        Ok(statement) => statement,
        Err(err) => return failed(format!("statement: {err}")),
    };
    let named = statement["subject"].as_array().is_some_and(|subjects| {
        subjects
            .iter()
            .any(|s| s["digest"]["sha256"].as_str() == Some(sha256))
    });
    if !named {
        return failed("statement does not name the package digest".into());
    }
    let params = &statement["predicate"]["buildDefinition"]["externalParameters"];
    Provenance {
        verified: true,
        build_key: Some(packslip::minisign::key_id_hex(&key.key_id)),
        pkgbase: params["pkgbase"].as_str().map(str::to_string),
        source: params["source"].as_str().map(str::to_string),
        commit: params["commit"].as_str().map(str::to_string),
        error: None,
    }
}

/// Fetch `<file>.rekor.json` and check its body is a dsse entry whose
/// payload hash is the provenance envelope's payload.
fn check_transparency(base: &str, filename: &str) -> Transparency {
    let failed = |error: String| Transparency {
        ok: false,
        log: None,
        log_index: None,
        error: Some(error),
    };
    let entry: serde_json::Value =
        match super::tools::download(&format!("{base}/{filename}.rekor.json"), 64 * 1024 * 1024)
            .and_then(|bytes| Ok(serde_json::from_slice(&bytes)?))
        {
            Ok(entry) => entry,
            Err(err) => return failed(format!("{err:#}")),
        };
    let envelope_bytes = match super::tools::download(
        &format!("{base}/{filename}.provenance.json"),
        64 * 1024 * 1024,
    ) {
        Ok(bytes) => bytes,
        Err(err) => return failed(format!("{err:#}")),
    };
    let payload = serde_json::from_slice::<packslip::dsse::Envelope>(&envelope_bytes)
        .ok()
        .and_then(|e| e.payload_bytes().ok());
    let Some(payload) = payload else {
        return failed("provenance envelope unreadable".into());
    };
    use base64::Engine as _;
    let body = entry["body"]
        .as_str()
        .and_then(|b| base64::engine::general_purpose::STANDARD.decode(b).ok())
        .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok());
    let Some(body) = body else {
        return failed("entry body unreadable".into());
    };
    let expected = trust::sha256_bytes(&payload);
    let actual = body["spec"]["payloadHash"]["value"]
        .as_str()
        .unwrap_or_default();
    if body["kind"] != "dsse" || !actual.eq_ignore_ascii_case(&expected) {
        return failed("entry is not about the provenance envelope".into());
    }
    if entry["inclusion_proof"].is_null() {
        return failed("entry has no inclusion proof".into());
    }
    Transparency {
        ok: true,
        log: entry["log_url"].as_str().map(str::to_string),
        log_index: entry["log_index"].as_u64(),
        error: None,
    }
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
        self.index_with_recording(host, repo, offline, true)
    }

    /// Fetch and verify an index without mutating rollback state.
    pub fn index_readonly(
        &self,
        host: &Host,
        repo: &str,
        offline: bool,
    ) -> Result<trust::Fetched<Index>> {
        self.index_with_recording(host, repo, offline, false)
    }

    fn index_with_recording(
        &self,
        host: &Host,
        repo: &str,
        offline: bool,
        record_sequence: bool,
    ) -> Result<trust::Fetched<Index>> {
        let Some(source) = self.feed_source(host, repo) else {
            bail!("[{repo}] has no server to fetch feeds from");
        };
        let keyring = trust::Keyring::load(self.paths.sysroot.as_deref())?;
        let cache = trust::Cache::for_repo(repo, self.paths.sysroot.as_deref())?;
        let ledger = self.ledger()?;
        let seen = ledger.index_sequences.get(repo).copied();
        let fetched: trust::Fetched<Index> = trust::fetch_checked(
            &source,
            "omapac-index.json",
            &keyring,
            &cache,
            offline,
            |index: &Index| {
                if let Some(seen) = seen
                    && index.sequence < seen
                {
                    bail!(
                        "[{repo}] index sequence {} is older than the {seen} this machine has seen: a stale or rolled-back mirror",
                        index.sequence
                    );
                }
                Ok(())
            },
        )?;
        if fetched.value.repo != repo {
            bail!("[{repo}] index says it is for [{}]", fetched.value.repo);
        }
        if record_sequence
            && ledger.index_sequences.get(repo).copied() != Some(fetched.value.sequence)
        {
            let mut patch = crate::ledger::Patch::default();
            patch
                .index_sequences
                .insert(repo.to_string(), fetched.value.sequence);
            if let Err(err) = self.record(&patch) {
                eprintln!(
                    "warning: verified [{repo}] index sequence {} but could not record rollback state: {err:#}",
                    fetched.value.sequence
                );
            }
        }
        Ok(fetched)
    }
}

impl RunWith<&App> for Verify {
    type Output = Result<()>;

    fn run_with(self, app: &App) -> Self::Output {
        let host = app.host()?;
        let path = Path::new(&self.target);
        let explicit_path = path.components().count() > 1 || self.target.contains(".pkg.tar.");
        let (name, repo, filename, file): (String, String, String, Option<PathBuf>) =
            if explicit_path && path.is_file() {
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
                        require_omapac_index(source, &filename)?;
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
                require_omapac_index(source, &self.target)?;
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
        let base = app.feed_source(&host, &repo).map(|f| f.base);
        let provenance = base
            .as_ref()
            .filter(|_| {
                entry
                    .sidecars
                    .iter()
                    .any(|s| s == &format!("{filename}.provenance.json"))
            })
            .map(|base| check_provenance(base, &filename, &entry.sha256, &index.build_keys));
        let transparency = base
            .as_ref()
            .filter(|_| {
                entry
                    .sidecars
                    .iter()
                    .any(|s| s == &format!("{filename}.rekor.json"))
            })
            .map(|base| check_transparency(base, &filename));
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
            provenance,
            transparency,
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
            match &report.provenance {
                Some(p) if p.verified => println!(
                    "provenance: verified (build key {}, {} at {} from {})",
                    p.build_key.as_deref().unwrap_or("?"),
                    p.pkgbase.as_deref().unwrap_or("?"),
                    p.commit.as_deref().unwrap_or("?"),
                    p.source.as_deref().unwrap_or("?")
                ),
                Some(p) => println!(
                    "provenance: FAILED: {}",
                    p.error.as_deref().unwrap_or("unknown")
                ),
                None => println!("provenance: none published"),
            }
            match &report.transparency {
                Some(t) if t.ok => println!(
                    "transparency: entry {} at {}",
                    t.log_index.unwrap_or(0),
                    t.log.as_deref().unwrap_or("?")
                ),
                Some(t) => println!(
                    "transparency: FAILED: {}",
                    t.error.as_deref().unwrap_or("unknown")
                ),
                None => {}
            }
        }
        let failed = report.provenance.as_ref().is_some_and(|p| !p.verified)
            || report.transparency.as_ref().is_some_and(|t| !t.ok)
            || report.digest_ok == Some(false)
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
        self.paths.rooted(path)
    }
}
