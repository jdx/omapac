//! `omapac-repo index`: the signed index of a repository directory. See
//! `docs/spec/repository-feeds.md`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use eyre::{Context as _, Result, bail};
use packslip::minisign::{PublicKey, SecretKey};
use serde::{Deserialize, Serialize};
use usage_rs::RunWith;

pub const INDEX_FILE: &str = "omapac-index.json";

/// The index document. Mirrors the client's `trust::feeds::Index`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Index {
    pub version: u32,
    pub repo: String,
    pub sequence: u64,
    pub generated_at: String,
    pub db: IndexDb,
    pub packages: BTreeMap<String, IndexPackage>,
    #[serde(default)]
    pub build_keys: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndexDb {
    pub file: String,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct IndexPackage {
    pub sha256: String,
    pub size: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub published_at: Option<String>,
    #[serde(default)]
    pub sidecars: Vec<String>,
    #[serde(default)]
    pub evidence: Evidence,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct Evidence {
    #[serde(default)]
    pub build_provenance: bool,
    #[serde(default)]
    pub vendor_manifest: bool,
    #[serde(default)]
    pub verdicts: u32,
    #[serde(default)]
    pub reproducible: Option<bool>,
}

/// Write the signed index for a repository directory
///
/// Scans the directory for the database and every package file, records
/// each file's digest and size, carries publish times over from the
/// previous index for files already listed (new files get now), lists
/// the sidecars present, verifies build provenance envelopes with the
/// accepted build keys, and writes omapac-index.json plus its minisign
/// signature with the sequence one above the previous index.
#[derive(Debug, usage_rs::Args)]
pub struct IndexCmd {
    /// The repository name, as in pacman.conf
    #[usage(long)]
    repo: String,
    /// The directory holding <repo>.db and the packages
    #[usage(short = 'd', long, value_hint = usage_rs::ValueHint::DirPath)]
    dir: PathBuf,
    /// The index signing key (secret seed from `packslip keygen`)
    #[usage(short = 'k', long, value_hint = usage_rs::ValueHint::FilePath)]
    key: PathBuf,
    /// Accepted build key public files, repeatable
    #[usage(long)]
    build_key: Vec<PathBuf>,
    /// Use this sequence instead of previous + 1
    #[usage(long)]
    sequence: Option<u64>,
    /// Print the index instead of writing it
    #[usage(long)]
    stdout: bool,
}

impl RunWith<()> for IndexCmd {
    type Output = Result<()>;

    fn run_with(self, _: ()) -> Self::Output {
        let key_text = std::fs::read_to_string(&self.key)
            .wrap_err_with(|| format!("reading {}", self.key.display()))?;
        let key = SecretKey::parse(&key_text)?;
        let previous = read_previous(&self.dir)?;
        let mut build_keys = Vec::new();
        let key_texts: Vec<(String, String)> = if self.build_key.is_empty() {
            previous
                .as_ref()
                .map(|index| {
                    index
                        .build_keys
                        .iter()
                        .cloned()
                        .map(|text| ("previous index".to_string(), text))
                        .collect()
                })
                .unwrap_or_default()
        } else {
            self.build_key
                .iter()
                .map(|path| {
                    std::fs::read_to_string(path)
                        .wrap_err_with(|| format!("reading {}", path.display()))
                        .map(|text| (path.display().to_string(), text))
                })
                .collect::<Result<_>>()?
        };
        for (source, text) in key_texts {
            build_keys.push((
                PublicKey::parse(&text).map_err(|e| eyre::eyre!("{source}: {e}"))?,
                text,
            ));
        }
        let index = build(
            &self.repo,
            &self.dir,
            previous.as_ref(),
            &build_keys,
            self.sequence,
        )?;
        let bytes = serde_json::to_vec_pretty(&index)?;
        if self.stdout {
            println!("{}", String::from_utf8_lossy(&bytes));
            return Ok(());
        }
        let signature = key
            .sign(
                &bytes,
                &format!("omapac-index {} sequence {}", index.repo, index.sequence),
            )
            .to_file();
        let path = self.dir.join(INDEX_FILE);
        write_signed_pair(&path, &bytes, signature.as_bytes())?;
        println!(
            "wrote {} (sequence {}, {} package(s), db {})",
            path.display(),
            index.sequence,
            index.packages.len(),
            index.db.file
        );
        Ok(())
    }
}

fn sig_path(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(".minisig");
    PathBuf::from(name)
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let temp = path.with_extension("tmp");
    std::fs::write(&temp, bytes).wrap_err_with(|| format!("writing {}", temp.display()))?;
    std::fs::rename(&temp, path).wrap_err_with(|| format!("renaming to {}", path.display()))?;
    Ok(())
}

/// Stage both members before publishing either one, and restore the old
/// index if publishing the signature fails. This avoids leaving a mixed
/// pair after an ordinary I/O error.
fn write_signed_pair(path: &Path, bytes: &[u8], signature: &[u8]) -> Result<()> {
    let signature_path = sig_path(path);
    let index_temp = path.with_extension("json.pair-tmp");
    let signature_temp = signature_path.with_extension("minisig.pair-tmp");
    std::fs::write(&index_temp, bytes)
        .wrap_err_with(|| format!("writing {}", index_temp.display()))?;
    if let Err(err) = std::fs::write(&signature_temp, signature) {
        let _ = std::fs::remove_file(&index_temp);
        return Err(err).wrap_err_with(|| format!("writing {}", signature_temp.display()));
    }
    let previous = std::fs::read(path).ok();
    std::fs::rename(&index_temp, path)
        .wrap_err_with(|| format!("publishing {}", path.display()))?;
    if let Err(err) = std::fs::rename(&signature_temp, &signature_path) {
        match previous {
            Some(previous) => write_atomic(path, &previous)?,
            None => {
                let _ = std::fs::remove_file(path);
            }
        }
        return Err(err).wrap_err_with(|| format!("publishing {}", signature_path.display()));
    }
    Ok(())
}

/// The previous index in the directory, if any.
pub fn read_previous(dir: &Path) -> Result<Option<Index>> {
    match std::fs::read(dir.join(INDEX_FILE)) {
        Ok(bytes) => Ok(Some(
            serde_json::from_slice(&bytes).wrap_err("parsing the previous index")?,
        )),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err).wrap_err("reading the previous index"),
    }
}

/// Sidecar suffixes the index lists, in the order they are reported.
const SIDECARS: &[&str] = &[
    ".sig",
    crate::attest::SIDECAR,
    ".sigstore.json",
    ".vendor.sigstore.json",
    ".vendor.json",
    ".scan.json",
];

/// Build the index for `dir`.
pub fn build(
    repo: &str,
    dir: &Path,
    previous: Option<&Index>,
    build_keys: &[(PublicKey, String)],
    sequence: Option<u64>,
) -> Result<Index> {
    let db_file = format!("{repo}.db");
    let db_path = dir.join(&db_file);
    if !db_path.is_file() {
        bail!(
            "{} not found; is {} a repository directory?",
            db_path.display(),
            dir.display()
        );
    }
    let (db_sha, _) = packslip::digest_file(&db_path)?;
    let now = jiff::Timestamp::now().to_string();
    let keys: Vec<PublicKey> = build_keys.iter().map(|(k, _)| k.clone()).collect();
    let mut packages = BTreeMap::new();
    let mut entries: Vec<PathBuf> = std::fs::read_dir(dir)
        .wrap_err_with(|| format!("reading {}", dir.display()))?
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.is_file() && is_package(p))
        .collect();
    entries.sort();
    for path in entries {
        let filename = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default()
            .to_string();
        let (sha256, size) = packslip::digest_file(&path)?;
        let sidecars: Vec<String> = SIDECARS
            .iter()
            .map(|suffix| format!("{filename}{suffix}"))
            .filter(|name| dir.join(name).is_file())
            .collect();
        let mut evidence = Evidence::default();
        let provenance = crate::attest::sidecar_path(&path);
        if provenance.is_file() {
            match crate::attest::verify_sidecar(&provenance, &sha256, &keys) {
                Ok(Some(_)) => evidence.build_provenance = true,
                Ok(None) => {}
                Err(err) => eprintln!("warning: {filename}: provenance not accepted: {err:#}"),
            }
        }
        evidence.vendor_manifest = sidecars
            .iter()
            .any(|s| s.ends_with(".vendor.json") || s.ends_with(".vendor.sigstore.json"));
        let published_at = previous
            .and_then(|p| p.packages.get(&filename))
            .filter(|p| p.sha256 == sha256)
            .and_then(|p| p.published_at.clone())
            .unwrap_or_else(|| now.clone());
        packages.insert(
            filename,
            IndexPackage {
                sha256,
                size,
                published_at: Some(published_at),
                sidecars,
                evidence,
            },
        );
    }
    let sequence = match (sequence, previous) {
        (Some(explicit), Some(prev)) if explicit <= prev.sequence => bail!(
            "--sequence {explicit} is not above the previous index's {}",
            prev.sequence
        ),
        (Some(explicit), _) => explicit,
        (None, Some(prev)) => prev.sequence + 1,
        (None, None) => 1,
    };
    Ok(Index {
        version: 1,
        repo: repo.to_string(),
        sequence,
        generated_at: now,
        db: IndexDb {
            file: db_file,
            sha256: db_sha,
        },
        packages,
        build_keys: build_keys.iter().map(|(_, text)| text.clone()).collect(),
    })
}

fn is_package(path: &Path) -> bool {
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or_default();
    name.contains(".pkg.tar.") && !name.ends_with(".sig") && !name.ends_with(".json")
}
