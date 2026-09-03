//! `pacvamp-repo sign`: the signer gate. The repository GPG key signs a
//! package only after its build provenance verifies with an allowlisted
//! build key. See `docs/spec/provenance.md`, "The signer gate".

use std::path::{Path, PathBuf};
use std::process::Command;

use eyre::{Context as _, Result, bail};
use packslip::dsse::Envelope;
use packslip::minisign::PublicKey;
use serde::Serialize;
use usage_rs::RunWith;

/// Sign packages with the repository key after checking provenance
///
/// For every package in the directory without a .sig (or the packages
/// given), verify its provenance envelope with an allowlisted build key
/// and that the subject digest matches the file; optionally require a
/// transparency log entry and consistency with the index. Only then run
/// gpg to produce the detached signature pacman checks. A package that
/// fails any check is refused and the command exits 1, so a build host
/// compromise cannot produce a repository-signed package by itself.
#[derive(Debug, usage_rs::Args)]
pub struct Sign {
    /// The repository directory
    #[usage(short = 'd', long, value_hint = usage_rs::ValueHint::DirPath)]
    dir: PathBuf,
    /// Only these package files (relative to the directory)
    #[usage(long)]
    package: Vec<PathBuf>,
    /// Allowlisted build key public files, repeatable
    #[usage(long, required = true)]
    build_key: Vec<PathBuf>,
    /// The GPG key id to sign with
    #[usage(long)]
    gpg_key: String,
    /// The gpg program
    #[usage(long, default = "gpg")]
    gpg: String,
    /// Require a stored transparency log entry about the envelope, with
    /// an inclusion proof that reaches its root
    #[usage(long)]
    require_rekor: bool,
    /// The log's public key (SPKI PEM) to verify checkpoints with
    #[usage(long, value_hint = usage_rs::ValueHint::FilePath)]
    rekor_pubkey: Option<PathBuf>,
    /// Require the package to be listed with this digest in the index
    #[usage(long)]
    index: Option<PathBuf>,
    /// Check and report without signing
    #[usage(short = 'n', long)]
    dry_run: bool,
    /// Print the report as JSON
    #[usage(short = 'J', long)]
    json: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "status", rename_all = "kebab-case")]
pub enum Outcome {
    Signed { build_key: String },
    WouldSign { build_key: String },
    AlreadySigned,
    Refused { reason: String },
}

#[derive(Debug, Clone, Serialize)]
pub struct Verdict {
    pub file: String,
    #[serde(flatten)]
    pub outcome: Outcome,
}

impl RunWith<()> for Sign {
    type Output = Result<()>;

    fn run_with(self, _: ()) -> Self::Output {
        let mut keys = Vec::new();
        for path in &self.build_key {
            let text = std::fs::read_to_string(path)
                .wrap_err_with(|| format!("reading {}", path.display()))?;
            keys.push(PublicKey::parse(&text).map_err(|e| eyre::eyre!("{}: {e}", path.display()))?);
        }
        let index = match &self.index {
            Some(path) => Some(
                serde_json::from_slice::<crate::index::Index>(
                    &std::fs::read(path).wrap_err_with(|| format!("reading {}", path.display()))?,
                )
                .wrap_err("parsing the index")?,
            ),
            None => None,
        };
        let log_key = match &self.rekor_pubkey {
            Some(path) => Some(crate::rekor::log_key(
                &std::fs::read_to_string(path)
                    .wrap_err_with(|| format!("reading {}", path.display()))?,
            )?),
            None => None,
        };
        let packages: Vec<PathBuf> = if self.package.is_empty() {
            let mut all: Vec<PathBuf> = std::fs::read_dir(&self.dir)
                .wrap_err_with(|| format!("reading {}", self.dir.display()))?
                .filter_map(Result::ok)
                .map(|e| e.path())
                .filter(|p| p.is_file() && crate::index::is_package(p))
                .collect();
            all.sort();
            all
        } else {
            self.package.iter().map(|p| self.dir.join(p)).collect()
        };
        let mut verdicts = Vec::new();
        for package in &packages {
            let file = package
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or_default()
                .to_string();
            let outcome = if sig_path(package).exists() {
                Outcome::AlreadySigned
            } else {
                match check(
                    package,
                    &keys,
                    self.require_rekor,
                    log_key.as_ref(),
                    index.as_ref(),
                ) {
                    Err(reason) => Outcome::Refused { reason },
                    Ok(build_key) if self.dry_run => Outcome::WouldSign { build_key },
                    Ok(build_key) => match gpg_sign(&self.gpg, &self.gpg_key, package) {
                        Ok(()) => Outcome::Signed { build_key },
                        Err(err) => Outcome::Refused {
                            reason: format!("gpg: {err:#}"),
                        },
                    },
                }
            };
            verdicts.push(Verdict { file, outcome });
        }
        let refused = verdicts
            .iter()
            .filter(|v| matches!(v.outcome, Outcome::Refused { .. }))
            .count();
        if self.json {
            println!("{}", serde_json::to_string_pretty(&verdicts)?);
        } else {
            for v in &verdicts {
                match &v.outcome {
                    Outcome::Signed { build_key } => {
                        println!("signed   {} (provenance by {build_key})", v.file)
                    }
                    Outcome::WouldSign { build_key } => {
                        println!("would sign {} (provenance by {build_key})", v.file)
                    }
                    Outcome::AlreadySigned => println!("skipped  {} (already signed)", v.file),
                    Outcome::Refused { reason } => println!("REFUSED  {}: {reason}", v.file),
                }
            }
        }
        if refused > 0 {
            bail!("{refused} package(s) refused a signature");
        }
        Ok(())
    }
}

fn sig_path(package: &Path) -> PathBuf {
    let mut name = package.as_os_str().to_owned();
    name.push(".sig");
    PathBuf::from(name)
}

/// Every gate a package must pass; returns the build key id that vouched.
pub fn check(
    package: &Path,
    keys: &[PublicKey],
    require_rekor: bool,
    log_key: Option<&p256::ecdsa::VerifyingKey>,
    index: Option<&crate::index::Index>,
) -> Result<String, String> {
    let (sha256, _) = packslip::digest_file(package).map_err(|e| format!("hashing: {e}"))?;
    let provenance = crate::attest::sidecar_path(package);
    let text = std::fs::read_to_string(&provenance)
        .map_err(|_| "no provenance envelope beside the package".to_string())?;
    let envelope: Envelope =
        serde_json::from_str(&text).map_err(|e| format!("provenance envelope: {e}"))?;
    let Some((payload, key)) = envelope.verify_any(keys.iter()) else {
        return Err("provenance is not signed by an allowlisted build key".into());
    };
    let statement: crate::attest::Statement =
        serde_json::from_slice(&payload).map_err(|e| format!("provenance statement: {e}"))?;
    if statement.predicate_type != crate::attest::PREDICATE_TYPE {
        return Err(format!(
            "provenance predicate is {}, not {}",
            statement.predicate_type,
            crate::attest::PREDICATE_TYPE
        ));
    }
    if !statement.subject.iter().any(|s| s.digest.sha256 == sha256) {
        return Err("provenance subject digest does not match the package".into());
    }
    if require_rekor {
        let entry = crate::rekor::read(&crate::rekor::sidecar_path(package))
            .map_err(|e| format!("{e:#}"))?
            .ok_or_else(|| "no transparency log entry beside the package".to_string())?;
        crate::rekor::check(&entry, &envelope)
            .map_err(|e| format!("transparency log entry: {e:#}"))?;
        crate::rekor::verify_inclusion(&entry, log_key)
            .map_err(|e| format!("transparency log entry: {e:#}"))?;
    }
    if let Some(index) = index {
        let file = package
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default();
        match index.packages.get(file) {
            Some(entry) if entry.sha256 == sha256 => {}
            Some(_) => return Err("index lists the file with a different digest".into()),
            None => return Err("not listed in the index".into()),
        }
    }
    Ok(packslip::minisign::key_id_hex(&key.key_id))
}

fn gpg_sign(gpg: &str, key: &str, package: &Path) -> Result<()> {
    let sig = sig_path(package);
    let temp = sig.with_extension("sig.tmp");
    let _ = std::fs::remove_file(&temp);
    let result = (|| {
        let status = Command::new(gpg)
            .args([
                "--batch",
                "--yes",
                "--detach-sign",
                "--local-user",
                key,
                "--output",
            ])
            .arg(&temp)
            .arg(package)
            .status()
            .wrap_err_with(|| format!("running {gpg}"))?;
        if !status.success() {
            bail!("exited with status {}", status.code().unwrap_or(-1));
        }
        if !temp.is_file() {
            bail!("{} was not written", temp.display());
        }
        std::fs::rename(&temp, &sig).wrap_err_with(|| format!("publishing {}", sig.display()))?;
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(temp);
    }
    result
}
