//! `omapac-repo attest`: a build provenance statement per package, in a
//! DSSE envelope signed with the build host's key. See
//! `docs/spec/provenance.md`.

use std::path::{Path, PathBuf};

use eyre::{Context as _, Result, bail};
use packslip::dsse::{Envelope, IN_TOTO_PAYLOAD_TYPE};
use packslip::minisign::SecretKey;
use serde::{Deserialize, Serialize};
use usage_rs::RunWith;

pub const PREDICATE_TYPE: &str = "https://slsa.dev/provenance/v1";
pub const BUILD_TYPE: &str = "https://omapac.dev/build/makepkg/v1";
/// The sidecar suffix for a provenance envelope.
pub const SIDECAR: &str = ".provenance.json";

/// A SLSA v1 provenance statement, the parts this build fills in.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Statement {
    #[serde(rename = "_type")]
    pub kind: String,
    pub subject: Vec<Subject>,
    #[serde(rename = "predicateType")]
    pub predicate_type: String,
    pub predicate: Predicate,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Subject {
    pub name: String,
    pub digest: Digest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Digest {
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Predicate {
    #[serde(rename = "buildDefinition")]
    pub build_definition: BuildDefinition,
    #[serde(rename = "runDetails")]
    pub run_details: RunDetails,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BuildDefinition {
    #[serde(rename = "buildType")]
    pub build_type: String,
    #[serde(rename = "externalParameters")]
    pub external_parameters: ExternalParameters,
    #[serde(rename = "resolvedDependencies")]
    pub resolved_dependencies: Vec<ResolvedDependency>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExternalParameters {
    pub pkgbase: String,
    /// The PKGBUILD repository and commit that were built.
    pub source: String,
    pub commit: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolvedDependency {
    pub uri: String,
    pub digest: Digest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunDetails {
    pub builder: Builder,
    pub metadata: Metadata,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Builder {
    /// `omapac-repo attest` plus the build key id.
    pub id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Metadata {
    #[serde(rename = "invocationId")]
    pub invocation_id: String,
    #[serde(rename = "finishedOn")]
    pub finished_on: String,
}

/// Write a build provenance envelope beside each package
///
/// Every package file gets `<file>.provenance.json`: an in-toto statement
/// with the SLSA v1 provenance predicate naming the pkgbase, the PKGBUILD
/// source and commit, and every source artifact with its digest, signed
/// with the build key in a DSSE envelope. The index marks a package as
/// having build provenance when the envelope verifies with an accepted
/// build key.
#[derive(Debug, usage_rs::Args)]
pub struct Attest {
    /// Package files to attest
    #[usage(required = true)]
    packages: Vec<PathBuf>,
    /// The build key (secret seed from `packslip keygen`)
    #[usage(short = 'k', long, value_hint = usage_rs::ValueHint::FilePath)]
    key: PathBuf,
    /// The pkgbase that was built
    #[usage(long)]
    pkgbase: String,
    /// The PKGBUILD repository URL
    #[usage(long)]
    source: String,
    /// The PKGBUILD commit that was built
    #[usage(long)]
    commit: String,
    /// A source artifact as uri=sha256, repeatable
    #[usage(long)]
    dependency: Vec<String>,
    /// An identifier for this build run; defaults to a timestamp
    #[usage(long)]
    invocation: Option<String>,
    /// Upload each envelope to this transparency log and store the entry
    /// beside the package (`https://rekor.sigstore.dev` for the public log)
    #[usage(long)]
    rekor: Option<String>,
}

impl RunWith<()> for Attest {
    type Output = Result<()>;

    fn run_with(self, _: ()) -> Self::Output {
        let key_text = std::fs::read_to_string(&self.key)
            .wrap_err_with(|| format!("reading {}", self.key.display()))?;
        let key = SecretKey::parse(&key_text)?;
        let dependencies = self
            .dependency
            .iter()
            .map(|d| {
                let Some((uri, sha256)) = d.rsplit_once('=') else {
                    bail!("--dependency {d:?}: expected uri=sha256");
                };
                Ok(ResolvedDependency {
                    uri: uri.to_string(),
                    digest: Digest {
                        sha256: sha256.to_string(),
                    },
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let invocation = self
            .invocation
            .clone()
            .unwrap_or_else(|| jiff::Timestamp::now().to_string());
        for package in &self.packages {
            let statement = statement(
                package,
                &self.pkgbase,
                &self.source,
                &self.commit,
                &dependencies,
                &key,
                &invocation,
            )?;
            let payload = serde_json::to_vec(&statement)?;
            let envelope = Envelope::sign(IN_TOTO_PAYLOAD_TYPE, &payload, &key);
            let out = sidecar_path(package);
            std::fs::write(&out, serde_json::to_vec_pretty(&envelope)?)
                .wrap_err_with(|| format!("writing {}", out.display()))?;
            println!("wrote {}", out.display());
            if let Some(log) = &self.rekor {
                let entry = crate::rekor::upload(log, &envelope, &key.public_key())?;
                let path = crate::rekor::sidecar_path(package);
                std::fs::write(&path, serde_json::to_vec_pretty(&entry)?)
                    .wrap_err_with(|| format!("writing {}", path.display()))?;
                println!(
                    "logged {} at {} index {}",
                    path.display(),
                    entry.log_url,
                    entry.log_index
                );
            }
        }
        Ok(())
    }
}

/// `<package>.provenance.json`.
pub fn sidecar_path(package: &Path) -> PathBuf {
    let mut name = package.as_os_str().to_owned();
    name.push(SIDECAR);
    PathBuf::from(name)
}

/// Build the statement for one package file.
pub fn statement(
    package: &Path,
    pkgbase: &str,
    source: &str,
    commit: &str,
    dependencies: &[ResolvedDependency],
    key: &SecretKey,
    invocation: &str,
) -> Result<Statement> {
    let (sha256, _) = packslip::digest_file(package)
        .wrap_err_with(|| format!("hashing {}", package.display()))?;
    let name = package
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or_default()
        .to_string();
    Ok(Statement {
        kind: "https://in-toto.io/Statement/v1".into(),
        subject: vec![Subject {
            name,
            digest: Digest { sha256 },
        }],
        predicate_type: PREDICATE_TYPE.into(),
        predicate: Predicate {
            build_definition: BuildDefinition {
                build_type: BUILD_TYPE.into(),
                external_parameters: ExternalParameters {
                    pkgbase: pkgbase.into(),
                    source: source.into(),
                    commit: commit.into(),
                },
                resolved_dependencies: dependencies.to_vec(),
            },
            run_details: RunDetails {
                builder: Builder {
                    id: format!(
                        "omapac-repo attest {}",
                        packslip::minisign::key_id_hex(&key.public_key().key_id)
                    ),
                },
                metadata: Metadata {
                    invocation_id: invocation.into(),
                    finished_on: jiff::Timestamp::now().to_string(),
                },
            },
        },
    })
}

/// Read and verify a provenance envelope with any of `keys`, returning
/// the statement when its subject digest matches `sha256`.
pub fn verify_sidecar(
    path: &Path,
    sha256: &str,
    keys: &[packslip::minisign::PublicKey],
) -> Result<Option<Statement>> {
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(err).wrap_err_with(|| format!("reading {}", path.display())),
    };
    let envelope: Envelope =
        serde_json::from_str(&text).wrap_err_with(|| format!("parsing {}", path.display()))?;
    let Some((payload, _)) = envelope.verify_any(keys.iter()) else {
        bail!("{}: no accepted build key signed it", path.display());
    };
    let statement: Statement = serde_json::from_slice(&payload)
        .wrap_err_with(|| format!("parsing the statement in {}", path.display()))?;
    if statement.predicate_type != PREDICATE_TYPE {
        bail!(
            "{}: predicate type {} is not {PREDICATE_TYPE}",
            path.display(),
            statement.predicate_type
        );
    }
    if !statement.subject.iter().any(|s| s.digest.sha256 == sha256) {
        bail!(
            "{}: subject digest does not match the package",
            path.display()
        );
    }
    Ok(Some(statement))
}
