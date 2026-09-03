//! Verifying a packslip: signature against a pinned key, document
//! structure, and the digests of any artifacts at hand.

use std::path::Path;

use crate::minisign::{PublicKey, Sig};
use crate::model::{InvalidDocument, Level, Scheme, Statement};

/// What a successful verification established.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Verified {
    pub project: String,
    pub version: String,
    pub published_at: String,
    /// The key id that signed, as minisign prints it.
    pub key_id: String,
    pub level: Level,
    /// Artifacts whose digests were checked against files.
    pub checked_artifacts: Vec<String>,
    pub artifact_count: usize,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("document is not valid JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("document is invalid: {0}")]
    Invalid(#[from] InvalidDocument),
    #[error(
        "document declares identity scheme {0:?}, but only minisign is verifiable in this build"
    )]
    UnsupportedScheme(Scheme),
    #[error("document declares key id {declared}, the signature is by {actual}")]
    DeclaredKeyMismatch { declared: String, actual: String },
    #[error("signature: {0}")]
    Signature(#[from] crate::minisign::Error),
    #[error("artifact {name}: {why}")]
    Artifact { name: String, why: String },
}

/// Verify document bytes with a detached minisign signature against the
/// pinned public key, then check any local artifacts by file name.
pub fn verify(
    document: &[u8],
    signature: &str,
    pubkey: &PublicKey,
    artifacts: &[&Path],
) -> Result<Verified, Error> {
    let statement: Statement = serde_json::from_slice(document)?;
    statement.validate()?;
    if statement.predicate.identity.scheme != Scheme::Minisign {
        return Err(Error::UnsupportedScheme(
            statement.predicate.identity.scheme,
        ));
    }
    let sig = Sig::parse(signature)?;
    pubkey.verify(document, &sig)?;
    let actual = crate::minisign::key_id_hex(&pubkey.key_id);
    if !statement
        .predicate
        .identity
        .key_id
        .eq_ignore_ascii_case(&actual)
    {
        return Err(Error::DeclaredKeyMismatch {
            declared: statement.predicate.identity.key_id.clone(),
            actual,
        });
    }
    let mut checked = Vec::new();
    for path in artifacts {
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default()
            .to_string();
        let Some(expected) = statement.digest_of(&name) else {
            return Err(Error::Artifact {
                name,
                why: "not listed in the document".into(),
            });
        };
        let (actual, size) = crate::digest_file(path).map_err(|e| Error::Artifact {
            name: name.clone(),
            why: e.to_string(),
        })?;
        if actual != expected {
            return Err(Error::Artifact {
                name,
                why: format!("sha256 is {actual}, document says {expected}"),
            });
        }
        let declared_size = statement
            .predicate
            .artifacts
            .iter()
            .find(|a| a.name == name)
            .map(|a| a.size);
        if let Some(declared) = declared_size
            && declared != size
        {
            return Err(Error::Artifact {
                name,
                why: format!("size is {size}, document says {declared}"),
            });
        }
        checked.push(name);
    }
    Ok(Verified {
        project: statement.predicate.project.clone(),
        version: statement.predicate.version.clone(),
        published_at: statement.predicate.published_at.clone(),
        key_id: actual,
        level: statement.declared_level(),
        checked_artifacts: checked,
        artifact_count: statement.predicate.artifacts.len(),
    })
}
