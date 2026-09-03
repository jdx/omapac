//! Creating a packslip from release artifacts: digests, sizes, platform
//! inference from file names, and a minisign signature.

use std::path::Path;

use crate::minisign::{SecretKey, key_id_hex};
use crate::model::{
    Artifact, Digest, Identity, PREDICATE_TYPE, Predicate, STATEMENT_TYPE, Scheme, Source,
    Statement, Subject,
};

/// What `create` needs.
pub struct Request<'a> {
    pub project: &'a str,
    pub version: &'a str,
    pub published_at: Option<&'a str>,
    pub source: Option<Source>,
    pub artifacts: Vec<ArtifactInput<'a>>,
    /// Prepended to artifact names for their download URL, when given.
    pub url_base: Option<&'a str>,
    pub sbom: Option<&'a str>,
    pub supersedes: Option<&'a str>,
    pub key: &'a SecretKey,
}

/// One artifact file, with optional overrides for what the name implies.
pub struct ArtifactInput<'a> {
    pub path: &'a Path,
    pub os: Option<&'a str>,
    pub arch: Option<&'a str>,
    pub libc: Option<&'a str>,
    pub provenance: Vec<String>,
}

/// The document bytes and the signature file text.
pub struct Created {
    pub document: Vec<u8>,
    pub signature: String,
    pub statement: Statement,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("{0}")]
    Invalid(#[from] crate::model::InvalidDocument),
}

/// The `(os, arch, libc, format)` a file name implies.
pub type Platform = (
    Option<&'static str>,
    Option<&'static str>,
    Option<&'static str>,
    Option<&'static str>,
);

/// Infer `(os, arch, libc, format)` from a release file name.
pub fn infer_platform(name: &str) -> Platform {
    let lower = name.to_ascii_lowercase();
    let os = if lower.contains("linux") {
        Some("linux")
    } else if lower.contains("darwin") || lower.contains("macos") || lower.contains("apple") {
        Some("darwin")
    } else if lower.contains("windows") || lower.contains("win64") || lower.ends_with(".exe") {
        Some("windows")
    } else if lower.contains("freebsd") {
        Some("freebsd")
    } else {
        None
    };
    let arch = if lower.contains("x86_64")
        || lower.contains("x86-64")
        || lower.contains("x64")
        || lower.contains("amd64")
    {
        Some("x86_64")
    } else if lower.contains("aarch64") || lower.contains("arm64") {
        Some("aarch64")
    } else if lower.contains("armv7") || lower.contains("armhf") {
        Some("armv7")
    } else if lower.contains("riscv64") {
        Some("riscv64")
    } else if lower.contains("i686") || lower.contains("x86") {
        Some("i686")
    } else {
        None
    };
    let libc = if lower.contains("musl") {
        Some("musl")
    } else if os == Some("linux") {
        Some("gnu")
    } else {
        None
    };
    let format = [
        "tar.xz", "tar.gz", "tar.zst", "tar.bz2", "tgz", "zip", "deb", "rpm", "dmg", "pkg", "msi",
        "exe", "AppImage",
    ]
    .into_iter()
    .find(|ext| lower.ends_with(&format!(".{}", ext.to_ascii_lowercase())));
    (os, arch, libc, format)
}

/// Build, validate, and sign.
pub fn create(request: &Request<'_>) -> Result<Created, Error> {
    let mut subject = Vec::new();
    let mut artifacts = Vec::new();
    for input in &request.artifacts {
        let name = input
            .path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default()
            .to_string();
        let (sha256, size) = crate::digest_file(input.path).map_err(|source| Error::Io {
            path: input.path.display().to_string(),
            source,
        })?;
        let (os, arch, libc, format) = infer_platform(&name);
        subject.push(Subject {
            name: name.clone(),
            digest: Digest { sha256 },
        });
        let url = request
            .url_base
            .map(|base| format!("{}/{name}", base.trim_end_matches('/')));
        artifacts.push(Artifact {
            url,
            name,
            os: input.os.or(os).map(str::to_string),
            arch: input.arch.or(arch).map(str::to_string),
            libc: input.libc.or(libc).map(str::to_string),
            size,
            format: format.map(str::to_string),
            provenance: input.provenance.clone(),
        });
    }
    let published_at = request
        .published_at
        .map(str::to_string)
        .unwrap_or_else(|| jiff::Timestamp::now().to_string());
    let statement = Statement {
        kind: STATEMENT_TYPE.into(),
        subject,
        predicate_type: PREDICATE_TYPE.into(),
        predicate: Predicate {
            project: request.project.into(),
            version: request.version.into(),
            published_at,
            source: request.source.clone(),
            artifacts,
            identity: Identity {
                scheme: Scheme::Minisign,
                key_id: key_id_hex(&request.key.public_key().key_id),
            },
            sbom: request.sbom.map(str::to_string),
            supersedes: request.supersedes.map(str::to_string),
        },
    };
    statement.validate()?;
    let document = statement.canonical_bytes();
    let trusted = format!(
        "packslip {} {} published_at:{}",
        statement.predicate.project, statement.predicate.version, statement.predicate.published_at
    );
    let signature = request.key.sign(&document, &trusted).to_file();
    Ok(Created {
        document,
        signature,
        statement,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn infers_platforms() {
        assert_eq!(
            infer_platform("mise-v2026.9.1-linux-x64.tar.xz"),
            (Some("linux"), Some("x86_64"), Some("gnu"), Some("tar.xz"))
        );
        assert_eq!(
            infer_platform("mise-v2026.9.1-linux-arm64-musl.tar.gz"),
            (Some("linux"), Some("aarch64"), Some("musl"), Some("tar.gz"))
        );
        assert_eq!(
            infer_platform("tool-macos-aarch64.zip"),
            (Some("darwin"), Some("aarch64"), None, Some("zip"))
        );
        assert_eq!(
            infer_platform("tool-windows-x64.exe"),
            (Some("windows"), Some("x86_64"), None, Some("exe"))
        );
        assert_eq!(infer_platform("SHASUMS256.txt"), (None, None, None, None));
        assert_eq!(
            infer_platform("tool-linux-x86-64.tar.gz"),
            (Some("linux"), Some("x86_64"), Some("gnu"), Some("tar.gz"))
        );
    }

    #[test]
    fn create_then_verify_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("tool-v1.0.0-linux-x64.tar.xz");
        let b = dir.path().join("tool-v1.0.0-darwin-arm64.tar.xz");
        std::fs::write(&a, b"linux bytes").unwrap();
        std::fs::write(&b, b"darwin bytes").unwrap();
        let key = SecretKey::from_seed([1u8; 32]);
        let created = create(&Request {
            project: "pkg:github/example/tool",
            version: "1.0.0",
            published_at: Some("2026-09-01T00:00:00Z"),
            source: Some(Source {
                repo: "https://github.com/example/tool".into(),
                commit: None,
                tag: Some("v1.0.0".into()),
            }),
            artifacts: vec![
                ArtifactInput {
                    path: &a,
                    os: None,
                    arch: None,
                    libc: None,
                    provenance: vec!["https://example.com/a.sigstore.json".into()],
                },
                ArtifactInput {
                    path: &b,
                    os: None,
                    arch: None,
                    libc: None,
                    provenance: vec![],
                },
            ],
            url_base: Some("https://github.com/example/tool/releases/download/v1.0.0/"),
            sbom: None,
            supersedes: Some("0.9.0"),
            key: &key,
        })
        .unwrap();
        assert_eq!(
            created.statement.predicate.artifacts[0].url.as_deref(),
            Some(
                "https://github.com/example/tool/releases/download/v1.0.0/tool-v1.0.0-linux-x64.tar.xz"
            )
        );
        assert_eq!(created.statement.predicate.artifacts[0].size, 11);
        assert_eq!(
            created.statement.declared_level(),
            crate::Level::L2,
            "one artifact lacks provenance"
        );

        let verified = crate::verify(
            &created.document,
            &created.signature,
            &key.public_key(),
            &[&a, &b],
        )
        .unwrap();
        assert_eq!(verified.version, "1.0.0");
        assert_eq!(
            verified.checked_artifacts,
            [
                "tool-v1.0.0-linux-x64.tar.xz",
                "tool-v1.0.0-darwin-arm64.tar.xz"
            ]
        );
        assert_eq!(verified.level, crate::Level::L2);

        // Tampering with the document, the artifact, or the key fails.
        let mut tampered = created.document.clone();
        let last = tampered.len() - 2;
        tampered[last] = b' ';
        assert!(crate::verify(&tampered, &created.signature, &key.public_key(), &[]).is_err());
        std::fs::write(&a, b"other bytes").unwrap();
        let err = crate::verify(
            &created.document,
            &created.signature,
            &key.public_key(),
            &[&a],
        )
        .unwrap_err();
        assert!(err.to_string().contains("sha256 is"), "{err}");
        let other = SecretKey::from_seed([2u8; 32]).public_key();
        assert!(crate::verify(&created.document, &created.signature, &other, &[]).is_err());
        let unknown = dir.path().join("unknown.tar.gz");
        std::fs::write(&unknown, b"").unwrap();
        let err = crate::verify(
            &created.document,
            &created.signature,
            &key.public_key(),
            &[&unknown],
        )
        .unwrap_err();
        assert!(err.to_string().contains("not listed"), "{err}");
    }
}
