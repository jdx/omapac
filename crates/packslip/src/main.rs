#![forbid(unsafe_code)]

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use eyre::{Context as _, Result, bail};
use omapac_cli_support::version::{BinInfo, Version};
use packslip::create::{ArtifactInput, Request};
use packslip::minisign::{PublicKey, SecretKey};
use packslip::model::Source;
use usage_rs::RunWith;

const BIN: BinInfo = BinInfo {
    name: "packslip",
    version: env!("CARGO_PKG_VERSION"),
};

/// Create and verify packslip release manifests
///
/// A packslip is one signed document per release that says what the
/// artifacts are and how to verify them, so any consumer can pin one
/// identity and check downloads without per-vendor logic.
#[derive(usage_rs::Cli)]
#[usage(
    bin = "packslip",
    version,
    author = "Jeff Dickey <@jdx>",
    arg_required_else_help
)]
struct Cli {
    #[usage(subcommand)]
    command: Option<Commands>,
}

#[derive(usage_rs::Subcommands)]
#[usage(run_with)]
enum Commands {
    Create(Box<Create>),
    Keygen(Keygen),
    Schema(Schema),
    Verify(Verify),
    Version(Version),
}

/// Generate a signing key pair
///
/// Writes the secret seed to the given path (mode 0600) and a
/// minisign-format public key beside it with a .pub extension.
#[derive(Debug, usage_rs::Args)]
struct Keygen {
    /// Where to write the secret key
    #[usage(short = 'o', long, default = "packslip.key")]
    out: PathBuf,
}

impl RunWith<BinInfo> for Keygen {
    type Output = Result<()>;

    fn run_with(self, _: BinInfo) -> Self::Output {
        use std::io::Write as _;
        use std::os::unix::fs::OpenOptionsExt as _;
        let pubkey = self.out.with_extension("pub");
        if self.out == pubkey {
            bail!(
                "secret and public key paths both resolve to {}",
                self.out.display()
            );
        }
        if self.out.exists() || pubkey.exists() {
            bail!(
                "{} or {} exists; not overwriting a key",
                self.out.display(),
                pubkey.display()
            );
        }
        let key = SecretKey::generate();
        let mut secret_created = false;
        let mut public_created = false;
        let write_result: Result<()> = (|| {
            let mut secret = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&self.out)
                .wrap_err_with(|| format!("creating {}", self.out.display()))?;
            secret_created = true;
            secret
                .write_all(key.to_file().as_bytes())
                .wrap_err_with(|| format!("writing {}", self.out.display()))?;
            let mut public = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&pubkey)
                .wrap_err_with(|| format!("creating {}", pubkey.display()))?;
            public_created = true;
            public
                .write_all(key.public_key().to_file().as_bytes())
                .wrap_err_with(|| format!("writing {}", pubkey.display()))?;
            Ok(())
        })();
        if let Err(err) = write_result {
            if public_created {
                let _ = std::fs::remove_file(&pubkey);
            }
            if secret_created {
                let _ = std::fs::remove_file(&self.out);
            }
            return Err(err);
        }
        println!(
            "wrote {} and {} (key id {})",
            self.out.display(),
            pubkey.display(),
            packslip::minisign::key_id_hex(&key.public_key().key_id)
        );
        Ok(())
    }
}

/// Print the JSON schema of the document
#[derive(Debug, usage_rs::Args)]
struct Schema {}

impl RunWith<BinInfo> for Schema {
    type Output = Result<()>;

    fn run_with(self, _: BinInfo) -> Self::Output {
        println!(
            "{}",
            serde_json::to_string_pretty(&packslip::Statement::schema())?
        );
        Ok(())
    }
}

/// Create and sign a packslip for a release
///
/// Digests every artifact, infers os/arch/libc/format from file names
/// (override with name:os/arch), and writes packslip.json plus
/// packslip.json.minisig into --out.
#[derive(Debug, usage_rs::Args)]
struct Create {
    /// Package URL of the project, such as pkg:github/jdx/mise
    #[usage(long)]
    project: String,
    /// The release version
    #[usage(long)]
    version: String,
    /// Artifact files, optionally as path:os/arch[/libc]
    #[usage(required = true)]
    artifacts: Vec<String>,
    /// Secret key file from `packslip keygen`
    #[usage(short = 'k', long, value_hint = usage_rs::ValueHint::FilePath)]
    key: PathBuf,
    /// Directory to write into
    #[usage(short = 'o', long, default = ".")]
    out: PathBuf,
    /// Download URL prefix for the artifacts
    #[usage(long)]
    url_base: Option<String>,
    /// Source repository URL
    #[usage(long)]
    source_repo: Option<String>,
    /// Source commit
    #[usage(long)]
    commit: Option<String>,
    /// Source tag
    #[usage(long)]
    tag: Option<String>,
    /// RFC 3339 publish time; defaults to now
    #[usage(long)]
    published_at: Option<String>,
    /// SBOM URL
    #[usage(long)]
    sbom: Option<String>,
    /// The version this release replaces
    #[usage(long)]
    supersedes: Option<String>,
    /// Provenance URL for every artifact (repeatable, positional order)
    #[usage(long)]
    provenance: Vec<String>,
}

impl RunWith<BinInfo> for Create {
    type Output = Result<()>;

    fn run_with(self, _: BinInfo) -> Self::Output {
        if self.source_repo.is_none() && (self.commit.is_some() || self.tag.is_some()) {
            eyre::bail!("--commit and --tag require --source-repo");
        }
        let key_text = std::fs::read_to_string(&self.key)
            .wrap_err_with(|| format!("reading {}", self.key.display()))?;
        let key = SecretKey::parse(&key_text)?;
        let parsed: Vec<ArtifactSpec> = self.artifacts.iter().map(|s| parse_spec(s)).collect();
        let artifacts: Vec<ArtifactInput<'_>> = parsed
            .iter()
            .enumerate()
            .map(|(i, spec)| ArtifactInput {
                path: &spec.path,
                os: spec.os.as_deref(),
                arch: spec.arch.as_deref(),
                libc: spec.libc.as_deref(),
                provenance: self.provenance.get(i).cloned().into_iter().collect(),
            })
            .collect();
        let source = self.source_repo.as_ref().map(|repo| Source {
            repo: repo.clone(),
            commit: self.commit.clone(),
            tag: self.tag.clone(),
        });
        let created = packslip::create::create(&Request {
            project: &self.project,
            version: &self.version,
            published_at: self.published_at.as_deref(),
            source,
            artifacts,
            url_base: self.url_base.as_deref(),
            sbom: self.sbom.as_deref(),
            supersedes: self.supersedes.as_deref(),
            key: &key,
        })?;
        std::fs::create_dir_all(&self.out)
            .wrap_err_with(|| format!("creating {}", self.out.display()))?;
        let document = self.out.join("packslip.json");
        let signature = self.out.join("packslip.json.minisig");
        std::fs::write(&document, &created.document)?;
        std::fs::write(&signature, &created.signature)?;
        println!(
            "wrote {} and {} ({} artifact(s), level {})",
            document.display(),
            signature.display(),
            created.statement.predicate.artifacts.len(),
            created.statement.declared_level()
        );
        Ok(())
    }
}

/// An artifact argument: a path, optionally with `:os/arch[/libc]`.
struct ArtifactSpec {
    path: PathBuf,
    os: Option<String>,
    arch: Option<String>,
    libc: Option<String>,
}

/// Recognize only a well-formed `os/arch[/libc]` suffix. In particular,
/// colons inside timestamped directory names remain part of the path.
fn parse_spec(spec: &str) -> ArtifactSpec {
    match spec.rsplit_once(':') {
        Some((path, platform)) if valid_platform(platform) => {
            let mut parts = platform.split('/');
            ArtifactSpec {
                path: PathBuf::from(path),
                os: parts.next().map(str::to_string),
                arch: parts.next().map(str::to_string),
                libc: parts.next().map(str::to_string),
            }
        }
        _ => ArtifactSpec {
            path: PathBuf::from(spec),
            os: None,
            arch: None,
            libc: None,
        },
    }
}

fn valid_platform(platform: &str) -> bool {
    let parts: Vec<_> = platform.split('/').collect();
    (parts.len() == 2 || parts.len() == 3)
        && parts.iter().all(|part| {
            part.as_bytes().first().is_some_and(u8::is_ascii_alphabetic)
                && part
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
        })
}

/// Verify a packslip against a pinned public key
///
/// Checks the signature, the document, and the digest and size of every
/// artifact file given. Exits 1 on any failure.
#[derive(Debug, usage_rs::Args)]
struct Verify {
    /// The packslip.json to verify
    #[usage(value_hint = usage_rs::ValueHint::FilePath)]
    document: PathBuf,
    /// The minisign public key file, or its base64 line
    #[usage(short = 'p', long)]
    pubkey: String,
    /// The signature file; defaults to <document>.minisig
    #[usage(short = 's', long)]
    signature: Option<PathBuf>,
    /// Artifact files to check against the document
    #[usage(short = 'a', long)]
    artifact: Vec<PathBuf>,
    /// Print the result as JSON
    #[usage(short = 'J', long)]
    json: bool,
}

impl RunWith<BinInfo> for Verify {
    type Output = Result<()>;

    fn run_with(self, _: BinInfo) -> Self::Output {
        let pubkey_text = if Path::new(&self.pubkey).is_file() {
            std::fs::read_to_string(&self.pubkey)?
        } else {
            self.pubkey.clone()
        };
        let pubkey = PublicKey::parse(&pubkey_text)?;
        let document = std::fs::read(&self.document)
            .wrap_err_with(|| format!("reading {}", self.document.display()))?;
        let signature_path = self.signature.clone().unwrap_or_else(|| {
            let mut name = self.document.as_os_str().to_owned();
            name.push(".minisig");
            PathBuf::from(name)
        });
        let signature = std::fs::read_to_string(&signature_path)
            .wrap_err_with(|| format!("reading {}", signature_path.display()))?;
        let artifacts: Vec<&Path> = self.artifact.iter().map(PathBuf::as_path).collect();
        match packslip::verify(&document, &signature, &pubkey, &artifacts) {
            Ok(verified) => {
                if self.json {
                    println!("{}", serde_json::to_string_pretty(&verified)?);
                } else {
                    println!(
                        "ok: {} {} published {} signed by {} level {} ({} of {} artifact(s) checked)",
                        verified.project,
                        verified.version,
                        verified.published_at,
                        verified.key_id,
                        verified.level,
                        verified.checked_artifacts.len(),
                        verified.artifact_count
                    );
                }
                Ok(())
            }
            Err(err) => {
                eprintln!("verification failed: {err}");
                std::process::exit(1)
            }
        }
    }
}

fn main() -> Result<()> {
    color_eyre::install()?;
    let args: Vec<OsString> = std::env::args_os().collect();
    let argv = omapac_cli_support::argv(&args);
    let cli = omapac_cli_support::unwrap_or_exit(Cli::spec(), &argv, Cli::parse_from_argv(&argv));
    match cli.command {
        Some(command) => command.run_with(BIN),
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn artifact_platform_suffix_does_not_consume_timestamped_paths() {
        let timestamped = parse_spec("dist/2026-09-03T11:17:00Z/tool.tar.xz");
        assert_eq!(
            timestamped.path,
            PathBuf::from("dist/2026-09-03T11:17:00Z/tool.tar.xz")
        );
        assert!(timestamped.os.is_none());

        let overridden = parse_spec("tool.tar.xz:freebsd/riscv64/musl");
        assert_eq!(overridden.path, PathBuf::from("tool.tar.xz"));
        assert_eq!(overridden.os.as_deref(), Some("freebsd"));
        assert_eq!(overridden.arch.as_deref(), Some("riscv64"));
        assert_eq!(overridden.libc.as_deref(), Some("musl"));
    }
}
