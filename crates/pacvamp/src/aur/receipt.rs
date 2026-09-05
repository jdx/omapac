//! Local build records. These are not signed publisher attestations.
use super::{build::BuildOpts, review::Reviewed};
use eyre::{Result, bail};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    io::Write as _,
    path::{Path, PathBuf},
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Reference {
    pub path: PathBuf,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Input {
    #[serde(default)]
    pub mode: Option<u32>,
    pub sha256: Option<String>,
    pub link: Option<PathBuf>,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct Receipt {
    #[serde(default)]
    pub source_date_epoch: Option<i64>,
    #[serde(default)]
    pub image_sha256: Option<String>,
    pub schema: u32,
    pub claim: String,
    pub pkgbase: String,
    pub commit: String,
    pub at: i64,
    pub jail: bool,
    #[serde(default)]
    pub chroot: Option<PathBuf>,
    pub build_network: bool,
    pub limits: crate::build_process::Limits,
    pub makepkg_sha256: String,
    pub dependencies: BTreeMap<String, String>,
    pub sources: BTreeMap<PathBuf, Input>,
    pub vcs_refs: BTreeMap<PathBuf, String>,
    pub outputs: BTreeMap<String, String>,
}

pub fn inputs(root: &Path) -> Result<BTreeMap<PathBuf, Input>> {
    fn visit(root: &Path, path: &Path, out: &mut BTreeMap<PathBuf, Input>) -> Result<()> {
        let meta = std::fs::symlink_metadata(path)?;
        if meta.is_symlink() {
            out.insert(
                path.strip_prefix(root)?.into(),
                Input {
                    mode: None,
                    sha256: None,
                    link: Some(std::fs::read_link(path)?),
                },
            );
        } else if meta.is_file() {
            out.insert(
                path.strip_prefix(root)?.into(),
                Input {
                    mode: Some({
                        use std::os::unix::fs::PermissionsExt as _;
                        meta.permissions().mode() & 0o7777
                    }),
                    sha256: Some(packslip::digest_file(path)?.0),
                    link: None,
                },
            );
        } else if meta.is_dir() {
            for entry in std::fs::read_dir(path)? {
                visit(root, &entry?.path(), out)?;
            }
        } else {
            bail!("unsupported source input {}", path.display());
        }
        Ok(())
    }
    let mut out = BTreeMap::new();
    visit(root, root, &mut out)?;
    Ok(out)
}

pub fn vcs_refs(root: &Path) -> Result<BTreeMap<PathBuf, String>> {
    let mut refs = BTreeMap::new();
    for entry in std::fs::read_dir(root)? {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let path = entry.path();
        let gitdir = if path.join(".git").is_dir() {
            path.join(".git")
        } else {
            path.clone()
        };
        if !gitdir.join("HEAD").is_file() || !gitdir.join("objects").is_dir() {
            continue;
        }
        let output = std::process::Command::new("git")
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .arg("--git-dir")
            .arg(&gitdir)
            .args(["show-ref", "--head"])
            .output()?;
        if !output.status.success() {
            bail!("cannot record source Git refs in {}", path.display());
        }
        refs.insert(
            path.strip_prefix(root)?.into(),
            String::from_utf8(output.stdout)?,
        );
    }
    Ok(refs)
}

pub fn write(
    reviewed: &Reviewed,
    opts: &BuildOpts,
    sources: BTreeMap<PathBuf, Input>,
    refs: BTreeMap<PathBuf, String>,
    files: &[PathBuf],
) -> Result<()> {
    let mut outputs = BTreeMap::new();
    for file in files {
        let name = file
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| eyre::eyre!("invalid output filename"))?;
        outputs.insert(name.into(), packslip::digest_file(file)?.0);
    }
    if let Some(root) = &opts.chroot
        && Some(image_digest(root)?) != opts.image_sha256
    {
        bail!("build image changed while building; refusing receipt");
    }
    let receipt = Receipt {
        source_date_epoch: opts.source_date_epoch,
        image_sha256: opts.image_sha256.clone(),
        schema: 1,
        claim: "local observation; not a signed attestation".into(),
        pkgbase: reviewed.pkgbase.clone(),
        commit: reviewed.target.clone(),
        at: crate::ledger::now(),
        jail: opts.jail,
        chroot: opts.chroot.clone(),
        build_network: opts.network,
        limits: opts.limits.clone(),
        makepkg_sha256: packslip::digest_file(
            &opts
                .chroot
                .as_ref()
                .map(|root| root.join("usr/bin/makepkg"))
                .unwrap_or_else(|| opts.makepkg.clone()),
        )?
        .0,
        dependencies: opts.dependencies.clone(),
        sources,
        vcs_refs: refs,
        outputs,
    };
    let parent = opts
        .pkgdest
        .parent()
        .ok_or_else(|| eyre::eyre!("missing run directory"))?;
    let mut tmp = tempfile::NamedTempFile::new_in(parent)?;
    serde_json::to_writer_pretty(&mut tmp, &receipt)?;
    tmp.write_all(b"\n")?;
    tmp.as_file().sync_all()?;
    tmp.persist(parent.join("receipt.json"))?;
    std::fs::File::open(parent)?.sync_all()?;
    Ok(())
}

pub fn for_artifact(file: &Path) -> Result<(Receipt, Reference)> {
    let path = file
        .parent()
        .and_then(Path::parent)
        .ok_or_else(|| eyre::eyre!("artifact has no run directory"))?
        .join("receipt.json");
    let receipt: Receipt = serde_json::from_slice(&std::fs::read(&path)?)?;
    if receipt.schema != 1 {
        bail!("unsupported build receipt schema {}", receipt.schema);
    }
    let name = file
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| eyre::eyre!("invalid artifact name"))?;
    let digest = packslip::digest_file(file)?.0;
    if receipt.outputs.get(name) != Some(&digest) {
        bail!("artifact does not match its build receipt");
    }
    Ok((
        receipt,
        Reference {
            sha256: packslip::digest_file(&path)?.0,
            path,
        },
    ))
}

/// Hash the image visible to the builder; private entries retain metadata only.
pub fn image_digest(root: &Path) -> Result<String> {
    use sha2::{Digest as _, Sha256};
    use std::{io::Read as _, os::unix::fs::MetadataExt as _};
    fn visit(
        root: &Path,
        path: &Path,
        out: &mut BTreeMap<PathBuf, serde_json::Value>,
    ) -> Result<()> {
        let meta = std::fs::symlink_metadata(path)?;
        let mut value = serde_json::json!({"mode":meta.mode(),"uid":meta.uid(),"gid":meta.gid(),"mtime":meta.mtime(),"mtime_nsec":meta.mtime_nsec()});
        if meta.is_symlink() {
            value["link"] = serde_json::to_value(std::fs::read_link(path)?)?;
        } else if meta.is_file() {
            match std::fs::File::open(path) {
                Ok(mut file) => {
                    let mut hash = Sha256::new();
                    let mut buffer = [0; 65536];
                    loop {
                        let n = file.read(&mut buffer)?;
                        if n == 0 {
                            break;
                        }
                        hash.update(&buffer[..n]);
                    }
                    value["sha256"] = format!("{:x}", hash.finalize()).into();
                }
                Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => {
                    value["unreadable"] = true.into();
                    value["size"] = meta.len().into();
                }
                Err(err) => return Err(err.into()),
            }
        } else if meta.is_dir() {
            match std::fs::read_dir(path) {
                Ok(entries) => {
                    for entry in entries {
                        visit(root, &entry?.path(), out)?;
                    }
                }
                Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => {
                    value["unreadable"] = true.into()
                }
                Err(err) => return Err(err.into()),
            }
        } else {
            // Sockets and device nodes (for example stale GnuPG agent sockets)
            // have no stable file contents to hash. Never open them.
            value["special"] = true.into();
            value["device"] = meta.rdev().into();
        }
        out.insert(path.strip_prefix(root)?.into(), value);
        Ok(())
    }
    let mut inventory = BTreeMap::new();
    for entry in std::fs::read_dir(root)? {
        let entry = entry?;
        if [
            "dev",
            "proc",
            "sys",
            "run",
            "tmp",
            "build",
            "pacvamp-helper",
            "pacvamp-cgroup",
        ]
        .iter()
        .any(|reserved| entry.file_name() == *reserved)
        {
            continue;
        }
        visit(root, &entry.path(), &mut inventory)?;
    }
    Ok(format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(&inventory)?)
    ))
}

#[derive(Debug, Serialize)]
pub struct Difference {
    pub component: String,
    pub before: serde_json::Value,
    pub after: serde_json::Value,
}
#[derive(Debug, Serialize)]
pub struct Comparison {
    pub identical: bool,
    pub differences: Vec<Difference>,
    pub claim: &'static str,
}
pub fn compare(before: &Receipt, after: &Receipt) -> Result<Comparison> {
    let a = serde_json::to_value(before)?;
    let b = serde_json::to_value(after)?;
    let mut differences = Vec::new();
    for key in [
        "pkgbase",
        "commit",
        "source_date_epoch",
        "image_sha256",
        "jail",
        "build_network",
        "limits",
        "makepkg_sha256",
        "dependencies",
        "sources",
        "vcs_refs",
        "outputs",
    ] {
        if a[key] != b[key] {
            differences.push(Difference {
                component: key.into(),
                before: a[key].clone(),
                after: b[key].clone(),
            });
        }
    }
    Ok(Comparison {
        identical: differences.is_empty(),
        differences,
        claim: "local comparison of recorded inputs and outputs; not an independent reproducibility attestation",
    })
}
