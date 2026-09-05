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
    pub sha256: Option<String>,
    pub link: Option<PathBuf>,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct Receipt {
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
                    sha256: None,
                    link: Some(std::fs::read_link(path)?),
                },
            );
        } else if meta.is_file() {
            out.insert(
                path.strip_prefix(root)?.into(),
                Input {
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
    let receipt = Receipt {
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
