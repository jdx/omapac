//! Explicit devtools provisioning and disposable dependency environments.
use crate::engine::sudo::{Context, Invocation};
use eyre::{Result, bail};
use std::path::{Path, PathBuf};

pub fn privileged(program: &str, args: Vec<String>) -> Result<()> {
    let invocation = Invocation::new(which::which(program)?, args)
        .elevated(&Context::detect(Default::default()))?;
    eprintln!("{}", invocation.display());
    use std::os::fd::AsFd as _;
    if !invocation
        .command()
        .stdout(std::process::Stdio::from(
            std::io::stderr().as_fd().try_clone_to_owned()?,
        ))
        .status()?
        .success()
    {
        bail!("{program} failed");
    }
    Ok(())
}
fn arg(path: &Path) -> Result<String> {
    path.to_str()
        .map(str::to_owned)
        .ok_or_else(|| eyre::eyre!("image paths must be UTF-8"))
}
pub fn new_root(path: &Path) -> Result<()> {
    match path.symlink_metadata() {
        Ok(_) => bail!("image destination already exists"),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => return Err(err.into()),
    }
    if !path.is_absolute() || path == Path::new("/") {
        bail!("image destination must be a new absolute path other than /");
    }
    if path
        .components()
        .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        bail!("image destination cannot contain ..");
    }
    Ok(())
}
pub fn initialize(destination: &Path, packages: &[String]) -> Result<()> {
    new_root(destination)?;
    validate_packages(packages)?;
    let mut args = vec![
        "-C".into(),
        "/etc/pacman.conf".into(),
        arg(destination)?,
        "base-devel".into(),
    ];
    args.extend_from_slice(packages);
    privileged("mkarchroot", args)?;
    super::chroot::host(destination)?;
    Ok(())
}
pub fn clone_image(root: &Path, destination: &Path) -> Result<()> {
    super::chroot::host(root)?;
    new_root(destination)?;
    privileged(
        "cp",
        vec![
            "-a".into(),
            "--reflink=auto".into(),
            "--".into(),
            arg(&root.canonicalize()?)?,
            arg(destination)?,
        ],
    )
}
pub fn validate_packages(packages: &[String]) -> Result<()> {
    for package in packages {
        if package.starts_with('-')
            || package.is_empty()
            || !package
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"@._+-/".contains(&c))
        {
            bail!("invalid repository package target {package:?}");
        }
    }
    Ok(())
}
pub fn update(root: &Path, packages: &[String], yes: bool) -> Result<()> {
    super::chroot::host(root)?;
    validate_packages(packages)?;
    let mut args = vec![
        arg(root)?,
        "pacman".into(),
        "-Syu".into(),
        "--needed".into(),
    ];
    if yes {
        args.push("--noconfirm".into());
    }
    args.push("--".into());
    args.extend_from_slice(packages);
    privileged("arch-nspawn", args)
}

pub struct Disposable {
    pub root: PathBuf,
    _directory: tempfile::TempDir,
}
impl Disposable {
    pub fn prepare(
        root: &Path,
        packages: &[String],
        artifacts: &[PathBuf],
        yes: bool,
    ) -> Result<Self> {
        validate_packages(packages)?;
        // Copy and verify artifacts before asking root to consume them.
        let directory = tempfile::Builder::new()
            .prefix("pacvamp-image-")
            .tempdir()?;
        let artifacts_dir = directory.path().join("artifacts");
        std::fs::create_dir(&artifacts_dir)?;
        let mut copies = Vec::new();
        for (i, artifact) in artifacts.iter().enumerate() {
            let (receipt, _) = super::receipt::for_artifact(artifact)?;
            let name = artifact
                .file_name()
                .and_then(|s| s.to_str())
                .ok_or_else(|| eyre::eyre!("invalid artifact name"))?;
            let copy = artifacts_dir.join(format!("dependency-{i}.pkg.tar.zst"));
            std::fs::copy(artifact, &copy)?;
            if receipt.outputs.get(name) != Some(&packslip::digest_file(&copy)?.0) {
                bail!("dependency artifact changed while copying");
            }
            copies.push(copy);
        }
        let image = Self {
            root: directory.path().join("root"),
            _directory: directory,
        };
        clone_image(root, &image.root)?;
        if !packages.is_empty() {
            update(&image.root, packages, yes)?;
        }
        if !copies.is_empty() {
            // arch-nspawn exposes the private artifact directory read-only.
            let mut args = vec![
                arg(&image.root)?,
                format!(
                    "--bind-ro={}:{}",
                    arg(&artifacts_dir)?,
                    "/pacvamp-dependencies"
                ),
                "pacman".into(),
                "-U".into(),
            ];
            if yes {
                args.push("--noconfirm".into());
            }
            args.push("--".into());
            for copy in copies {
                args.push(format!(
                    "/pacvamp-dependencies/{}",
                    copy.file_name().unwrap().to_string_lossy()
                ));
            }
            privileged("arch-nspawn", args)?;
        }
        super::chroot::host(&image.root)?;
        Ok(image)
    }
}
impl Drop for Disposable {
    fn drop(&mut self) {
        if self.root.exists()
            && let Err(err) = privileged(
                "rm",
                vec![
                    "-rf".into(),
                    "--".into(),
                    self.root.to_string_lossy().into_owned(),
                ],
            )
        {
            eprintln!(
                "could not remove disposable image {}: {err:#}",
                self.root.display()
            );
        }
    }
}
