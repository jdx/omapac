use std::fmt::Write as _;

use eyre::{Context as _, Result, bail};
use pacvamp_policy::Decision;
use usage_rs::RunWith;

use super::{App, print_json};
use crate::aur::review::{Request, Reviewed, review};
use crate::aur::rpc::Rpc as _;
use crate::lockfile::Lockfile;

/// Review, approve, and build AUR packages
#[derive(Debug, usage_rs::Args)]
pub struct Aur {
    #[usage(subcommand)]
    command: AurCommands,
}

#[derive(Debug, usage_rs::Subcommands)]
#[usage(run_with)]
enum AurCommands {
    Approve(Approve),
    Build(Build),
    Diff(Diff),
    Review(Review),
    Receipt(Receipt),
}

/// Build an approved AUR package without installing it
///
/// Sources are fetched with network, then makepkg runs in the jail with
/// writes limited to the build directory and no network unless the
/// manifest grants it. Prints the package files it built.
#[derive(Debug, usage_rs::Args)]
pub struct Build {
    /// The package name
    package: String,
    /// Build this commit instead of the approved one
    #[usage(long)]
    commit: Option<String>,
    /// Install missing repository dependencies without asking
    #[usage(short = 'y', long)]
    yes: bool,
    /// Clone the configured image and install dependencies there for this build
    #[usage(long)]
    prepare_image: bool,
    /// Reviewed local dependency artifacts to install into the disposable image
    #[usage(long)]
    dependency_artifact: Vec<std::path::PathBuf>,
    /// Print the files as JSON
    #[usage(short = 'J', long)]
    json: bool,
}

impl RunWith<&App> for Build {
    type Output = Result<()>;

    fn run_with(self, app: &App) -> Self::Output {
        let mut prepared =
            app.prepare_aur(&self.package, self.commit.as_deref(), true, self.yes)?;
        if !self.prepare_image && !self.dependency_artifact.is_empty() {
            bail!("--dependency-artifact requires --prepare-image");
        }
        let _image = if self.prepare_image {
            let root = crate::aur::chroot::root(&prepared.settings)
                .ok_or_else(|| eyre::eyre!("--prepare-image requires policy.aur.chroot = true"))?;
            let host = crate::aur::chroot::host(&root)?;
            let missing =
                crate::aur::build::missing_deps(&host, &prepared.reviewed, &prepared.arch)?;
            let packages = missing
                .repo
                .iter()
                .map(|p| {
                    p.repo
                        .as_ref()
                        .map_or_else(|| p.name.clone(), |r| format!("{r}/{}", p.name))
                })
                .collect::<Vec<_>>();
            let image = crate::aur::environment::Disposable::prepare(
                &root,
                &packages,
                &self.dependency_artifact,
                self.yes,
            )?;
            prepared.settings.aur_chroot_root = image.root.clone();
            Some(image)
        } else {
            None
        };
        let files = app.build_aur(&prepared, self.yes)?;
        if self.json {
            return print_json(&files);
        }
        for file in files {
            println!("{}", file.display());
        }
        Ok(())
    }
}

impl RunWith<&App> for Aur {
    type Output = Result<()>;

    fn run_with(self, app: &App) -> Self::Output {
        self.command.run_with(app)
    }
}

/// Review an AUR package at its current commit
///
/// Fetches the package's git history and metadata, evaluates the policy
/// findings against the last approved commit, and shows the PKGBUILD diff
/// (or the whole PKGBUILD on a first review). Nothing is built.
#[derive(Debug, usage_rs::Args)]
pub struct Review {
    /// The package name
    package: String,
    /// Review this commit instead of the current one
    #[usage(long)]
    commit: Option<String>,
    /// Do not print the PKGBUILD diff
    #[usage(long)]
    no_diff: bool,
    /// Evaluate as an unattended run would
    #[usage(long)]
    unattended: bool,
    /// Print as JSON
    #[usage(short = 'J', long)]
    json: bool,
    /// Show the review and diff in a scrollable pager
    #[usage(long)]
    pager: bool,
}

/// Approve an AUR package's commit for building
///
/// Records the reviewed commit and the evidence in pacvamp.lock next to
/// the user manifest. Interactively, the findings are shown and you
/// confirm; unattended, a denied review is refused unless --force.
#[derive(Debug, usage_rs::Args)]
pub struct Approve {
    /// The package name
    package: String,
    /// Approve this commit instead of the current one
    #[usage(long)]
    commit: Option<String>,
    /// Approve without asking, even over denials
    #[usage(long)]
    force: bool,
    /// Approve without asking when nothing denies
    #[usage(short = 'y', long)]
    yes: bool,
}

/// Show the PKGBUILD diff since the approved commit
#[derive(Debug, usage_rs::Args)]
pub struct Diff {
    /// The package name
    package: String,
    /// Diff to this commit instead of the current one
    #[usage(long)]
    commit: Option<String>,
}

/// A package that has been reviewed and is cleared for building.
pub struct Prepared {
    pub reviewed: Reviewed,
    pub settings: crate::manifest::Settings,
    pub arch: String,
    /// Whether the run may ask questions; dependencies inherit it.
    pub unattended: bool,
}

/// How deep an AUR dependency chain may go before it is refused.
const MAX_AUR_DEPTH: usize = 8;

#[derive(Clone)]
struct AncestorOutputs {
    pkgname: String,
    commit: String,
    packages: Vec<(String, String, Vec<alpm_db::dep::Dependency>)>,
}

impl AncestorOutputs {
    fn from_prepared(prepared: &Prepared) -> Self {
        let version = prepared.reviewed.srcinfo.version();
        let packages = prepared
            .reviewed
            .srcinfo
            .pkgnames()
            .into_iter()
            .map(|name| {
                let provides = prepared.reviewed.srcinfo.provides(name, &prepared.arch);
                (name.to_string(), version.clone(), provides)
            })
            .collect();
        Self {
            pkgname: prepared.reviewed.pkgname.clone(),
            commit: prepared.reviewed.target.clone(),
            packages,
        }
    }

    fn satisfies(&self, dep: &alpm_db::dep::Dependency) -> bool {
        self.packages
            .iter()
            .any(|(name, version, provides)| dep.satisfied_by(name, version, provides))
    }

    fn sibling_satisfies(&self, dep: &alpm_db::dep::Dependency) -> bool {
        self.packages.iter().any(|(name, version, provides)| {
            name != &self.pkgname && dep.satisfied_by(name, version, provides)
        })
    }
}

impl App {
    /// Review `name` and check it is approved at the target commit, or
    /// approve it interactively. `yes` means unattended: an unapproved or
    /// denied package is refused rather than asked about.
    pub fn prepare_aur(
        &self,
        name: &str,
        commit: Option<&str>,
        _interactive_hint: bool,
        yes: bool,
    ) -> Result<Prepared> {
        let interactive = !yes && crate::ui::interactive();
        let (reviewed, mut lock) = self.review_aur(name, commit, interactive)?;
        let manifest = self.manifest()?;
        let settings = manifest.settings.clone();
        let approved_here = lock
            .aur
            .get(&reviewed.pkgbase)
            .or_else(|| lock.aur.get(name))
            .is_some_and(|entry| entry.commit == reviewed.target);
        if !approved_here {
            if !interactive {
                bail!(
                    "{name} at {} is not approved; run `pacvamp aur review {name}` and `pacvamp aur approve {name}` first",
                    &reviewed.target[..12]
                );
            }
            print!("{}", render(&reviewed));
            let text = reviewed.review_text()?;
            if !text.is_empty() {
                println!();
                print!("{text}");
            }
            if reviewed.report.denied() {
                bail!(
                    "{} finding(s) deny this commit; review it and use `pacvamp aur approve --force {name}` to override explicitly",
                    reviewed.report.denials().count(),
                );
            }
            if !crate::ui::confirm(
                &format!("Approve and build {name} at {}?", &reviewed.target[..12]),
                false,
            )? {
                bail!("not approved");
            }
            lock.aur.remove(name);
            lock.aur
                .insert(reviewed.pkgbase.clone(), reviewed.lock_entry());
            lock.save(&self.lockfile_path())?;
        }
        if !reviewed.evidence.recipe.install_files.is_empty()
            && settings.aur_install_scripts == crate::manifest::settings::InstallScripts::Deny
        {
            bail!(
                "{name} carries install scriptlet(s) {} and policy says deny",
                reviewed.evidence.recipe.install_files.join(", ")
            );
        }
        let host = self.host()?;
        let arch = host
            .config
            .options
            .arch()
            .unwrap_or_else(|| alpm_db::conf::host_arch().to_string());
        Ok(Prepared {
            reviewed,
            unattended: !interactive,
            settings,
            arch,
        })
    }

    /// Install missing repository dependencies, then build.
    pub fn build_aur(&self, prepared: &Prepared, yes: bool) -> Result<Vec<std::path::PathBuf>> {
        self.build_aur_chain(prepared, &[], &[], &mut Vec::new(), yes)
    }

    /// Build with `chain` naming the packages whose dependencies led here.
    fn build_aur_chain(
        &self,
        prepared: &Prepared,
        chain: &[String],
        ancestors: &[AncestorOutputs],
        built: &mut Vec<(String, String, Vec<alpm_db::dep::Dependency>)>,
        yes: bool,
    ) -> Result<Vec<std::path::PathBuf>> {
        if let Some(root) = crate::aur::chroot::root(&prepared.settings) {
            let image = crate::aur::chroot::host(&root)?;
            let missing =
                crate::aur::build::missing_deps(&image, &prepared.reviewed, &prepared.arch)?;
            if !missing.repo.is_empty() || !missing.other.is_empty() {
                let names: Vec<_> = missing
                    .repo
                    .iter()
                    .map(|p| p.name.clone())
                    .chain(missing.other.iter().map(|p| p.spec()))
                    .collect();
                bail!(
                    "clean chroot is missing build dependencies: {}; provision them in {} before retrying (host packages are not used)",
                    names.join(", "),
                    root.display()
                );
            }
            let opts = crate::aur::build::BuildOpts::from_settings(
                &prepared.settings,
                &prepared.reviewed.pkgbase,
                &crate::aur::cache_dir(),
                &image,
            )?;
            return crate::aur::build::build(&prepared.reviewed, &opts);
        }
        let host = self.host()?;
        let missing = crate::aur::build::missing_deps(&host, &prepared.reviewed, &prepared.arch)?;
        if !missing.other.is_empty() {
            self.build_aur_dependencies(prepared, &missing.other, chain, ancestors, built, yes)?;
        }
        self.install_aur_repo_dependencies(&host, &missing.repo, yes)?;
        let opts = crate::aur::build::BuildOpts::from_settings(
            &prepared.settings,
            &prepared.reviewed.pkgbase,
            &crate::aur::cache_dir(),
            &self.host()?,
        )?;
        crate::aur::build::build(&prepared.reviewed, &opts)
    }

    /// Dependencies no repository carries: each must be an AUR package,
    /// reviewed and approved like the parent, built first, and installed
    /// as a dependency. Version constraints are checked against what the
    /// recipe builds and provides.
    fn build_aur_dependencies(
        &self,
        parent: &Prepared,
        deps: &[alpm_db::dep::Dependency],
        chain: &[String],
        ancestors: &[AncestorOutputs],
        built: &mut Vec<(String, String, Vec<alpm_db::dep::Dependency>)>,
        yes: bool,
    ) -> Result<()> {
        let mut chain = chain.to_vec();
        chain.push(parent.reviewed.pkgname.clone());
        let mut ancestors = ancestors.to_vec();
        ancestors.push(AncestorOutputs::from_prepared(parent));
        if chain.len() > MAX_AUR_DEPTH {
            bail!("AUR dependency chain too deep: {}", chain.join(" -> "));
        }
        for dep in deps {
            let host = self.host()?;
            if host.is_satisfied(dep)?
                || built
                    .iter()
                    .any(|(name, version, provides)| dep.satisfied_by(name, version, provides))
            {
                continue;
            }
            let preserve_explicit = host
                .installed_package(&dep.name)?
                .is_some_and(|package| package.reason == alpm_db::local::InstallReason::Explicit);
            if let Some(ancestor_index) = ancestors
                .iter()
                .position(|ancestor| ancestor.satisfies(dep))
            {
                let ancestor = ancestors[ancestor_index].clone();
                if ancestor.sibling_satisfies(dep) {
                    let prepared = self.prepare_aur(
                        &ancestor.pkgname,
                        Some(&ancestor.commit),
                        true,
                        parent.unattended,
                    )?;
                    // `--nodeps` only skips makepkg's dependency preflight:
                    // the recipe still needs every tool and library except
                    // the descendant whose split sibling this bootstrap is
                    // about to provide.
                    let bootstrap_host = self.host()?;
                    let mut missing = crate::aur::build::missing_deps(
                        &bootstrap_host,
                        &prepared.reviewed,
                        &prepared.arch,
                    )?;
                    let descendants = &ancestors[ancestor_index + 1..];
                    missing
                        .other
                        .retain(|dep| !descendants.iter().any(|item| item.satisfies(dep)));
                    self.install_aur_repo_dependencies(&bootstrap_host, &missing.repo, yes)?;
                    if !missing.other.is_empty() {
                        self.build_aur_dependencies(
                            &prepared,
                            &missing.other,
                            &chain,
                            &ancestors,
                            built,
                            yes,
                        )?;
                    }
                    let opts = crate::aur::build::BuildOpts::from_settings(
                        &prepared.settings,
                        &prepared.reviewed.pkgbase,
                        &crate::aur::cache_dir(),
                        &self.host()?,
                    )?;
                    let files = crate::aur::build::build_without_dependency_checks(
                        &prepared.reviewed,
                        &opts,
                    )?;
                    let packages = crate::aur::build::built_packages(&files)?;
                    let mut selected = Vec::new();
                    let mut selected_packages = Vec::new();
                    for (file, package) in files.into_iter().zip(packages) {
                        if let Some((name, version, provides)) =
                            ancestor.packages.iter().find(|(name, version, provides)| {
                                name == &package.name && dep.satisfied_by(name, version, provides)
                            })
                        {
                            selected.push(file);
                            selected_packages.push((
                                name.clone(),
                                version.clone(),
                                provides.clone(),
                            ));
                        }
                    }
                    if selected.is_empty() {
                        bail!(
                            "{}: bootstrapped split package did not produce {}",
                            parent.reviewed.pkgname,
                            dep.spec()
                        );
                    }
                    self.install_selected_built(&prepared, &selected, None, "install")?;
                    built.extend(selected_packages);
                    continue;
                }
                bail!(
                    "AUR dependency cycle: {} -> {}",
                    chain.join(" -> "),
                    dep.name
                );
            }
            if chain.iter().any(|name| name == &dep.name) {
                bail!(
                    "AUR dependency cycle: {} -> {}",
                    chain.join(" -> "),
                    dep.name
                );
            }
            let known = self
                .aur_rpc()
                .info(&[&dep.name])
                .wrap_err_with(|| format!("looking up {} on the AUR", dep.name))?;
            if !known.iter().any(|p| p.name == dep.name) {
                bail!(
                    "{}: dependency {} is in no repository and not on the AUR",
                    parent.reviewed.pkgname,
                    dep.spec()
                );
            }
            println!(
                "{} needs {} from the AUR; reviewing it first",
                parent.reviewed.pkgname,
                dep.spec()
            );
            let prepared = self.prepare_aur(&dep.name, None, true, parent.unattended)?;
            let version = prepared.reviewed.srcinfo.version();
            let provides: Vec<alpm_db::dep::Dependency> = prepared
                .reviewed
                .srcinfo
                .provides(&dep.name, &prepared.arch);
            if !dep.satisfied_by(&dep.name, &version, &provides) {
                bail!(
                    "{}: AUR {} builds {} {}, which does not satisfy {}",
                    parent.reviewed.pkgname,
                    dep.name,
                    dep.name,
                    version,
                    dep.spec()
                );
            }
            let files = self.build_aur_chain(&prepared, &chain, &ancestors, built, yes)?;
            self.install_built(&prepared, &files, !preserve_explicit, "install")?;
            built.push((dep.name.clone(), version, provides));
        }
        Ok(())
    }

    fn install_aur_repo_dependencies(
        &self,
        host: &crate::host::Host,
        dependencies: &[crate::engine::Target],
        yes: bool,
    ) -> Result<()> {
        if dependencies.is_empty() {
            return Ok(());
        }
        let engine = self.engine()?;
        let mut tx = crate::engine::Transaction::install(dependencies.to_vec());
        if let crate::engine::Operation::Install { as_deps, .. } = &mut tx.operation {
            *as_deps = true;
        }
        let resolved = crate::engine::Engine::plan(&engine, &tx)?;
        let command = engine
            .apply_invocation(
                &tx,
                crate::engine::ApplyOpts {
                    dry_run: true,
                    no_confirm: true,
                },
            )
            .display();
        let plan = super::transaction::plan(host, &resolved, command);
        let performed = super::transaction::confirm_and_apply(
            self,
            &engine,
            &resolved,
            &plan,
            "install dependencies",
            yes,
            false,
        )?;
        if performed {
            self.record(&super::transaction::ledger_patch(
                &plan,
                &[],
                "install",
                false,
            ))?;
        }
        Ok(())
    }

    /// Install package files a build produced and record them in the
    /// ledger.
    pub fn install_built(
        &self,
        prepared: &Prepared,
        files: &[std::path::PathBuf],
        as_deps: bool,
        by: &str,
    ) -> Result<()> {
        for file in files {
            crate::aur::receipt::for_artifact(file)?;
        }
        let packages = crate::aur::build::built_packages(files)?;
        let version = prepared.reviewed.srcinfo.version();
        let mut selected_names = vec![prepared.reviewed.pkgname.clone()];
        let mut next = 0;
        while next < selected_names.len() {
            let name = selected_names[next].clone();
            next += 1;
            for dep in prepared.reviewed.srcinfo.depends(&name, &prepared.arch) {
                for package in &packages {
                    let provides = prepared
                        .reviewed
                        .srcinfo
                        .provides(&package.name, &prepared.arch);
                    if !selected_names.contains(&package.name)
                        && dep.satisfied_by(&package.name, &version, &provides)
                    {
                        selected_names.push(package.name.clone());
                    }
                }
            }
        }
        let selected: Vec<_> = files
            .iter()
            .cloned()
            .zip(packages)
            .filter(|(_, package)| selected_names.contains(&package.name))
            .collect();
        if selected.is_empty() {
            bail!(
                "{}: makepkg did not produce the requested package",
                prepared.reviewed.pkgname
            );
        }
        let files: Vec<_> = selected.into_iter().map(|(file, _)| file).collect();
        self.install_selected_built(
            prepared,
            &files,
            (!as_deps).then_some(prepared.reviewed.pkgname.as_str()),
            by,
        )
    }

    /// Install an already selected subset of a split build. Bootstrap code
    /// uses this after choosing the sibling that breaks a dependency cycle.
    fn install_selected_built(
        &self,
        prepared: &Prepared,
        files: &[std::path::PathBuf],
        explicit_name: Option<&str>,
        by: &str,
    ) -> Result<()> {
        for file in files {
            crate::aur::receipt::for_artifact(file)?;
        }
        let receipt_ref = crate::aur::receipt::for_artifact(
            files
                .first()
                .ok_or_else(|| eyre::eyre!("no build artifacts"))?,
        )?
        .1;
        let packages = crate::aur::build::built_packages(files)?;
        let host = self.host()?;
        let mut dependency_files = Vec::new();
        let mut explicit_files = Vec::new();
        let mut selected = Vec::new();
        for (file, package) in files.iter().cloned().zip(packages) {
            let explicit = explicit_name == Some(package.name.as_str())
                || host
                    .installed_package(&package.name)?
                    .is_some_and(|installed| {
                        installed.reason == alpm_db::local::InstallReason::Explicit
                    });
            if explicit {
                explicit_files.push(file);
            } else {
                dependency_files.push(file);
            }
            selected.push((package, explicit));
        }
        let engine = self.engine()?;
        let installed_names = selected
            .iter()
            .map(|(package, _)| package.name.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        let all_dependencies = selected.iter().all(|(_, explicit)| !explicit);
        let mut patch = crate::ledger::Patch::default();
        for (package, explicit) in selected {
            patch.upsert.insert(
                package.name,
                crate::ledger::Entry {
                    version: package.version,
                    tier: crate::resolve::Tier::Aur,
                    repo: None,
                    aur_commit: Some(prepared.reviewed.target.clone()),
                    build_receipt: Some(receipt_ref.clone()),
                    verification: None,
                    explicit,
                    by: by.to_string(),
                    at: crate::ledger::now(),
                },
            );
        }
        self.journaled(patch, || {
            for (files, as_deps) in [(dependency_files, true), (explicit_files, false)] {
                if !files.is_empty() {
                    crate::engine::Engine::install_files(
                        &engine,
                        &crate::engine::FileInstall {
                            files,
                            as_deps,
                            overwrite: Vec::new(),
                        },
                        crate::engine::ApplyOpts {
                            dry_run: false,
                            no_confirm: true,
                        },
                    )?;
                }
            }
            Ok(())
        })?;
        println!(
            "installed {} {} from AUR commit {}{}",
            installed_names,
            prepared.reviewed.srcinfo.version(),
            &prepared.reviewed.target[..12],
            if all_dependencies {
                " as a dependency"
            } else {
                ""
            }
        );
        Ok(())
    }

    /// Where AUR repositories are cloned from; `PACVAMP_AUR_GIT_BASE`
    /// points at a mirror or a test remote.
    pub fn aur_remote(&self) -> crate::aur::git::Remote {
        match std::env::var("PACVAMP_AUR_GIT_BASE") {
            Ok(base) if !base.is_empty() => crate::aur::git::Remote { base },
            _ => crate::aur::git::Remote::aur(),
        }
    }

    /// The user lockfile, beside the user manifest.
    pub fn lockfile_path(&self) -> std::path::PathBuf {
        Lockfile::path_beside(&self.manifest_paths().user)
    }

    /// Review `name`, at `commit` or the remote head.
    pub fn review_aur(
        &self,
        name: &str,
        commit: Option<&str>,
        interactive: bool,
    ) -> Result<(Reviewed, Lockfile)> {
        self.review_aur_with_pin(name, commit, interactive, commit.is_some())
    }

    fn review_aur_with_pin(
        &self,
        name: &str,
        commit: Option<&str>,
        interactive: bool,
        pinned: bool,
    ) -> Result<(Reviewed, Lockfile)> {
        let host = self.host()?;
        let manifest = self.manifest()?;
        let lock = Lockfile::load(&self.lockfile_path())?;
        let rpc = self.aur_rpc();
        let remote = self.aur_remote();
        let cache_dir = crate::aur::cache_dir();
        let arch = host
            .config
            .options
            .arch()
            .unwrap_or_else(|| alpm_db::conf::host_arch().to_string());
        let feeds = self.feeds(&host, &manifest.settings)?;
        let request = Request {
            host: &host,
            rpc: &rpc,
            remote: &remote,
            cache_dir: &cache_dir,
            settings: &manifest.settings,
            locked: &lock.aur,
            commit,
            pinned,
            interactive,
            arch: &arch,
            advisories: feeds.as_ref().and_then(|f| f.0.as_ref()),
            verdicts: feeds.as_ref().and_then(|f| f.1.as_ref()),
        };
        let reviewed = review(name, &request)?;
        Ok((reviewed, lock))
    }
}

impl App {
    /// The advisory and verdict feeds of the first `opr` repository, per
    /// `trust.advisories`: `off` never fetches, `on` warns and continues
    /// when they cannot be had, `required` fails.
    pub fn feeds(
        &self,
        host: &crate::host::Host,
        settings: &crate::manifest::Settings,
    ) -> Result<
        Option<(
            Option<crate::trust::Advisories>,
            Option<crate::trust::Verdicts>,
        )>,
    > {
        use crate::manifest::settings::Advisories as Mode;
        if settings.trust_advisories == Mode::Off {
            return Ok(None);
        }
        let unavailable = |detail: String| {
            if settings.trust_advisories == Mode::Required {
                bail!("trust.advisories is required: {detail}");
            }
            eprintln!("warning: advisory feeds unavailable: {detail}");
            Ok(None)
        };
        let Some(source) = host
            .sources
            .iter()
            .find(|s| matches!(s.tier, crate::resolve::Tier::Opr))
        else {
            return unavailable("no OPR repository is configured".into());
        };
        let Some(feed) = self.feed_source(host, &source.name) else {
            return unavailable(format!(
                "[{}] has no server to fetch feeds from",
                source.name
            ));
        };
        let keyring = match crate::trust::Keyring::load(self.paths.sysroot.as_deref()) {
            Ok(keyring) => keyring,
            Err(err) => {
                return unavailable(format!("loading trust keys: {err:#}"));
            }
        };
        let cache = crate::trust::Cache::for_repo(&source.name, self.paths.sysroot.as_deref())?;
        let advisories = crate::trust::fetch(&feed, "advisories.json", &keyring, &cache, false)
            .map(|fetched: crate::trust::Fetched<crate::trust::Advisories>| fetched.value);
        let verdicts = crate::trust::fetch(&feed, "verdicts.json", &keyring, &cache, false)
            .map(|fetched: crate::trust::Fetched<crate::trust::Verdicts>| fetched.value);
        if settings.trust_advisories == Mode::Required {
            return Ok(Some((
                Some(advisories.wrap_err("trust.advisories is required")?),
                Some(verdicts.wrap_err("trust.advisories is required")?),
            )));
        }
        let advisories = advisories
            .map_err(|err| {
                eprintln!("warning: advisory feeds unavailable (advisories): {err:#}");
            })
            .ok();
        let verdicts = verdicts
            .map_err(|err| {
                eprintln!("warning: advisory feeds unavailable (verdicts): {err:#}");
            })
            .ok();
        Ok(Some((advisories, verdicts)))
    }
}

/// Render a review for a human.
pub fn render(reviewed: &Reviewed) -> String {
    let mut out = String::new();
    let e = &reviewed.evidence;
    let _ = writeln!(
        out,
        "{} {} at {} [aur]",
        reviewed.pkgname,
        e.recipe.version,
        &reviewed.target[..12]
    );
    if let Some(rpc) = &e.rpc {
        let _ = writeln!(
            out,
            "maintainer {}, {} votes, last modified {}",
            rpc.maintainer.as_deref().unwrap_or("nobody (orphan)"),
            rpc.num_votes,
            crate::aur::format_age(rpc.last_modified, e.now)
        );
    }
    match &e.approved {
        Some(approved) if approved.commit == reviewed.target => {
            let _ = writeln!(out, "approved: this commit");
        }
        Some(approved) => {
            let _ = writeln!(
                out,
                "approved: {} (reviewing the change since)",
                &approved.commit[..12]
            );
        }
        None => {
            let _ = writeln!(out, "approved: never (first review)");
        }
    }
    for note in &reviewed.notes {
        let _ = writeln!(out, "note: {note}");
    }
    if reviewed.report.findings.is_empty() {
        let _ = writeln!(out, "findings: none");
    } else {
        let _ = writeln!(out, "findings ({:?} mode):", reviewed.report.mode);
        for judged in &reviewed.report.findings {
            let mark = match judged.decision {
                Decision::Allow => "info",
                Decision::Warn => "warn",
                Decision::Deny => "DENY",
            };
            let _ = writeln!(
                out,
                "  {mark}  {}: {}",
                judged.finding.id, judged.finding.message
            );
        }
    }
    out
}

impl RunWith<&App> for Review {
    type Output = Result<()>;

    fn run_with(self, app: &App) -> Self::Output {
        let interactive = !self.unattended && crate::ui::interactive();
        let (reviewed, _) = app.review_aur(&self.package, self.commit.as_deref(), interactive)?;
        let denied = reviewed.report.denied();
        if self.json {
            print_json(&serde_json::json!({
                "pkgbase": reviewed.pkgbase,
                "pkgname": reviewed.pkgname,
                "commit": reviewed.target,
                "version": reviewed.evidence.recipe.version,
                "approved": reviewed.evidence.approved.as_ref().map(|a| a.commit.clone()),
                "report": reviewed.report,
                "notes": reviewed.notes,
                "diff": if self.no_diff { None } else { Some(reviewed.review_text()?) },
            }))?;
            if denied {
                std::process::exit(1);
            }
            return Ok(());
        }
        if self.pager {
            crate::tui::require_terminal("aur review --pager", "run without --pager")?;
            let mut text = render(&reviewed);
            if !self.no_diff {
                let diff = reviewed.review_text()?;
                if !diff.is_empty() {
                    text.push('\n');
                    text.push_str(&diff);
                }
            }
            crate::tui::page(
                &format!("Review {} at {}", reviewed.pkgname, &reviewed.target[..12]),
                &text,
            )?;
        } else {
            print!("{}", render(&reviewed));
            if !self.no_diff {
                let text = reviewed.review_text()?;
                if !text.is_empty() {
                    println!();
                    print!("{text}");
                }
            }
        }
        if denied {
            std::process::exit(1);
        }
        Ok(())
    }
}

impl RunWith<&App> for Approve {
    type Output = Result<()>;

    fn run_with(self, app: &App) -> Self::Output {
        let interactive = !self.yes && crate::ui::interactive();
        let (reviewed, mut lock) =
            app.review_aur_with_pin(&self.package, self.commit.as_deref(), interactive, false)?;
        print!("{}", render(&reviewed));
        if reviewed.report.denied() && !self.force {
            bail!(
                "{}: {} finding(s) deny; review interactively or pass --force to approve anyway",
                self.package,
                reviewed.report.denials().count()
            );
        }
        if !self.yes && !self.force {
            let text = reviewed.review_text()?;
            if !text.is_empty() {
                println!();
                print!("{text}");
            }
            if !crate::ui::confirm(
                &format!("Approve {} at {}?", self.package, &reviewed.target[..12]),
                false,
            )? {
                bail!("not approved");
            }
        }
        // One approval covers all split packages produced by the pkgbase.
        lock.aur.remove(&self.package);
        lock.aur
            .insert(reviewed.pkgbase.clone(), reviewed.lock_entry());
        let path = app.lockfile_path();
        lock.save(&path)?;
        println!(
            "approved {} at {} in {}",
            self.package,
            &reviewed.target[..12],
            path.display()
        );
        Ok(())
    }
}

impl RunWith<&App> for Diff {
    type Output = Result<()>;

    fn run_with(self, app: &App) -> Self::Output {
        let (reviewed, _) = app.review_aur(&self.package, self.commit.as_deref(), true)?;
        print!("{}", reviewed.review_text()?);
        Ok(())
    }
}

/// Inspect a local build receipt and verify the artifact still matches it
#[derive(Debug, usage_rs::Args)]
pub struct Receipt {
    artifact: std::path::PathBuf,
    #[usage(long)]
    json: bool,
}
impl RunWith<&App> for Receipt {
    type Output = Result<()>;
    fn run_with(self, _app: &App) -> Result<()> {
        let (receipt, reference) = crate::aur::receipt::for_artifact(&self.artifact)?;
        if self.json {
            return print_json(&receipt);
        }
        println!(
            "{} at {}\n{}\nreceipt: {}\n{} source inputs; {} installed build dependencies; artifact hash matches",
            receipt.pkgbase,
            receipt.commit,
            receipt.claim,
            reference.path.display(),
            receipt.sources.len(),
            receipt.dependencies.len()
        );
        Ok(())
    }
}
