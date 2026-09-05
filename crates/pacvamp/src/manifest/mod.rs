//! The manifest: what the machine should have, declared in layered
//! `pacvamp.toml` files, with the managed floor applied last. See
//! `PLAN.md`, "Manifest, lockfile, ledger, managed config".
//!
//! Layers, lowest to highest: `/etc/pacvamp/pacvamp.toml`,
//! `/etc/pacvamp/conf.d/*.toml` in name order, then the user's
//! `$XDG_CONFIG_HOME/pacvamp/pacvamp.toml`. The same package key wins by
//! last layer. `/etc/pacvamp/managed.toml` and `$PACVAMP_MANAGED_CONFIG_PATH`
//! are applied after everything with combinators that can only tighten.

pub mod edit;
pub mod settings;

use std::path::{Path, PathBuf};

use eyre::{Context as _, Result, bail};
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};

pub use settings::Settings;
use settings::{ChannelToml, PolicyToml, UpdateToml};

/// Where a declared package comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Source {
    /// A sync database, in repository order or pinned with `repo`.
    #[default]
    Repo,
    /// The AUR, built locally from a reviewed commit.
    Aur,
}

/// Whether the package should be on the machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum State {
    #[default]
    Present,
    Absent,
}

/// One `[packages]` entry as written.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct PackageToml {
    pub source: Source,
    /// Pin to one repository, for `source = "repo"`.
    pub repo: Option<String>,
    pub state: State,
    /// Never upgrade this package (IgnorePkg semantics).
    pub hold: bool,
}

/// A `[packages]` value: a table, or a bare `"present"` / `"absent"`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(untagged)]
enum PackageValue {
    State(State),
    Table(PackageToml),
}

/// One manifest file as written.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct LayerToml {
    packages: IndexMap<String, PackageValue>,
    policy: PolicyToml,
    update: UpdateToml,
    channel: ChannelToml,
}

/// A declared package after merging, with where it was declared.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Declared {
    pub name: String,
    #[serde(flatten)]
    pub package: PackageToml,
    pub declared_in: PathBuf,
}

/// Where the manifest layers live.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestPaths {
    pub system: PathBuf,
    pub conf_d: PathBuf,
    pub user: PathBuf,
    pub managed: Vec<PathBuf>,
}

impl ManifestPaths {
    /// The conventional locations, under `sysroot` for the system files.
    pub fn conventional(sysroot: Option<&Path>) -> ManifestPaths {
        let rooted = |path: &str| match sysroot {
            Some(root) => root.join(path.trim_start_matches('/')),
            None => PathBuf::from(path),
        };
        let config_home = std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".config")))
            .unwrap_or_else(|| PathBuf::from("/root/.config"));
        let mut managed = vec![rooted("/etc/pacvamp/managed.toml")];
        if let Some(extra) = std::env::var_os("PACVAMP_MANAGED_CONFIG_PATH") {
            managed.push(PathBuf::from(extra));
        }
        ManifestPaths {
            system: rooted("/etc/pacvamp/pacvamp.toml"),
            conf_d: rooted("/etc/pacvamp/conf.d"),
            user: config_home.join("pacvamp/pacvamp.toml"),
            managed,
        }
    }

    /// The layers that exist, lowest to highest.
    pub fn layers(&self) -> Vec<PathBuf> {
        let mut layers = Vec::new();
        if self.system.is_file() {
            layers.push(self.system.clone());
        }
        if let Ok(entries) = std::fs::read_dir(&self.conf_d) {
            let mut files: Vec<PathBuf> = entries
                .filter_map(Result::ok)
                .map(|e| e.path())
                .filter(|p| p.extension().is_some_and(|e| e == "toml") && p.is_file())
                .collect();
            files.sort();
            layers.extend(files);
        }
        if self.user.is_file() {
            layers.push(self.user.clone());
        }
        layers
    }
}

/// The merged manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Manifest {
    pub packages: IndexMap<String, Declared>,
    pub settings: Settings,
    /// Layer files that were read, lowest to highest.
    pub layers: Vec<PathBuf>,
    /// Managed files that were applied.
    pub managed: Vec<PathBuf>,
}

impl Manifest {
    /// Load and merge every layer at `paths`.
    pub fn load(paths: &ManifestPaths) -> Result<Manifest> {
        let mut packages: IndexMap<String, Declared> = IndexMap::new();
        let mut settings = Settings::default();
        let layers = paths.layers();
        for path in &layers {
            let layer = read_layer(path)?;
            for (name, value) in layer.packages {
                let package = match value {
                    PackageValue::State(state) => PackageToml {
                        state,
                        ..Default::default()
                    },
                    PackageValue::Table(table) => table,
                };
                packages.insert(
                    name.clone(),
                    Declared {
                        name,
                        package,
                        declared_in: path.clone(),
                    },
                );
            }
            settings.merge(&layer.policy, &layer.update, &layer.channel);
        }
        let mut managed = Vec::new();
        for path in &paths.managed {
            if !path.is_file() {
                continue;
            }
            let text = std::fs::read_to_string(path)
                .wrap_err_with(|| format!("reading {}", path.display()))?;
            let floor: ManagedToml =
                toml::from_str(&text).wrap_err_with(|| format!("parsing {}", path.display()))?;
            floor
                .policy
                .validate()
                .wrap_err_with(|| format!("parsing {}", path.display()))?;
            settings.apply_managed(&floor.policy);
            managed.push(path.clone());
        }
        if settings.paranoid {
            settings.harden();
        }
        Ok(Manifest {
            packages,
            settings,
            layers,
            managed,
        })
    }

    /// The declaration for `name`, if any layer has one.
    pub fn declared(&self, name: &str) -> Option<&Declared> {
        self.packages.get(name)
    }
}

/// `managed.toml` carries only policy; a `[packages]` table there would be
/// a floor on packages, which is not a thing.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
struct ManagedToml {
    policy: PolicyToml,
}

fn read_layer(path: &Path) -> Result<LayerToml> {
    let text =
        std::fs::read_to_string(path).wrap_err_with(|| format!("reading {}", path.display()))?;
    let layer: LayerToml =
        toml::from_str(&text).wrap_err_with(|| format!("parsing {}", path.display()))?;
    layer
        .policy
        .validate()
        .wrap_err_with(|| format!("parsing {}", path.display()))?;
    for (name, value) in &layer.packages {
        if let PackageValue::Table(table) = value
            && table.source == Source::Aur
            && table.repo.is_some()
        {
            bail!(
                "{}: package {name}: `repo` does not apply to source = \"aur\"",
                path.display()
            );
        }
    }
    Ok(layer)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn paths(dir: &Path) -> ManifestPaths {
        ManifestPaths {
            system: dir.join("etc/pacvamp/pacvamp.toml"),
            conf_d: dir.join("etc/pacvamp/conf.d"),
            user: dir.join("home/.config/pacvamp/pacvamp.toml"),
            managed: vec![dir.join("etc/pacvamp/managed.toml")],
        }
    }

    fn write(path: &Path, text: &str) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, text).unwrap();
    }

    #[test]
    fn layers_merge_in_order_and_record_provenance() {
        let dir = tempfile::tempdir().unwrap();
        let p = paths(dir.path());
        write(
            &p.system,
            "[packages]\nhelix = {}\nlibreoffice-fresh = {}\n[policy]\nmode = \"warn\"\n",
        );
        write(
            &p.conf_d.join("10-omarchy.toml"),
            "[packages]\nyay = \"present\"\n[update]\noverwrite = [\"/usr/share/omarchy/*\"]\n",
        );
        write(
            &p.conf_d.join("05-early.toml"),
            "[packages]\nyay = { hold = true }\n",
        );
        write(
            &p.user,
            "[packages]\nlibreoffice-fresh = { state = \"absent\" }\ngoogle-chrome = { source = \"aur\" }\n[policy]\naur.min_commit_age = \"72h\"\n",
        );
        let manifest = Manifest::load(&p).unwrap();
        let names: Vec<&str> = manifest.packages.keys().map(String::as_str).collect();
        assert_eq!(
            names,
            ["helix", "libreoffice-fresh", "yay", "google-chrome"]
        );
        let office = &manifest.packages["libreoffice-fresh"];
        assert_eq!(office.package.state, State::Absent);
        assert_eq!(office.declared_in, p.user);
        let yay = &manifest.packages["yay"];
        assert!(!yay.package.hold, "10-omarchy.toml wins over 05-early.toml");
        assert_eq!(yay.declared_in, p.conf_d.join("10-omarchy.toml"));
        assert_eq!(
            manifest.packages["google-chrome"].package.source,
            Source::Aur
        );
        assert_eq!(
            manifest.settings.aur_min_commit_age,
            settings::Age::hours(72)
        );
        assert_eq!(manifest.settings.update_overwrite, ["/usr/share/omarchy/*"]);
        assert_eq!(manifest.layers.len(), 4);
        assert!(manifest.managed.is_empty());
    }

    #[test]
    fn managed_floor_is_applied_last() {
        let dir = tempfile::tempdir().unwrap();
        let p = paths(dir.path());
        write(
            &p.user,
            "[policy]\naur.min_commit_age = \"1h\"\naur.jail = false\n",
        );
        write(
            &p.managed[0],
            "[policy]\naur.min_commit_age = \"48h\"\naur.jail = true\n",
        );
        let manifest = Manifest::load(&p).unwrap();
        assert_eq!(
            manifest.settings.aur_min_commit_age,
            settings::Age::hours(48)
        );
        assert!(manifest.settings.aur_jail);
        assert_eq!(manifest.managed, [p.managed[0].clone()]);
    }

    #[test]
    fn user_paranoid_mode_hardens_without_a_managed_file() {
        let dir = tempfile::tempdir().unwrap();
        let p = paths(dir.path());
        write(&p.user, "[policy]\nparanoid = true\n");

        let manifest = Manifest::load(&p).unwrap();

        assert_eq!(manifest.settings.mode, settings::Mode::Deny);
        assert!(manifest.settings.aur_jail);
        assert_eq!(
            manifest.settings.trust_custom_repos,
            settings::CustomRepos::Deny
        );
    }

    #[test]
    fn errors_name_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let p = paths(dir.path());
        write(
            &p.user,
            "[packages]\nx = { source = \"aur\", repo = \"extra\" }\n",
        );
        let err = Manifest::load(&p).unwrap_err().to_string();
        assert!(err.contains("`repo` does not apply"), "{err}");
        write(&p.user, "[packages]\nx = { stat = \"absent\" }\n");
        let err = format!("{:#}", Manifest::load(&p).unwrap_err());
        assert!(err.contains("parsing") && err.contains("stat"), "{err}");
        write(&p.managed[0], "[packages]\nx = {}\n");
        write(&p.user, "");
        let err = format!("{:#}", Manifest::load(&p).unwrap_err());
        assert!(err.contains("managed.toml"), "{err}");
    }

    #[test]
    fn missing_files_mean_an_empty_manifest() {
        let dir = tempfile::tempdir().unwrap();
        let manifest = Manifest::load(&paths(dir.path())).unwrap();
        assert!(manifest.packages.is_empty());
        assert_eq!(manifest.settings, Settings::default());
    }
}
