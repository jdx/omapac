//! Settings: what the manifest layers say about policy, merged lowest to
//! highest, with the managed floor applied last through per-setting
//! combinators the way aube does it. See `PLAN.md`, "Settings" and
//! "Managed config".
//!
//! Combinators:
//! - `max`: the stricter (larger) value wins, so a user can raise an age
//!   above the floor but never lower it;
//! - `trueWins`: once the floor says `true`, it stays `true`;
//! - `ranked`: values have a strictness order and the stricter wins;
//! - `managedWins`: the floor replaces the value outright.

use std::fmt;
use std::str::FromStr;
use std::time::Duration;

use serde::{Deserialize, Serialize};

/// A duration written as `0`, `30m`, `48h`, `14d`, or `2w`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Age(pub Duration);

impl Age {
    pub const ZERO: Age = Age(Duration::ZERO);

    pub fn hours(hours: u64) -> Age {
        Age(Duration::from_secs(hours * 3600))
    }

    pub fn days(days: u64) -> Age {
        Age(Duration::from_secs(days * 86_400))
    }
}

impl FromStr for Age {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();
        if s == "0" {
            return Ok(Age::ZERO);
        }
        let split = s
            .find(|c: char| !c.is_ascii_digit())
            .ok_or_else(|| format!("{s:?}: an age needs a unit (s, m, h, d, w) or is 0"))?;
        let (number, unit) = s.split_at(split);
        let number: u64 = number.parse().map_err(|_| format!("{s:?}: not a number"))?;
        let seconds = match unit {
            "s" => 1,
            "m" => 60,
            "h" => 3600,
            "d" => 86_400,
            "w" => 7 * 86_400,
            _ => {
                return Err(format!(
                    "{s:?}: unknown unit {unit:?}, use s, m, h, d, or w"
                ));
            }
        };
        Ok(Age(Duration::from_secs(number * seconds)))
    }
}

impl fmt::Display for Age {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let secs = self.0.as_secs();
        if secs == 0 {
            return f.write_str("0");
        }
        for (unit, size) in [("w", 7 * 86_400), ("d", 86_400), ("h", 3600), ("m", 60)] {
            if secs.is_multiple_of(size) {
                return write!(f, "{}{unit}", secs / size);
            }
        }
        write!(f, "{secs}s")
    }
}

impl Serialize for Age {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for Age {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Value {
            Text(String),
            Integer(u64),
        }
        match Value::deserialize(deserializer)? {
            Value::Text(text) => text.parse().map_err(serde::de::Error::custom),
            Value::Integer(0) => Ok(Age::ZERO),
            Value::Integer(value) => Err(serde::de::Error::custom(format!(
                "integer age {value} needs a unit; only unquoted 0 is accepted"
            ))),
        }
    }
}

/// What a finding does when policy says warn or deny.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    #[default]
    Warn,
    Deny,
}

/// What to do with `.INSTALL` scriptlets from the AUR.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum InstallScripts {
    Allow,
    #[default]
    Approve,
    Deny,
}

/// How hard to enforce a verification source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Enforcement {
    Off,
    #[default]
    Verify,
    Required,
}

/// How to treat advisories.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Advisories {
    Off,
    #[default]
    On,
    Required,
}

/// What to do with packages from a custom repository.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum CustomRepos {
    Allow,
    #[default]
    Warn,
    Deny,
}

/// The weight of a reviewer kind's verdicts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ReviewerWeight {
    Ignore,
    Warn,
    Gate,
}

/// The `[policy]` table as written in one layer; every field optional.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct PolicyToml {
    pub mode: Option<Mode>,
    pub paranoid: Option<bool>,
    pub safe: Option<bool>,
    pub aur: AurToml,
    pub repo: RepoToml,
    pub trust: TrustToml,
    pub scanner: ScannerToml,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct AurToml {
    pub min_commit_age: Option<Age>,
    pub min_package_age: Option<Age>,
    pub min_votes: Option<u32>,
    pub jail: Option<bool>,
    pub chroot: Option<bool>,
    pub allow_network_build: Vec<String>,
    /// Managed only: packages that may never build with network.
    pub deny_network_build: Vec<String>,
    pub install_scripts: Option<InstallScripts>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct RepoToml {
    pub min_release_age: PerTierToml,
    pub min_release_age_excludes: Option<Vec<String>>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct PerTierToml {
    pub arch: Option<Age>,
    pub opr: Option<Age>,
    pub custom: Option<Age>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct TrustToml {
    pub index: Option<Enforcement>,
    pub provenance: Option<Enforcement>,
    pub reviewers: indexmap::IndexMap<String, ReviewerWeight>,
    pub no_downgrade: Option<bool>,
    pub advisories: Option<Advisories>,
    pub custom_repos: Option<CustomRepos>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct ScannerToml {
    pub socket_token: Option<String>,
}

/// The `[channel]` table.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct ChannelToml {
    /// Where immutable Arch snapshots live, for `channel pin`.
    pub snapshot_base: Option<String>,
    /// The tool channel store, for `omapac tools` and the mise plugin.
    pub tools_base: Option<String>,
}

/// The `[update]` table.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct UpdateToml {
    pub overwrite: Vec<String>,
    pub ignore: Vec<String>,
    pub ignore_group: Vec<String>,
    /// Shell commands run before an update, in order.
    pub pre_hooks: Vec<String>,
    /// Shell commands run after an update, in order.
    pub post_hooks: Vec<String>,
}

/// Effective settings after merging every layer and the managed floor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Settings {
    pub mode: Mode,
    pub paranoid: bool,
    pub safe: bool,
    pub aur_min_commit_age: Age,
    pub aur_min_package_age: Age,
    pub aur_min_votes: u32,
    pub aur_jail: bool,
    pub aur_chroot: bool,
    pub aur_allow_network_build: Vec<String>,
    pub aur_install_scripts: InstallScripts,
    pub repo_min_release_age_arch: Age,
    pub repo_min_release_age_opr: Age,
    pub repo_min_release_age_custom: Age,
    pub repo_min_release_age_excludes: Vec<String>,
    pub trust_index: Enforcement,
    pub trust_provenance: Enforcement,
    pub trust_reviewers: indexmap::IndexMap<String, ReviewerWeight>,
    pub trust_no_downgrade: bool,
    pub trust_advisories: Advisories,
    pub trust_custom_repos: CustomRepos,
    pub scanner_socket_token: Option<String>,
    pub update_overwrite: Vec<String>,
    pub update_ignore: Vec<String>,
    pub update_ignore_group: Vec<String>,
    pub update_pre_hooks: Vec<String>,
    pub update_post_hooks: Vec<String>,
    pub channel_snapshot_base: Option<String>,
    pub channel_tools_base: Option<String>,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            mode: Mode::Warn,
            paranoid: false,
            safe: false,
            aur_min_commit_age: Age::hours(48),
            aur_min_package_age: Age::days(14),
            aur_min_votes: 10,
            aur_jail: true,
            aur_chroot: false,
            aur_allow_network_build: Vec::new(),
            aur_install_scripts: InstallScripts::Approve,
            repo_min_release_age_arch: Age::ZERO,
            repo_min_release_age_opr: Age::ZERO,
            repo_min_release_age_custom: Age::ZERO,
            repo_min_release_age_excludes: Vec::new(),
            trust_index: Enforcement::Verify,
            trust_provenance: Enforcement::Verify,
            trust_reviewers: [
                ("static", ReviewerWeight::Gate),
                ("av", ReviewerWeight::Gate),
                ("ai", ReviewerWeight::Warn),
                ("human", ReviewerWeight::Gate),
                ("reproducible", ReviewerWeight::Warn),
            ]
            .into_iter()
            .map(|(k, v)| (k.to_string(), v))
            .collect(),
            trust_no_downgrade: true,
            trust_advisories: Advisories::On,
            trust_custom_repos: CustomRepos::Warn,
            scanner_socket_token: None,
            update_overwrite: Vec::new(),
            update_ignore: Vec::new(),
            update_ignore_group: Vec::new(),
            update_pre_hooks: Vec::new(),
            update_post_hooks: Vec::new(),
            channel_snapshot_base: None,
            channel_tools_base: None,
        }
    }
}

fn append_unique(into: &mut Vec<String>, from: &[String]) {
    for item in from {
        if !into.contains(item) {
            into.push(item.clone());
        }
    }
}

impl Settings {
    /// Apply an ordinary layer: scalars override, lists append.
    pub fn merge(&mut self, policy: &PolicyToml, update: &UpdateToml, channel: &ChannelToml) {
        if channel.snapshot_base.is_some() {
            self.channel_snapshot_base = channel.snapshot_base.clone();
        }
        if channel.tools_base.is_some() {
            self.channel_tools_base = channel.tools_base.clone();
        }
        macro_rules! set {
            ($field:ident, $value:expr) => {
                if let Some(value) = $value {
                    self.$field = value;
                }
            };
        }
        set!(mode, policy.mode);
        set!(paranoid, policy.paranoid);
        set!(safe, policy.safe);
        set!(aur_min_commit_age, policy.aur.min_commit_age);
        set!(aur_min_package_age, policy.aur.min_package_age);
        set!(aur_min_votes, policy.aur.min_votes);
        set!(aur_jail, policy.aur.jail);
        set!(aur_chroot, policy.aur.chroot);
        append_unique(
            &mut self.aur_allow_network_build,
            &policy.aur.allow_network_build,
        );
        set!(aur_install_scripts, policy.aur.install_scripts);
        set!(repo_min_release_age_arch, policy.repo.min_release_age.arch);
        set!(repo_min_release_age_opr, policy.repo.min_release_age.opr);
        set!(
            repo_min_release_age_custom,
            policy.repo.min_release_age.custom
        );
        if let Some(excludes) = &policy.repo.min_release_age_excludes {
            append_unique(&mut self.repo_min_release_age_excludes, excludes);
        }
        set!(trust_index, policy.trust.index);
        set!(trust_provenance, policy.trust.provenance);
        for (kind, weight) in &policy.trust.reviewers {
            self.trust_reviewers.insert(kind.clone(), *weight);
        }
        set!(trust_no_downgrade, policy.trust.no_downgrade);
        set!(trust_advisories, policy.trust.advisories);
        set!(trust_custom_repos, policy.trust.custom_repos);
        set!(
            scanner_socket_token,
            policy.scanner.socket_token.clone().map(Some)
        );
        append_unique(&mut self.update_overwrite, &update.overwrite);
        append_unique(&mut self.update_ignore, &update.ignore);
        append_unique(&mut self.update_ignore_group, &update.ignore_group);
        append_unique(&mut self.update_pre_hooks, &update.pre_hooks);
        append_unique(&mut self.update_post_hooks, &update.post_hooks);
    }

    /// Apply the managed floor with each setting's combinator.
    pub fn apply_managed(&mut self, managed: &PolicyToml) {
        macro_rules! max {
            ($field:ident, $value:expr) => {
                if let Some(value) = $value {
                    self.$field = self.$field.max(value);
                }
            };
        }
        macro_rules! true_wins {
            ($field:ident, $value:expr) => {
                if $value == Some(true) {
                    self.$field = true;
                }
            };
        }
        macro_rules! managed_wins {
            ($field:ident, $value:expr) => {
                if let Some(value) = $value {
                    self.$field = value;
                }
            };
        }
        // ranked: the enums derive Ord in strictness order, so max works.
        max!(mode, managed.mode);
        true_wins!(paranoid, managed.paranoid);
        true_wins!(safe, managed.safe);
        max!(aur_min_commit_age, managed.aur.min_commit_age);
        max!(aur_min_package_age, managed.aur.min_package_age);
        max!(aur_min_votes, managed.aur.min_votes);
        true_wins!(aur_jail, managed.aur.jail);
        true_wins!(aur_chroot, managed.aur.chroot);
        self.aur_allow_network_build
            .retain(|pkg| !managed.aur.deny_network_build.contains(pkg));
        max!(aur_install_scripts, managed.aur.install_scripts);
        max!(repo_min_release_age_arch, managed.repo.min_release_age.arch);
        max!(repo_min_release_age_opr, managed.repo.min_release_age.opr);
        max!(
            repo_min_release_age_custom,
            managed.repo.min_release_age.custom
        );
        if let Some(excludes) = &managed.repo.min_release_age_excludes {
            self.repo_min_release_age_excludes = excludes.clone();
        }
        max!(trust_index, managed.trust.index);
        max!(trust_provenance, managed.trust.provenance);
        for (kind, weight) in &managed.trust.reviewers {
            self.trust_reviewers.insert(kind.clone(), *weight);
        }
        true_wins!(trust_no_downgrade, managed.trust.no_downgrade);
        max!(trust_advisories, managed.trust.advisories);
        max!(trust_custom_repos, managed.trust.custom_repos);
        managed_wins!(
            scanner_socket_token,
            managed.scanner.socket_token.clone().map(Some)
        );
        if self.paranoid {
            self.harden();
        }
    }

    /// What `paranoid` means: every soft gate hard.
    pub(super) fn harden(&mut self) {
        self.mode = Mode::Deny;
        self.aur_jail = true;
        self.aur_install_scripts = InstallScripts::Deny;
        self.aur_allow_network_build.clear();
        self.trust_index = Enforcement::Required;
        self.trust_provenance = Enforcement::Required;
        self.trust_advisories = Advisories::Required;
        self.trust_custom_repos = CustomRepos::Deny;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ages_parse_and_display() {
        assert_eq!("0".parse::<Age>().unwrap(), Age::ZERO);
        assert_eq!("48h".parse::<Age>().unwrap(), Age::hours(48));
        assert_eq!("14d".parse::<Age>().unwrap(), Age::days(14));
        assert_eq!("2w".parse::<Age>().unwrap(), Age::days(14));
        assert_eq!(
            "90m".parse::<Age>().unwrap(),
            Age(Duration::from_secs(5400))
        );
        assert_eq!(Age::hours(48).to_string(), "2d");
        assert_eq!(Age::hours(36).to_string(), "36h");
        assert_eq!(Age::ZERO.to_string(), "0");
        assert_eq!(Age(Duration::from_secs(90)).to_string(), "90s");
        assert!("48".parse::<Age>().is_err());
        assert!("48y".parse::<Age>().is_err());
        assert!("h".parse::<Age>().is_err());
        #[derive(Deserialize)]
        struct Wrapper {
            age: Age,
        }
        assert_eq!(toml::from_str::<Wrapper>("age = 0").unwrap().age, Age::ZERO);
        assert!(toml::from_str::<Wrapper>("age = 1").is_err());
    }

    fn policy(text: &str) -> PolicyToml {
        toml::from_str(text).unwrap()
    }

    #[test]
    fn layers_override_scalars_and_append_lists() {
        let mut settings = Settings::default();
        settings.merge(
            &policy(
                "mode = \"deny\"\naur.min_commit_age = \"72h\"\naur.allow_network_build = [\"a\"]",
            ),
            &UpdateToml {
                overwrite: vec!["/x/*".into()],
                ..Default::default()
            },
            &ChannelToml::default(),
        );
        settings.merge(
            &policy("aur.min_commit_age = \"24h\"\naur.allow_network_build = [\"b\", \"a\"]"),
            &UpdateToml::default(),
            &ChannelToml::default(),
        );
        assert_eq!(settings.mode, Mode::Deny);
        assert_eq!(settings.aur_min_commit_age, Age::hours(24));
        assert_eq!(settings.aur_allow_network_build, ["a", "b"]);
        assert_eq!(settings.update_overwrite, ["/x/*"]);
    }

    #[test]
    fn managed_floor_only_tightens() {
        let mut settings = Settings::default();
        settings.merge(
            &policy(
                "aur.min_commit_age = \"12h\"\naur.jail = false\ntrust.index = \"off\"\n\
                 trust.custom_repos = \"allow\"\naur.allow_network_build = [\"chrome\", \"electron-app\"]\n\
                 repo.min_release_age.opr = \"7d\"\nrepo.min_release_age_excludes = [\"linux\"]",
            ),
            &UpdateToml::default(),
            &ChannelToml::default(),
        );
        settings.apply_managed(&policy(
            "aur.min_commit_age = \"48h\"\naur.jail = true\ntrust.index = \"verify\"\n\
             trust.custom_repos = \"warn\"\naur.deny_network_build = [\"chrome\"]\n\
             repo.min_release_age.opr = \"1d\"\nrepo.min_release_age_excludes = []\ntrust.reviewers = { ai = \"gate\" }",
        ));
        assert_eq!(settings.aur_min_commit_age, Age::hours(48), "max");
        assert!(settings.aur_jail, "trueWins");
        assert_eq!(settings.trust_index, Enforcement::Verify, "ranked");
        assert_eq!(settings.trust_custom_repos, CustomRepos::Warn, "ranked");
        assert_eq!(
            settings.aur_allow_network_build,
            ["electron-app"],
            "floor deny list"
        );
        assert_eq!(
            settings.repo_min_release_age_opr,
            Age::days(7),
            "user may lag more"
        );
        assert!(
            settings.repo_min_release_age_excludes.is_empty(),
            "an explicitly empty managedWins list clears user values"
        );
        assert_eq!(
            settings.trust_reviewers["ai"],
            ReviewerWeight::Gate,
            "managedWins"
        );
    }

    #[test]
    fn paranoid_hardens_everything() {
        let mut settings = Settings::default();
        settings.aur_allow_network_build.push("x".into());
        settings.apply_managed(&policy("paranoid = true"));
        assert!(settings.paranoid);
        assert_eq!(settings.mode, Mode::Deny);
        assert_eq!(settings.aur_install_scripts, InstallScripts::Deny);
        assert!(settings.aur_allow_network_build.is_empty());
        assert_eq!(settings.trust_advisories, Advisories::Required);
        assert_eq!(settings.trust_custom_repos, CustomRepos::Deny);
    }

    #[test]
    fn unknown_keys_are_rejected() {
        assert!(toml::from_str::<PolicyToml>("aur.min_commit_agee = \"1h\"").is_err());
        assert!(toml::from_str::<PolicyToml>("nope = 1").is_err());
    }
}
