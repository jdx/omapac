//! Trust tiers and name resolution across the sources a machine has.
//!
//! Tiers come from `pacman.conf` repository names: Arch's official
//! repositories are `arch`, Omarchy's is `opr`, anything else is `custom`.
//! The AUR is a virtual source that never appears in `pacman.conf`, and a
//! package that is installed but in no sync database is `foreign`, which is
//! usually an AUR build but is not claimed to be one without evidence. See
//! `PLAN.md`, "Sources and resolution".

use std::fmt;

use serde::Serialize;

/// Where a package comes from, and therefore what its evidence is.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "kebab-case", tag = "tier", content = "name")]
pub enum Tier {
    /// Arch's official repositories, signed by Arch developers.
    Arch,
    /// The Omarchy Package Repository.
    Opr,
    /// Any other repository in `pacman.conf`, named.
    Custom(String),
    /// The AUR, built locally from a reviewed commit.
    Aur,
    /// Installed but in no sync database.
    Foreign,
}

impl Tier {
    /// Classify a `pacman.conf` repository by name.
    pub fn of_repo(repo: &str) -> Tier {
        match repo {
            "core" | "extra" | "multilib" | "core-testing" | "extra-testing"
            | "multilib-testing" | "kde-unstable" | "gnome-unstable" => Tier::Arch,
            "omarchy" => Tier::Opr,
            other => Tier::Custom(other.to_string()),
        }
    }

    /// The short label shown in listings.
    pub fn label(&self) -> &str {
        match self {
            Tier::Arch => "arch",
            Tier::Opr => "opr",
            Tier::Custom(_) => "custom",
            Tier::Aur => "aur",
            Tier::Foreign => "foreign",
        }
    }
}

impl fmt::Display for Tier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Tier::Custom(name) => write!(f, "custom:{name}"),
            other => f.write_str(other.label()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_repositories() {
        assert_eq!(Tier::of_repo("core"), Tier::Arch);
        assert_eq!(Tier::of_repo("multilib-testing"), Tier::Arch);
        assert_eq!(Tier::of_repo("omarchy"), Tier::Opr);
        assert_eq!(
            Tier::of_repo("chaotic-aur"),
            Tier::Custom("chaotic-aur".to_string())
        );
        assert_eq!(
            Tier::of_repo("chaotic-aur").to_string(),
            "custom:chaotic-aur"
        );
        assert_eq!(Tier::Foreign.to_string(), "foreign");
        assert_eq!(
            serde_json::to_string(&Tier::Custom("x".into())).unwrap(),
            r#"{"tier":"custom","name":"x"}"#
        );
        assert_eq!(
            serde_json::to_string(&Tier::Arch).unwrap(),
            r#"{"tier":"arch"}"#
        );
    }
}
