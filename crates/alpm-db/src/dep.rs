//! Dependency strings, following `alpm_dep_from_string` and `_alpm_depcmp`
//! in libalpm's `deps.c`.
//!
//! A dependency is `name[op version][: description]`, where `op` is one of
//! `<=`, `>=`, `<`, `>`, `=`, checked in that order. The description
//! separator is `": "` with a space, so an epoch's colon is not mistaken
//! for one. Provides use the same grammar with at most `=`.

use std::cmp::Ordering;
use std::fmt;

use crate::vercmp::vercmp;

/// A version comparison in a dependency.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Op {
    Eq,
    Ge,
    Le,
    Gt,
    Lt,
}

impl Op {
    fn as_str(self) -> &'static str {
        match self {
            Op::Eq => "=",
            Op::Ge => ">=",
            Op::Le => "<=",
            Op::Gt => ">",
            Op::Lt => "<",
        }
    }

    fn holds(self, ordering: Ordering) -> bool {
        match self {
            Op::Eq => ordering == Ordering::Equal,
            Op::Ge => ordering != Ordering::Less,
            Op::Le => ordering != Ordering::Greater,
            Op::Gt => ordering == Ordering::Greater,
            Op::Lt => ordering == Ordering::Less,
        }
    }
}

/// A parsed dependency, provision, conflict, or replacement.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Dependency {
    pub name: String,
    /// The comparison and version, when the string carried one.
    pub constraint: Option<(Op, String)>,
    /// The text after `": "`, used by optional dependencies.
    pub description: Option<String>,
}

impl Dependency {
    /// Parse a dependency string. Never fails; an odd string becomes a
    /// dependency with an odd name, as in libalpm.
    pub fn parse(text: &str) -> Dependency {
        let (spec, description) = match text.find(": ") {
            Some(i) => (&text[..i], Some(text[i + 2..].to_string())),
            None => (text, None),
        };
        let (name, constraint) = if let Some(i) = spec.find('<') {
            if spec[i + 1..].starts_with('=') {
                (&spec[..i], Some((Op::Le, spec[i + 2..].to_string())))
            } else {
                (&spec[..i], Some((Op::Lt, spec[i + 1..].to_string())))
            }
        } else if let Some(i) = spec.find('>') {
            if spec[i + 1..].starts_with('=') {
                (&spec[..i], Some((Op::Ge, spec[i + 2..].to_string())))
            } else {
                (&spec[..i], Some((Op::Gt, spec[i + 1..].to_string())))
            }
        } else if let Some(i) = spec.find('=') {
            (&spec[..i], Some((Op::Eq, spec[i + 1..].to_string())))
        } else {
            (spec, None)
        };
        Dependency {
            name: name.to_string(),
            constraint,
            description,
        }
    }

    /// Whether a package with this exact name and version satisfies the
    /// dependency (`_alpm_depcmp_literal`).
    pub fn matches(&self, name: &str, version: &str) -> bool {
        self.name == name && self.version_holds(Some(version))
    }

    /// Whether a provision satisfies the dependency
    /// (`_alpm_depcmp_provides`): names match, and either the dependency
    /// has no version, or the provision has one that satisfies it.
    pub fn satisfied_by_provision(&self, provision: &Dependency) -> bool {
        if self.name != provision.name {
            return false;
        }
        match &self.constraint {
            None => true,
            Some(_) => match &provision.constraint {
                Some((Op::Eq, version)) => self.version_holds(Some(version)),
                _ => false,
            },
        }
    }

    /// Whether a package named `name` at `version` with `provides` satisfies
    /// the dependency, directly or through a provision (`_alpm_depcmp`).
    pub fn satisfied_by(&self, name: &str, version: &str, provides: &[Dependency]) -> bool {
        self.matches(name, version)
            || provides
                .iter()
                .any(|provision| self.satisfied_by_provision(provision))
    }

    fn version_holds(&self, version: Option<&str>) -> bool {
        match (&self.constraint, version) {
            (None, _) => true,
            (Some(_), None) => false,
            (Some((op, wanted)), Some(have)) => op.holds(vercmp(have, wanted)),
        }
    }

    /// The `name[op version]` part, without the description.
    pub fn spec(&self) -> String {
        match &self.constraint {
            Some((op, version)) => format!("{}{}{}", self.name, op.as_str(), version),
            None => self.name.clone(),
        }
    }
}

impl fmt::Display for Dependency {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.spec())?;
        if let Some(description) = &self.description {
            write!(f, ": {description}")?;
        }
        Ok(())
    }
}

impl From<&str> for Dependency {
    fn from(text: &str) -> Self {
        Dependency::parse(text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_every_operator_and_round_trips() {
        let cases = [
            ("bash", "bash", None),
            ("glibc>=2.39", "glibc", Some((Op::Ge, "2.39"))),
            ("python<3.14", "python", Some((Op::Lt, "3.14"))),
            ("foo<=1", "foo", Some((Op::Le, "1"))),
            ("foo>1", "foo", Some((Op::Gt, "1"))),
            ("libalpm.so=16-64", "libalpm.so", Some((Op::Eq, "16-64"))),
            ("pkg=1:2.0-3", "pkg", Some((Op::Eq, "1:2.0-3"))),
        ];
        for (text, name, constraint) in cases {
            let dep = Dependency::parse(text);
            assert_eq!(dep.name, name, "{text}");
            assert_eq!(
                dep.constraint,
                constraint.map(|(op, v)| (op, v.to_string())),
                "{text}"
            );
            assert_eq!(dep.description, None);
            assert_eq!(dep.to_string(), text);
        }
    }

    #[test]
    fn descriptions_and_epochs() {
        let dep = Dependency::parse("base-devel: required to use makepkg");
        assert_eq!(dep.name, "base-devel");
        assert_eq!(dep.constraint, None);
        assert_eq!(dep.description.as_deref(), Some("required to use makepkg"));
        assert_eq!(dep.to_string(), "base-devel: required to use makepkg");

        let dep = Dependency::parse("pkg>=1:2.0: with an epoch");
        assert_eq!(dep.constraint, Some((Op::Ge, "1:2.0".to_string())));
        assert_eq!(dep.description.as_deref(), Some("with an epoch"));
    }

    #[test]
    fn literal_matching_uses_vercmp() {
        let dep = Dependency::parse("glibc>=2.39");
        assert!(dep.matches("glibc", "2.39-1"));
        assert!(dep.matches("glibc", "2.40"));
        assert!(!dep.matches("glibc", "2.38-9"));
        assert!(!dep.matches("musl", "2.40"));
        assert!(Dependency::parse("glibc").matches("glibc", "anything"));
        assert!(Dependency::parse("pkg=1.0").matches("pkg", "1.0-3"));
        assert!(Dependency::parse("pkg<1.0").matches("pkg", "1.0rc1"));
    }

    #[test]
    fn provisions() {
        let provides: Vec<Dependency> = ["libalpm.so=16-64", "pacman-frontend"]
            .into_iter()
            .map(Dependency::parse)
            .collect();
        assert!(Dependency::parse("libalpm.so=16-64").satisfied_by("pacman", "7.1", &provides));
        assert!(Dependency::parse("libalpm.so>=15-64").satisfied_by("pacman", "7.1", &provides));
        assert!(!Dependency::parse("libalpm.so=17-64").satisfied_by("pacman", "7.1", &provides));
        assert!(Dependency::parse("pacman-frontend").satisfied_by("pacman", "7.1", &provides));
        // A versioned dependency is not satisfied by an unversioned provision.
        assert!(!Dependency::parse("pacman-frontend>=1").satisfied_by("pacman", "7.1", &provides));
        // Nor by a provision with a non-equality constraint, which makepkg
        // would not emit but the grammar allows.
        assert!(!Dependency::parse("x>=1").satisfied_by_provision(&Dependency::parse("x>=2")));
    }
}
