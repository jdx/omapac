//! Format-preserving edits to a manifest file, for `add` and `drop`.

use std::path::Path;

use eyre::{Context as _, Result};
use toml_edit::{DocumentMut, InlineTable, Item, Table, value};

use super::{PackageToml, Source, State};

fn load(path: &Path) -> Result<DocumentMut> {
    match std::fs::read_to_string(path) {
        Ok(text) => text
            .parse::<DocumentMut>()
            .wrap_err_with(|| format!("parsing {}", path.display())),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(DocumentMut::new()),
        Err(err) => Err(err).wrap_err_with(|| format!("reading {}", path.display())),
    }
}

fn save(path: &Path, doc: &DocumentMut) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .wrap_err_with(|| format!("creating {}", parent.display()))?;
    }
    std::fs::write(path, doc.to_string()).wrap_err_with(|| format!("writing {}", path.display()))
}

/// Declare `name` in the manifest at `path`, replacing any existing entry.
pub fn set_package(path: &Path, name: &str, package: &PackageToml) -> Result<()> {
    let mut doc = load(path)?;
    if !doc.contains_table("packages") {
        doc["packages"] = Item::Table(Table::new());
    }
    let mut entry = InlineTable::new();
    if package.source == Source::Aur {
        entry.insert("source", "aur".into());
    }
    if let Some(repo) = &package.repo {
        entry.insert("repo", repo.as_str().into());
    }
    if package.state == State::Absent {
        entry.insert("state", "absent".into());
    }
    if package.hold {
        entry.insert("hold", true.into());
    }
    let table = doc["packages"].as_table_mut().expect("packages is a table");
    // Keep a trailing comment on a line whose value is being replaced.
    let suffix = table
        .get(name)
        .and_then(Item::as_value)
        .and_then(|v| v.decor().suffix().cloned());
    let mut new_value = value(entry);
    if let (Some(suffix), Some(v)) = (suffix, new_value.as_value_mut()) {
        v.decor_mut().set_suffix(suffix);
    }
    table[name] = new_value;
    save(path, &doc)
}

/// Remove `name` from the manifest at `path`. Returns whether it was there.
pub fn remove_package(path: &Path, name: &str) -> Result<bool> {
    let mut doc = load(path)?;
    let removed = doc
        .get_mut("packages")
        .and_then(Item::as_table_mut)
        .is_some_and(|table| table.remove(name).is_some());
    if removed {
        save(path, &doc)?;
    }
    Ok(removed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_and_remove_preserve_the_rest_of_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("omapac.toml");
        std::fs::write(
            &path,
            "# my machine\n[packages]\nhelix = {} # editor\n\n[policy]\nmode = \"warn\"\n",
        )
        .unwrap();
        set_package(
            &path,
            "google-chrome",
            &PackageToml {
                source: Source::Aur,
                ..Default::default()
            },
        )
        .unwrap();
        set_package(
            &path,
            "libreoffice-fresh",
            &PackageToml {
                state: State::Absent,
                ..Default::default()
            },
        )
        .unwrap();
        set_package(
            &path,
            "helix",
            &PackageToml {
                repo: Some("extra".into()),
                hold: true,
                ..Default::default()
            },
        )
        .unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert_eq!(
            text,
            "# my machine\n[packages]\nhelix = { repo = \"extra\", hold = true } # editor\n\
             google-chrome = { source = \"aur\" }\nlibreoffice-fresh = { state = \"absent\" }\n\n\
             [policy]\nmode = \"warn\"\n"
        );
        assert!(remove_package(&path, "google-chrome").unwrap());
        assert!(!remove_package(&path, "google-chrome").unwrap());
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(!text.contains("google-chrome"));
        assert!(text.contains("# my machine"));
    }

    #[test]
    fn creates_the_file_and_its_directory() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("deep/omapac.toml");
        set_package(&path, "helix", &PackageToml::default()).unwrap();
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "[packages]\nhelix = {}\n"
        );
        assert!(!remove_package(&dir.path().join("nope.toml"), "x").unwrap());
    }
}
