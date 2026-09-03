//! The tool channel index: vetted vendor tool releases mirrored with
//! their evidence, for mise. See `docs/spec/tool-channel.md`.

use std::collections::BTreeMap;

use packslip::model::Level;
use serde::{Deserialize, Serialize};

pub const INDEX_PATH: &str = "tools/index.json";
pub const CHANNELS: &[&str] = &["edge", "rc", "stable"];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolIndex {
    pub version: u32,
    pub sequence: u64,
    pub generated_at: String,
    #[serde(default)]
    pub tools: BTreeMap<String, ToolEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolEntry {
    /// The project's package URL.
    pub project: String,
    /// The vendor's minisign public key file text, pinned by the channel.
    pub vendor_pubkey: String,
    #[serde(default)]
    pub versions: BTreeMap<String, ToolVersion>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolVersion {
    pub published_at: String,
    pub vetted_at: String,
    pub level: Level,
    /// The vendor key id that signed the packslip.
    pub key_id: String,
    /// Which channels carry this version.
    #[serde(default)]
    pub channels: Vec<String>,
    /// Set when the channel pulled the version after the fact.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub held: Option<String>,
    /// mise platform (`linux-x64`) → the mirrored artifact.
    #[serde(default)]
    pub artifacts: BTreeMap<String, ToolArtifact>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolArtifact {
    pub name: String,
    pub sha256: String,
    pub size: u64,
    /// Path under the store, such as `tools/claude/1.2.3/claude-linux-x64.tar.gz`.
    pub path: String,
    #[serde(default)]
    pub sidecars: Vec<String>,
}

impl ToolIndex {
    pub fn empty(now: &str) -> ToolIndex {
        ToolIndex {
            version: 1,
            sequence: 0,
            generated_at: now.to_string(),
            tools: BTreeMap::new(),
        }
    }

    /// Versions of `tool` in `channel` (any when `None`), oldest publish
    /// time first, held versions excluded unless asked for. Order comes
    /// from publish time, never from parsing version strings.
    pub fn versions<'a>(
        &'a self,
        tool: &str,
        channel: Option<&str>,
        include_held: bool,
    ) -> Vec<(&'a str, &'a ToolVersion)> {
        let Some(entry) = self.tools.get(tool) else {
            return Vec::new();
        };
        let mut versions: Vec<(&str, &ToolVersion)> = entry
            .versions
            .iter()
            .filter(|(_, v)| include_held || v.held.is_none())
            .filter(|(_, v)| channel.is_none_or(|c| v.channels.iter().any(|x| x == c)))
            .map(|(k, v)| (k.as_str(), v))
            .collect();
        versions.sort_by(|a, b| {
            a.1.published_at
                .cmp(&b.1.published_at)
                .then_with(|| a.1.vetted_at.cmp(&b.1.vetted_at))
        });
        versions
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn version(published: &str, channels: &[&str], held: bool) -> ToolVersion {
        ToolVersion {
            published_at: published.into(),
            vetted_at: published.into(),
            level: Level::L2,
            key_id: "k".into(),
            channels: channels.iter().map(|c| c.to_string()).collect(),
            held: held.then(|| "bad".to_string()),
            artifacts: BTreeMap::new(),
        }
    }

    #[test]
    fn lists_by_publish_time_and_channel() {
        let mut index = ToolIndex::empty("now");
        let mut entry = ToolEntry {
            project: "pkg:github/x/y".into(),
            vendor_pubkey: "RW".into(),
            versions: BTreeMap::new(),
        };
        entry.versions.insert(
            "10.0.0".into(),
            version("2026-09-03T00:00:00Z", &["edge"], false),
        );
        entry.versions.insert(
            "9.0.0".into(),
            version("2026-08-01T00:00:00Z", &["edge", "rc", "stable"], false),
        );
        entry.versions.insert(
            "9.5.0".into(),
            version("2026-08-20T00:00:00Z", &["edge", "rc"], true),
        );
        index.tools.insert("tool".into(), entry);
        let all: Vec<&str> = index
            .versions("tool", None, false)
            .iter()
            .map(|(v, _)| *v)
            .collect();
        assert_eq!(
            all,
            vec!["9.0.0", "10.0.0"],
            "held excluded, publish order not text order"
        );
        let with_held: Vec<&str> = index
            .versions("tool", None, true)
            .iter()
            .map(|(v, _)| *v)
            .collect();
        assert_eq!(with_held, vec!["9.0.0", "9.5.0", "10.0.0"]);
        let stable: Vec<&str> = index
            .versions("tool", Some("stable"), false)
            .iter()
            .map(|(v, _)| *v)
            .collect();
        assert_eq!(stable, vec!["9.0.0"]);
        assert!(index.versions("other", None, false).is_empty());
    }
}
