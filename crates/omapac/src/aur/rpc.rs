//! The AUR RPC, version 5: `info` for exact names and `search` by keyword.
//! Documented at <https://aur.archlinux.org/rpc/swagger>.

use std::fmt;

use serde::{Deserialize, Serialize};

pub const DEFAULT_BASE: &str = "https://aur.archlinux.org";
const USER_AGENT: &str = concat!(
    "omapac/",
    env!("CARGO_PKG_VERSION"),
    " (+https://github.com/jdx/omapac)"
);

/// One package as the RPC describes it. Every field the RPC may omit is
/// optional; `Submitter` is absent when the submitting account is gone.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Package {
    pub name: String,
    pub package_base: String,
    pub version: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(rename = "URL", default)]
    pub url: Option<String>,
    #[serde(default)]
    pub maintainer: Option<String>,
    #[serde(default)]
    pub submitter: Option<String>,
    #[serde(default)]
    pub co_maintainers: Vec<String>,
    #[serde(default)]
    pub num_votes: u64,
    #[serde(default)]
    pub popularity: f64,
    /// Unix time the package was flagged out of date, if it is.
    #[serde(default)]
    pub out_of_date: Option<i64>,
    pub first_submitted: i64,
    pub last_modified: i64,
    #[serde(default)]
    pub pending_requests: u64,
    #[serde(default)]
    pub depends: Vec<String>,
    #[serde(default)]
    pub make_depends: Vec<String>,
    #[serde(default)]
    pub check_depends: Vec<String>,
    #[serde(default)]
    pub opt_depends: Vec<String>,
    #[serde(default)]
    pub conflicts: Vec<String>,
    #[serde(default)]
    pub provides: Vec<String>,
    #[serde(default)]
    pub replaces: Vec<String>,
    #[serde(default)]
    pub groups: Vec<String>,
    #[serde(default)]
    pub license: Vec<String>,
    #[serde(default)]
    pub keywords: Vec<String>,
}

impl Package {
    /// Whether the current maintainer is not the original submitter, which
    /// means the package changed hands at some point.
    pub fn changed_hands(&self) -> bool {
        match (&self.maintainer, &self.submitter) {
            (Some(m), Some(s)) => m != s,
            _ => false,
        }
    }

    pub fn is_orphan(&self) -> bool {
        self.maintainer.is_none()
    }
}

#[derive(Debug, Deserialize)]
struct Response {
    #[serde(default)]
    results: Vec<Package>,
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    error: Option<String>,
}

/// Why an RPC call failed.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("AUR RPC request failed: {0}")]
    Http(String),
    #[error("AUR RPC returned an error: {0}")]
    Rpc(String),
    #[error("AUR RPC response could not be parsed: {0}")]
    Parse(String),
}

/// Something that answers RPC requests, so tests can use fixtures.
pub trait Rpc {
    /// Exact-name lookup. Names that do not exist are simply absent.
    fn info(&self, names: &[&str]) -> Result<Vec<Package>, Error>;
    /// Keyword search over names and descriptions.
    fn search(&self, keyword: &str) -> Result<Vec<Package>, Error>;
}

/// The real RPC over HTTP.
#[derive(Debug, Clone)]
pub struct Client {
    pub base: String,
    agent: ureq::Agent,
}

impl Client {
    pub fn new() -> Client {
        Client::with_base(DEFAULT_BASE)
    }

    pub fn with_base(base: &str) -> Client {
        let config = ureq::Agent::config_builder()
            .user_agent(USER_AGENT)
            .timeout_global(Some(std::time::Duration::from_secs(30)))
            .build();
        Client {
            base: base.trim_end_matches('/').to_string(),
            agent: ureq::Agent::new_with_config(config),
        }
    }

    fn get(&self, url: &str) -> Result<Vec<Package>, Error> {
        let mut response = self
            .agent
            .get(url)
            .call()
            .map_err(|e| Error::Http(e.to_string()))?;
        let text = response
            .body_mut()
            .read_to_string()
            .map_err(|e| Error::Http(e.to_string()))?;
        parse(&text)
    }
}

impl Default for Client {
    fn default() -> Self {
        Client::new()
    }
}

/// Parse an RPC response body.
pub fn parse(text: &str) -> Result<Vec<Package>, Error> {
    let response: Response = serde_json::from_str(text).map_err(|e| Error::Parse(e.to_string()))?;
    if response.kind == "error" {
        return Err(Error::Rpc(
            response
                .error
                .unwrap_or_else(|| "unknown error".to_string()),
        ));
    }
    Ok(response.results)
}

impl Rpc for Client {
    fn info(&self, names: &[&str]) -> Result<Vec<Package>, Error> {
        if names.is_empty() {
            return Ok(Vec::new());
        }
        let mut found = Vec::new();
        // The RPC caps the query string; 100 names is comfortably under it.
        for chunk in names.chunks(100) {
            let query: Vec<String> = chunk
                .iter()
                .map(|n| format!("arg[]={}", encode(n)))
                .collect();
            let url = format!("{}/rpc/v5/info?{}", self.base, query.join("&"));
            found.extend(self.get(&url)?);
        }
        Ok(found)
    }

    fn search(&self, keyword: &str) -> Result<Vec<Package>, Error> {
        let url = format!(
            "{}/rpc/v5/search/{}?by=name-desc",
            self.base,
            encode(keyword)
        );
        self.get(&url)
    }
}

fn encode(s: &str) -> String {
    let mut out = String::new();
    for byte in s.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char)
            }
            other => out.push_str(&format!("%{other:02X}")),
        }
    }
    out
}

impl fmt::Display for Package {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.name, self.version)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const INFO: &str = include_str!("../../fixtures/aur/info.json");

    #[test]
    fn parses_info_with_optional_fields() {
        let packages = parse(INFO).unwrap();
        assert_eq!(packages.len(), 2, "the unknown name is simply absent");
        let yay = &packages[0];
        assert_eq!(yay.name, "yay");
        assert_eq!(yay.maintainer.as_deref(), Some("jguer"));
        assert_eq!(yay.submitter.as_deref(), Some("jguer"));
        assert!(!yay.changed_hands());
        assert_eq!(yay.num_votes, 2651);
        assert!(yay.popularity > 30.0);
        assert_eq!(yay.out_of_date, None);
        assert_eq!(yay.depends, ["pacman>6.1", "git"]);
        let chrome = &packages[1];
        assert_eq!(chrome.submitter, None, "absent when the account is gone");
        assert_eq!(chrome.maintainer.as_deref(), Some("gromit"));
        assert!(!chrome.is_orphan());
        assert_eq!(chrome.first_submitted, 1274819156);
    }

    #[test]
    fn errors_and_encoding() {
        let err = parse(r#"{"type":"error","error":"Too many package results.","resultcount":0,"results":[],"version":5}"#)
            .unwrap_err();
        assert!(
            matches!(err, Error::Rpc(ref m) if m.contains("Too many")),
            "{err}"
        );
        assert!(matches!(parse("nope"), Err(Error::Parse(_))));
        assert_eq!(encode("google-chrome"), "google-chrome");
        assert_eq!(encode("a b/c"), "a%20b%2Fc");
        assert_eq!(encode("c++-gtk-utils"), "c%2B%2B-gtk-utils");
    }

    /// Against the real AUR, only when asked for.
    #[test]
    fn live_info_when_enabled() {
        if std::env::var_os("OMAPAC_LIVE_TESTS").is_none() {
            eprintln!("skipping: set OMAPAC_LIVE_TESTS=1");
            return;
        }
        let client = Client::new();
        let packages = client.info(&["yay"]).unwrap();
        assert_eq!(packages[0].package_base, "yay");
        let hits = client.search("yay").unwrap();
        assert!(hits.iter().any(|p| p.name == "yay"));
    }
}
