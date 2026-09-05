use serde::{Deserialize, Serialize};
/// What the repository concludes from a verified release. This is the
/// repository's own scale for floors and no-downgrade; packslip itself
/// defines none, and SLSA build levels belong to verified provenance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Level {
    /// Checksums only, no signature.
    L0,
    /// Signed checksums or artifact signatures.
    L1,
    /// A verified packslip.
    L2,
    /// A verified packslip whose every artifact links build provenance.
    L3,
    /// L3 plus reproducible or independently verified builds.
    L4,
}

impl std::fmt::Display for Level {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Level::L0 => "L0",
            Level::L1 => "L1",
            Level::L2 => "L2",
            Level::L3 => "L3",
            Level::L4 => "L4",
        })
    }
}
