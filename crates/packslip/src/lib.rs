//! packslip: a vendor publishes one signed, machine-readable document per
//! release that says what the artifacts are and how to verify them.
//! Consumers pin one identity and get checksums, platform mapping,
//! provenance links, and an evidence level without per-vendor logic.
//!
//! The document is an in-toto statement; this crate holds the schema, the
//! verifier, and the generator. See `docs/spec/packslip.md` and `PLAN.md`,
//! "packslip: the vendor-binary standard".

#![forbid(unsafe_code)]

pub mod create;
pub mod minisign;
pub mod model;
pub mod verify;

pub use model::{Artifact, Identity, Level, Predicate, Scheme, Source, Statement, Subject};
pub use verify::{Verified, verify};

/// The sha256 of a file, lowercase hex, and its size.
pub fn digest_file(path: &std::path::Path) -> std::io::Result<(String, u64)> {
    use sha2::Digest as _;
    let mut file = std::fs::File::open(path)?;
    let mut hasher = sha2::Sha256::new();
    let size = std::io::copy(&mut file, &mut hasher)?;
    Ok((format!("{:x}", hasher.finalize()), size))
}
