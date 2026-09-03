//! packslip: a vendor publishes one signed, machine-readable document per
//! release that says what the artifacts are and how to verify them. Consumers
//! pin one identity and get checksums, platform mapping, provenance links, and
//! an evidence level without per-vendor logic.
//!
//! The document is an in-toto statement; this crate holds the schema, the
//! verifier, and the generator. See `PLAN.md`, "packslip: the vendor-binary
//! standard".

#![forbid(unsafe_code)]
