//! AIOSchema v0.5.5 — Rust reference implementation.
//!
//! # Quick start
//!
//! ```rust,no_run
//! use aioschema::{verify_manifest, Manifest, VerifyOptions};
//!
//! let asset_data = std::fs::read("asset.jpg").unwrap();
//! let manifest: Manifest =
//!     serde_json::from_str(&std::fs::read_to_string("asset.jpg.aios.json").unwrap()).unwrap();
//!
//! let result = verify_manifest(&asset_data, &manifest, &VerifyOptions::default()).unwrap();
//! assert!(result.success);
//! ```

pub mod algorithms;
pub mod types;
pub mod verify;

// ── Primary API — types and verification ──────────────────────────────────────
pub use types::{
    AiosError, AnchorRecord, Core, HashOriginal, Manifest, MatchType,
    VerificationResult, VerifyOptions,
    // Constants
    CORE_HASH_FIELDS, DEFAULT_HASH_ALG, SIDECAR_SUFFIX,
    SOFT_BINDING_THRESHOLD_DEFAULT, SOFT_BINDING_THRESHOLD_MAX,
    SPEC_VERSION, SUPPORTED_VERSIONS,
};
pub use verify::verify_manifest;

// ── Algorithms — hashing, canonical JSON, pattern matching ───────────────────
pub use algorithms::{
    // Hash computation
    compute_hash,
    parse_hash_prefix,
    // Canonical serialization
    canonical_json,
    canonical_core_fields,
    canonical_manifest_bytes,
    // Timing-safe comparison
    safe_equal,
    // Compiled regex patterns (useful for callers doing field validation)
    ANCHOR_PATTERN,
    CREATOR_ID_ATTRIBUTED_PATTERN,
    HASH_PATTERN,
    SIGNATURE_PATTERN,
    TIMESTAMP_PATTERN,
    UUID_PATTERN,
};
