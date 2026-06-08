// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ovidiu Ancuta
//
// aioschema/rust v0.5.6 | AIOSchema spec v0.5.6
// https://aioschema.org

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
    SPEC_VERSION, SUPPORTED_VERSIONS, MAX_EXTENSION_SIZE_BYTES,
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
// -- end aioschema/rust v0.5.6 | AIOSchema spec v0.5.6 --
