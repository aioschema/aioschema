//! Hash computation, canonical JSON, and regex patterns for AIOSchema v0.5.5.

use crate::types::{AiosError, CORE_HASH_FIELDS};
use once_cell::sync::Lazy;
use regex::Regex;
use sha2::{Digest, Sha256, Sha384};
use sha3::Sha3_256;
use serde_json::{Map, Value};
use std::collections::BTreeMap;

// ── Compiled regex patterns ───────────────────────────────────────────────────

/// `(sha256|sha3-256)-[0-9a-f]{64}` OR `sha384-[0-9a-f]{96}` (§5.3)
pub static HASH_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^(sha256|sha3-256)-[0-9a-f]{64}$|^sha384-[0-9a-f]{96}$").unwrap()
});

/// `ed25519-<128 hex chars>` (§5.1)
pub static SIGNATURE_PATTERN: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^ed25519-[0-9a-f]{128}$").unwrap());

/// `aios-anchor:<method>:<id>` (§9.1)
pub static ANCHOR_PATTERN: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^aios-anchor:[a-z0-9_-]+:[a-zA-Z0-9_-]+$").unwrap());

/// Strict ISO-8601 UTC with Z suffix (§5.2)
pub static TIMESTAMP_PATTERN: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$").unwrap());

/// `ed25519-fp-<32 hex chars>` attributed creator_id (§5.7)
pub static CREATOR_ID_ATTRIBUTED_PATTERN: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^ed25519-fp-[0-9a-f]{32}$").unwrap());

/// Any well-formed UUID (for anonymous creator_id)
pub static UUID_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$").unwrap()
});

// ── Hash computation ──────────────────────────────────────────────────────────

/// Compute a prefixed hash string `"<alg>-<hex>"` from `data`.
///
/// Supported algorithms: `"sha256"`, `"sha384"`, `"sha3-256"`.
pub fn compute_hash(data: &[u8], algorithm: &str) -> Result<String, AiosError> {
    match algorithm {
        "sha256" => {
            let digest = Sha256::digest(data);
            Ok(format!("sha256-{}", hex::encode(digest)))
        }
        "sha384" => {
            let digest = Sha384::digest(data);
            Ok(format!("sha384-{}", hex::encode(digest)))
        }
        "sha3-256" => {
            let digest = Sha3_256::digest(data);
            Ok(format!("sha3-256-{}", hex::encode(digest)))
        }
        other => Err(AiosError::UnsupportedAlgorithm(other.to_string())),
    }
}

/// Parse `"alg-hexdigest"` into `(algorithm, hex_digest)`.
///
/// Returns `Err` if the value does not match `HASH_PATTERN`.
pub fn parse_hash_prefix(value: &str) -> Result<(&str, &str), AiosError> {
    if !HASH_PATTERN.is_match(value) {
        return Err(AiosError::InvalidHash(format!(
            "invalid hash value {value:?}: expected (sha256|sha3-256)-<64hex> or sha384-<96hex>"
        )));
    }
    // sha3-256 has a hyphen inside the algorithm token — must be checked first.
    if let Some(rest) = value.strip_prefix("sha3-256-") {
        return Ok(("sha3-256", rest));
    }
    // sha256 or sha384
    let dash = value.find('-').unwrap(); // guaranteed by pattern
    Ok((&value[..dash], &value[dash + 1..]))
}

// ── Canonical JSON ────────────────────────────────────────────────────────────

/// Produce deterministic, compact JSON from a `serde_json::Value`.
///
/// All object keys are sorted recursively — this is the canonical form
/// required by §5.6. Uses `BTreeMap` internally so `serde_json` emits
/// sorted keys.
pub fn canonical_json(value: &Value) -> Result<Vec<u8>, AiosError> {
    let sorted = sort_value(value);
    Ok(serde_json::to_vec(&sorted)?)
}

/// Recursively sort all object keys in a JSON value tree.
fn sort_value(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let sorted: BTreeMap<String, Value> = map
                .iter()
                .map(|(k, v)| (k.clone(), sort_value(v)))
                .collect();
            // Convert BTreeMap back to serde_json Map (preserves insertion order,
            // but since we iterate a BTreeMap the order is already sorted).
            let mut out = Map::new();
            for (k, v) in sorted {
                out.insert(k, v);
            }
            Value::Object(out)
        }
        Value::Array(arr) => Value::Array(arr.iter().map(sort_value).collect()),
        other => other.clone(),
    }
}

/// Extract exactly `CORE_HASH_FIELDS` from a JSON object and return their
/// canonical bytes. Used to compute and verify `core_fingerprint`.
pub fn canonical_core_fields(core: &Value) -> Result<Vec<u8>, AiosError> {
    let obj = core.as_object().ok_or_else(|| {
        AiosError::Other("core must be a JSON object".to_string())
    })?;

    let mut subset = Map::new();
    for &field in CORE_HASH_FIELDS {
        if let Some(v) = obj.get(field) {
            subset.insert(field.to_string(), v.clone());
        }
    }
    canonical_json(&Value::Object(subset))
}

/// Serialize a full manifest for `manifest_signature` verification (§5.8).
///
/// `manifest_signature` is set to `null` before serialization to avoid a
/// circular dependency (bootstrap exclusion).
pub fn canonical_manifest_bytes(manifest: &Value) -> Result<Vec<u8>, AiosError> {
    let mut m = manifest.clone();
    if let Some(core) = m.get_mut("core").and_then(|c| c.as_object_mut()) {
        core.insert("manifest_signature".to_string(), Value::Null);
    }
    canonical_json(&m)
}

// ── Timing-safe comparison ────────────────────────────────────────────────────

/// Timing-safe string equality (§12.1).
pub fn safe_equal(a: &str, b: &str) -> bool {
    // Constant-time comparison via XOR fold.
    let ab = a.as_bytes();
    let bb = b.as_bytes();
    if ab.len() != bb.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in ab.iter().zip(bb.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}
