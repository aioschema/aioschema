//! unit_tests.rs
//!
//! Unit tests for `compute_hash`, `canonical_json`, and `verify_manifest`.

use aioschema::{
    canonical_json, compute_hash, parse_hash_prefix, verify_manifest,
    Core, HashOriginal, Manifest, VerifyOptions,
    CORE_HASH_FIELDS,
};
use hex;
use std::collections::BTreeMap;

// ── compute_hash ──────────────────────────────────────────────────────────────

#[test]
fn compute_hash_sha256_known_vector() {
    let data = b"The quick brown fox jumps over the lazy dog";
    let got  = compute_hash(data, "sha256").unwrap();
    let want = "sha256-d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592";
    assert_eq!(got, want);
}

#[test]
fn compute_hash_sha384_known_vector() {
    let data = b"The quick brown fox jumps over the lazy dog";
    let got  = compute_hash(data, "sha384").unwrap();
    let want = "sha384-ca737f1014a48f4c0b6dd43cb177b0afd9e5169367544c494011e3317dbf9a509cb1e5dc1e85a941bbee3d7f2afbc9b1";
    assert_eq!(got, want);
}

#[test]
fn compute_hash_sha256_empty() {
    let got  = compute_hash(b"", "sha256").unwrap();
    let want = "sha256-e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    assert_eq!(got, want);
}

#[test]
fn compute_hash_sha256_full_byte_range() {
    let data: Vec<u8> = (0u8..=255u8).collect();
    let got  = compute_hash(&data, "sha256").unwrap();
    let want = "sha256-40aff2e9d2d8922e47afd4648e6967497158785fbd1da870e7110266bf944880";
    assert_eq!(got, want);
}

#[test]
fn compute_hash_prefix_format_sha256() {
    let got = compute_hash(b"test", "sha256").unwrap();
    assert!(got.starts_with("sha256-"), "must start with sha256-");
    assert_eq!(got.len(), 7 + 64, "sha256 total length");
}

#[test]
fn compute_hash_prefix_format_sha384() {
    let got = compute_hash(b"test", "sha384").unwrap();
    assert!(got.starts_with("sha384-"), "must start with sha384-");
    assert_eq!(got.len(), 7 + 96, "sha384 total length");
}

#[test]
fn compute_hash_deterministic() {
    let data = b"determinism check";
    let a = compute_hash(data, "sha256").unwrap();
    let b = compute_hash(data, "sha256").unwrap();
    assert_eq!(a, b);
}

#[test]
fn compute_hash_unsupported_algorithm() {
    let err = compute_hash(b"x", "md5").unwrap_err();
    assert!(err.to_string().contains("unsupported"), "{err}");
}

// ── parse_hash_prefix ─────────────────────────────────────────────────────────

#[test]
fn parse_hash_prefix_sha256() {
    let value = format!("sha256-{}", "a".repeat(64));
    let (alg, digest) = parse_hash_prefix(&value).unwrap();
    assert_eq!(alg, "sha256");
    assert_eq!(digest.len(), 64);
}

#[test]
fn parse_hash_prefix_sha384() {
    let value = format!("sha384-{}", "b".repeat(96));
    let (alg, digest) = parse_hash_prefix(&value).unwrap();
    assert_eq!(alg, "sha384");
    assert_eq!(digest.len(), 96);
}

#[test]
fn parse_hash_prefix_sha3_256() {
    let value = format!("sha3-256-{}", "c".repeat(64));
    let (alg, digest) = parse_hash_prefix(&value).unwrap();
    assert_eq!(alg, "sha3-256");
    assert_eq!(digest.len(), 64);
}

#[test]
fn parse_hash_prefix_invalid_cases() {
    let invalids = [
        "",
        "sha256-",
        &format!("sha256-{}", "a".repeat(63)), // too short
        &format!("sha256-{}", "a".repeat(65)), // too long
        &format!("md5-{}", "a".repeat(32)),     // unsupported
        &format!("sha384-{}", "a".repeat(64)), // wrong length for sha384
        "notahash",
    ];
    for &v in &invalids {
        assert!(
            parse_hash_prefix(v).is_err(),
            "expected error for {v:?}, got Ok"
        );
    }
}

// ── canonical_json ────────────────────────────────────────────────────────────

#[test]
fn canonical_json_sorts_keys() {
    let obj = serde_json::json!({ "z": "last", "a": "first", "m": "middle" });
    let got  = String::from_utf8(canonical_json(&obj).unwrap()).unwrap();
    let want = r#"{"a":"first","m":"middle","z":"last"}"#;
    assert_eq!(got, want);
}

#[test]
fn canonical_json_no_whitespace() {
    let obj = serde_json::json!({ "k": "v" });
    let got = String::from_utf8(canonical_json(&obj).unwrap()).unwrap();
    assert!(
        !got.chars().any(|c| c.is_ascii_whitespace()),
        "canonical JSON must contain no whitespace, got: {got}"
    );
}

#[test]
fn canonical_json_known_vector() {
    // CV-05 input object
    let obj = serde_json::json!({
        "hash_original":      "sha256-abc123",
        "asset_id":           "urn:test:001",
        "creator_id":         "ed25519-fp-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "schema_version":     "0.5.5",
        "creation_timestamp": "2026-02-22T12:00:00Z"
    });
    let got  = String::from_utf8(canonical_json(&obj).unwrap()).unwrap();
    let want = r#"{"asset_id":"urn:test:001","creation_timestamp":"2026-02-22T12:00:00Z","creator_id":"ed25519-fp-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","hash_original":"sha256-abc123","schema_version":"0.5.5"}"#;
    assert_eq!(got, want);
}

#[test]
fn canonical_json_nested_sorting() {
    let obj = serde_json::json!({ "outer": { "z": 1, "a": 2 } });
    let got  = String::from_utf8(canonical_json(&obj).unwrap()).unwrap();
    let want = r#"{"outer":{"a":2,"z":1}}"#;
    assert_eq!(got, want);
}

#[test]
fn canonical_json_deterministic() {
    let obj = serde_json::json!({ "c": 3, "b": 2, "a": 1 });
    let a = canonical_json(&obj).unwrap();
    let b = canonical_json(&obj).unwrap();
    assert_eq!(a, b);
}

// ── verify_manifest ───────────────────────────────────────────────────────────

/// Build the fixed CV-07 asset bytes.
fn cv07_asset() -> Vec<u8> {
    hex::decode("43562d303720666978656420617373657420636f6e74656e7420666f722063726f73732d766572696669636174696f6e").unwrap()
}

/// Build the fixed CV-07 manifest.
fn cv07_manifest() -> Manifest {
    Manifest {
        core: Core {
            asset_id:            "00000000-0000-7000-8000-000000000001".to_string(),
            schema_version:      "0.5.5".to_string(),
            creation_timestamp:  "2026-02-22T12:00:00Z".to_string(),
            hash_original:       HashOriginal::Single(
                "sha256-88dedaf2e6b9c5ef7f32171831c1d6c39446d754ddc924a0792dd0f8100de15a".to_string(),
            ),
            creator_id:          "ed25519-fp-00000000000000000000000000000000".to_string(),
            core_fingerprint:    Some(
                "sha256-d61f35a9cbd7138874ab81017e78023f9ed8e1e9f8d458787078597cc8d082f4".to_string(),
            ),
            hash_schema_block:   None,
            signature:           None,
            manifest_signature:  None,
            anchor_reference:    None,
            previous_version_anchor: None,
        },
        extensions: BTreeMap::new(),
    }
}

#[test]
fn verify_valid_hard_match() {
    let result = verify_manifest(&cv07_asset(), &cv07_manifest(), &VerifyOptions::default()).unwrap();
    assert!(result.success, "expected success: {}", result.message);
    assert_eq!(result.match_type.unwrap().to_string(), "hard");
}

#[test]
fn verify_tampered_hash_original() {
    let mut m = cv07_manifest();
    m.core.hash_original = HashOriginal::Single(format!("sha256-{}", "0".repeat(64)));
    let result = verify_manifest(&cv07_asset(), &m, &VerifyOptions::default()).unwrap();
    assert!(!result.success, "expected failure for tampered hash_original");
}

#[test]
fn verify_tampered_core_fingerprint() {
    let mut m = cv07_manifest();
    m.core.core_fingerprint = Some(format!("sha256-{}", "f".repeat(64)));
    let result = verify_manifest(&cv07_asset(), &m, &VerifyOptions::default()).unwrap();
    assert!(!result.success, "expected failure for tampered core_fingerprint");
}

#[test]
fn verify_unsupported_schema_version() {
    let mut m = cv07_manifest();
    m.core.schema_version = "99.0".to_string();
    let result = verify_manifest(&cv07_asset(), &m, &VerifyOptions::default()).unwrap();
    assert!(!result.success, "expected failure for unsupported schema_version");
}

#[test]
fn verify_missing_creator_id() {
    let mut m = cv07_manifest();
    m.core.creator_id = String::new();
    let result = verify_manifest(&cv07_asset(), &m, &VerifyOptions::default()).unwrap();
    assert!(!result.success, "expected failure for missing creator_id");
}

#[test]
fn verify_invalid_timestamp() {
    let mut m = cv07_manifest();
    m.core.creation_timestamp = "2026-02-22 12:00:00".to_string(); // missing T and Z
    let result = verify_manifest(&cv07_asset(), &m, &VerifyOptions::default()).unwrap();
    assert!(!result.success, "expected failure for invalid timestamp");
}

#[test]
fn verify_non_utc_timestamp() {
    let mut m = cv07_manifest();
    m.core.creation_timestamp = "2026-02-22T12:00:00+05:00".to_string();
    let result = verify_manifest(&cv07_asset(), &m, &VerifyOptions::default()).unwrap();
    assert!(!result.success, "expected failure for non-UTC timestamp");
}

#[test]
fn verify_hash_schema_block_alias() {
    // CV-10: deprecated hash_schema_block must be accepted
    let mut m = cv07_manifest();
    let hsb = m.core.core_fingerprint.take().unwrap(); // move cfp → hsb
    m.core.hash_schema_block = Some(hsb);
    let result = verify_manifest(&cv07_asset(), &m, &VerifyOptions::default()).unwrap();
    assert!(result.success, "expected success with hash_schema_block alias: {}", result.message);
}

#[test]
fn verify_multi_hash() {
    // CV-11: multi-hash array — any match is sufficient
    let mut m = cv07_manifest();
    m.core.hash_original = HashOriginal::Multi(vec![
        "sha256-88dedaf2e6b9c5ef7f32171831c1d6c39446d754ddc924a0792dd0f8100de15a".to_string(),
        "sha384-8683ae6457999d73454fc65e8e1930d5603130c1ac0085b1a7249ad7e8943a24e3524d42d9298ff70ff664074043eb9d".to_string(),
    ]);
    // core_fingerprint must match the multi-hash core fields (CV-11 value)
    m.core.core_fingerprint = Some(
        "sha256-6391625df74b27daa78eda3a4ed84a3b578094792b67dc04782b4164bdd6a4c7".to_string(),
    );
    let result = verify_manifest(&cv07_asset(), &m, &VerifyOptions::default()).unwrap();
    assert!(result.success, "expected success for multi-hash manifest: {}", result.message);
}

#[test]
fn verify_anchor_warning_not_failure() {
    // anchor_reference present but verify_anchor=false → warning, not failure
    let mut m = cv07_manifest();
    m.core.anchor_reference = Some("aios-anchor:ots:abc123".to_string());
    let result = verify_manifest(&cv07_asset(), &m, &VerifyOptions::default()).unwrap();
    assert!(result.success, "anchor_reference with verify_anchor=false must not fail: {}", result.message);
    assert!(
        result.warnings.iter().any(|w| w.contains("anchor_reference")),
        "expected warning about unverified anchor_reference"
    );
}

#[test]
fn verify_unsigned_passes_without_key() {
    let result = verify_manifest(&cv07_asset(), &cv07_manifest(), &VerifyOptions::default()).unwrap();
    assert!(result.success, "unsigned manifest must verify without a key");
    assert!(!result.signature_verified, "SignatureVerified must be false");
}

// ── Bootstrap rule ────────────────────────────────────────────────────────────

#[test]
fn core_hash_fields_bootstrap_rule() {
    for &field in CORE_HASH_FIELDS {
        assert_ne!(
            field, "core_fingerprint",
            "CORE_HASH_FIELDS must not include core_fingerprint (bootstrap rule)"
        );
        assert_ne!(
            field, "hash_schema_block",
            "CORE_HASH_FIELDS must not include hash_schema_block"
        );
    }
}

#[test]
fn core_hash_fields_contains_required() {
    let required = ["asset_id", "schema_version", "creation_timestamp", "hash_original", "creator_id"];
    for r in required {
        assert!(
            CORE_HASH_FIELDS.contains(&r),
            "CORE_HASH_FIELDS missing required field {r:?}"
        );
    }
}
