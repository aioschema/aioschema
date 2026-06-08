// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ovidiu Ancuta
//
// aioschema/rust v0.5.6 | AIOSchema spec v0.5.6
// https://aioschema.org

use aioschema::{
    canonical_json, compute_hash, parse_hash_prefix, verify_manifest,
    Core, HashOriginal, Manifest, VerifyOptions,
    CORE_HASH_FIELDS, MAX_EXTENSION_SIZE_BYTES,
};
use hex;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

// ── ComputeHash ───────────────────────────────────────────────────────────────

#[test]
fn test_compute_hash_sha256_known_vector() {
    let data = b"The quick brown fox jumps over the lazy dog";
    let got = compute_hash(data, "sha256").unwrap();
    assert_eq!(got, "sha256-d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592");
}

#[test]
fn test_compute_hash_sha256_empty() {
    let got = compute_hash(b"", "sha256").unwrap();
    assert_eq!(got, "sha256-e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
}

#[test]
fn test_compute_hash_deterministic() {
    let a = compute_hash(b"test", "sha256").unwrap();
    let b = compute_hash(b"test", "sha256").unwrap();
    assert_eq!(a, b);
}

// ── ParseHashPrefix ───────────────────────────────────────────────────────────

#[test]
fn test_parse_hash_prefix_sha256() {
    let (alg, digest) = parse_hash_prefix("sha256-abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789").unwrap();
    assert_eq!(alg, "sha256");
    assert_eq!(digest.len(), 64);
}

// ── CanonicalJSON ──────────────────────────────────────────────────────────────

#[test]
fn test_canonical_json_sorts_keys() {
    let obj = serde_json::json!({"z": "last", "a": "first", "m": "middle"});
    let got = canonical_json(&obj).unwrap();
    assert_eq!(String::from_utf8(got).unwrap(), r#"{"a":"first","m":"middle","z":"last"}"#);
}

#[test]
fn test_canonical_json_no_whitespace() {
    let obj = serde_json::json!({"k": "v"});
    let got = canonical_json(&obj).unwrap();
    let s = String::from_utf8(got).unwrap();
    assert!(!s.contains(' ') && !s.contains('\n') && !s.contains('\t'));
}

// ── VerifyManifest ────────────────────────────────────────────────────────────

fn make_core(asset: &[u8]) -> Core {
    let hash = compute_hash(asset, "sha256").unwrap();
    let mut core = Core {
        asset_id: "0195a5bc-1e9a-7e3e-8f0a-5c6d7e8f9a0b".to_string(),
        schema_version: "0.5.6".to_string(),
        creation_timestamp: "2026-05-26T00:00:00Z".to_string(),
        hash_original: HashOriginal::Single(hash.clone()),
        creator_id: "0195a5bc-1e9a-7e3e-8f0a-5c6d7e8f9a0b".to_string(),
        core_fingerprint: None,
        hash_schema_block: None,
        signature: None,
        manifest_signature: None,
        anchor_reference: None,
        previous_version_anchor: None,
    };

    // Compute core_fingerprint
    let core_map = serde_json::json!({
        "asset_id": core.asset_id,
        "schema_version": core.schema_version,
        "creation_timestamp": core.creation_timestamp,
        "hash_original": hash,
        "creator_id": core.creator_id,
    });
    let core_bytes = canonical_json(&core_map).unwrap();
    let cfp = compute_hash(&core_bytes, "sha256").unwrap();
    core.core_fingerprint = Some(cfp);
    core
}

#[test]
fn test_verify_valid_hard_match() {
    let asset = b"hello world";
    let core = make_core(asset);
    let m = Manifest { core, extensions: BTreeMap::new() };
    let result = verify_manifest(asset, &m, &VerifyOptions::default()).unwrap();
    assert!(result.success, "expected success, got: {}", result.message);
}

#[test]
fn test_verify_unsupported_schema_version() {
    let asset = b"hello world";
    let mut core = make_core(asset);
    core.schema_version = "99.0".to_string();
    let m = Manifest { core, extensions: BTreeMap::new() };
    let result = verify_manifest(asset, &m, &VerifyOptions::default()).unwrap();
    assert!(!result.success, "expected failure for unsupported version");
}

#[test]
fn test_verify_missing_creator_id() {
    let asset = b"hello world";
    let mut core = make_core(asset);
    core.creator_id = "".to_string();
    let m = Manifest { core, extensions: BTreeMap::new() };
    let result = verify_manifest(asset, &m, &VerifyOptions::default()).unwrap();
    assert!(!result.success, "expected failure for missing creator_id");
}

#[test]
fn test_verify_hash_schema_block_alias() {
    let asset = b"hello world";
    let mut core = make_core(asset);
    // Move core_fingerprint to deprecated hash_schema_block
    let hsb = core.core_fingerprint.clone();
    core.hash_schema_block = hsb;
    core.core_fingerprint = None;
    let m = Manifest { core, extensions: BTreeMap::new() };
    let result = verify_manifest(asset, &m, &VerifyOptions::default()).unwrap();
    assert!(result.success, "expected success with hash_schema_block alias, got: {}", result.message);
}

#[test]
fn test_verify_unsigned_passes_without_key() {
    let asset = b"hello world";
    let core = make_core(asset);
    let m = Manifest { core, extensions: BTreeMap::new() };
    let result = verify_manifest(asset, &m, &VerifyOptions::default()).unwrap();
    assert!(result.success, "unsigned manifest must verify without a key: {}", result.message);
    assert!(!result.signature_verified);
}

#[test]
fn test_core_hash_fields_bootstrap_rule() {
    for field in CORE_HASH_FIELDS {
        assert_ne!(*field, "core_fingerprint", "CoreHashFields must not include core_fingerprint");
        assert_ne!(*field, "hash_schema_block", "CoreHashFields must not include hash_schema_block");
    }
}

// ── TV-21, TV-22, TV-24 (v0.5.6) ──────────────────────────────────────────────

#[test]
fn tv21_ai_declaration_valid() {
    let asset = b"TV-21 ai declaration";
    let mut core = make_core(asset);
    let mut ext = BTreeMap::new();
    ext.insert("ai_declaration".to_string(), serde_json::json!({
        "disclosure_required": true,
        "ai_generated": true,
        "ai_manipulated": false,
        "human_reviewed": true
    }));
    // Need to recompute core_fingerprint since we'll add extensions
    // Actually extensions are NOT in core_fingerprint, so we're fine
    let m = Manifest { core, extensions: ext };
    let result = verify_manifest(asset, &m, &VerifyOptions::default()).unwrap();
    assert!(result.success, "TV-21 failed: {}", result.message);
}

#[test]
fn tv22_ai_declaration_constraint_violation() {
    let asset = b"TV-22 constraint violation";
    let mut core = make_core(asset);
    let mut ext = BTreeMap::new();
    ext.insert("ai_declaration".to_string(), serde_json::json!({
        "disclosure_required": true,
        "ai_generated": false,
        "ai_manipulated": false,
        "human_reviewed": false,
        "standard_editing": true
    }));
    let m = Manifest { core, extensions: ext };
    let result = verify_manifest(asset, &m, &VerifyOptions::default()).unwrap();
    assert!(!result.success, "TV-22 must fail");
    assert!(result.message.contains("standard_editing"), "Expected 'standard_editing' in: {}", result.message);
}

#[test]
fn tv24_4kb_exceeded() {
    let asset = b"TV-24 exceeded test";
    let core = make_core(asset);
    let mut ext = BTreeMap::new();
    ext.insert("padding".to_string(), Value::String("x".repeat(MAX_EXTENSION_SIZE_BYTES)));
    let m = Manifest { core, extensions: ext };
    let result = verify_manifest(asset, &m, &VerifyOptions::default()).unwrap();
    assert!(!result.success, "TV-24 must fail");
    assert!(result.message.contains("4096"), "Expected '4096' in: {}", result.message);
}

#[test]
fn tv25_compliance_eu_art50() {
    let asset = b"TV-25 compliance_eu_art50 test";
    let core = make_core(asset);

    // Case A: compliance_eu_art50 present — no warning about the field expected
    let mut ext_a = BTreeMap::new();
    ext_a.insert("ai_declaration".to_string(), serde_json::json!({
        "disclosure_required": true,
        "ai_generated": true,
        "ai_manipulated": false,
        "human_reviewed": true
    }));
    ext_a.insert("compliance_eu_art50".to_string(), serde_json::json!({
        "editorial_responsibility": "Test Organisation",
        "review_type": "substantive"
    }));
    let m_a = Manifest { core: core.clone(), extensions: ext_a };
    let result_a = verify_manifest(asset, &m_a, &VerifyOptions::default()).unwrap();
    assert!(result_a.success, "TV-25 Case A failed: {}", result_a.message);
    for w in &result_a.warnings {
        assert!(!w.contains("compliance_eu_art50"),
            "TV-25 Case A: unexpected warning: {w}");
    }

    // Case B: human_reviewed=true but compliance_eu_art50 absent — warning expected, not failure
    let mut ext_b = BTreeMap::new();
    ext_b.insert("ai_declaration".to_string(), serde_json::json!({
        "disclosure_required": true,
        "ai_generated": true,
        "ai_manipulated": false,
        "human_reviewed": true
    }));
    let core_b = make_core(asset);
    let m_b = Manifest { core: core_b, extensions: ext_b };
    let result_b = verify_manifest(asset, &m_b, &VerifyOptions::default()).unwrap();
    assert!(result_b.success, "TV-25 Case B must pass (warning not failure): {}", result_b.message);
    let found = result_b.warnings.iter().any(|w| w.contains("compliance_eu_art50"));
    assert!(found, "TV-25 Case B: expected warning about missing compliance_eu_art50");
}
// -- end aioschema/rust v0.5.6 | AIOSchema spec v0.5.6 --
