// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ovidiu Ancuta
//
// aioschema/rust v0.5.6 | AIOSchema spec v0.5.6
// https://aioschema.org

use aioschema::{
    algorithms::canonical_core_fields,
    canonical_json, compute_hash, parse_hash_prefix, verify_manifest, Manifest,
    VerifyOptions, CORE_HASH_FIELDS,
};
use base64;
use base64::Engine;
use hex;
use serde::Deserialize;
use serde_json::Value;
use std::path::PathBuf;

// ── Vector file types ─────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct VectorFile {
    spec_version: String,
    vectors:      Vec<Vector>,
}

#[derive(Deserialize)]
struct Vector {
    id:          String,
    name:        String,
    inputs:      Value,
    expected:    Value,
}

// ── Loader ────────────────────────────────────────────────────────────────────

fn load_vectors() -> VectorFile {
    // Prefer explicit env var
    if let Ok(p) = std::env::var("AIOSCHEMA_VECTORS") {
        let data = std::fs::read_to_string(&p)
            .unwrap_or_else(|e| panic!("cannot read AIOSCHEMA_VECTORS={p}: {e}"));
        return serde_json::from_str(&data).expect("parse vectors JSON");
    }

    // Probe relative paths from CARGO_MANIFEST_DIR
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let candidates = [
        manifest_dir.join("../../cross_verify_vectors.json"),
        manifest_dir.join("../cross_verify_vectors.json"),
        manifest_dir.join("cross_verify_vectors.json"),
        PathBuf::from("cross_verify_vectors.json"),
    ];
    for path in &candidates {
        if path.exists() {
            let data = std::fs::read_to_string(path)
                .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
            return serde_json::from_str(&data).expect("parse vectors JSON");
        }
    }
    panic!(
        "cross_verify_vectors.json not found; \
         set AIOSCHEMA_VECTORS env var to its path"
    );
}

// ── Main test ─────────────────────────────────────────────────────────────────

#[test]
fn test_cross_verify_all_vectors() {
    let vf = load_vectors();
    eprintln!(
        "Loaded {} vectors (spec_version={})",
        vf.vectors.len(),
        vf.spec_version
    );
    assert!(vf.vectors.len() >= 14, "expected at least 14 CV vectors");

    let mut failures = 0usize;

    for v in &vf.vectors {
        let ok = match v.id.as_str() {
            "CV-01" | "CV-02" | "CV-03" | "CV-04" => run_hash_vector(v),
            "CV-05"                                => run_canonical_json_vector(v),
            "CV-06"                                => run_core_fingerprint_vector(v),
            id if id.starts_with("CV-")            => run_manifest_verify_vector(v),
            _                                      => {
                eprintln!("UNKNOWN vector id {}", v.id);
                false
            }
        };
        if ok {
            eprintln!("  PASS  {} — {}", v.id, v.name);
        } else {
            eprintln!("  FAIL  {} — {}", v.id, v.name);
            failures += 1;
        }
    }

    assert_eq!(failures, 0, "{failures} vector(s) failed");
}

// ── CV-01..CV-04: Hash computation ───────────────────────────────────────────

fn run_hash_vector(v: &Vector) -> bool {
    let data_hex = v.inputs["data_hex"].as_str().unwrap_or("");
    let algorithm = v.inputs["algorithm"].as_str().unwrap();
    let expected  = v.expected.as_str().unwrap();

    let data = hex::decode(data_hex).expect("decode data_hex");
    match compute_hash(&data, algorithm) {
        Ok(got) => {
            if got != expected {
                eprintln!("    got  {got}");
                eprintln!("    want {expected}");
                false
            } else {
                true
            }
        }
        Err(e) => {
            eprintln!("    ComputeHash error: {e}");
            false
        }
    }
}

// ── CV-05: Canonical JSON ─────────────────────────────────────────────────────

fn run_canonical_json_vector(v: &Vector) -> bool {
    let obj      = &v.inputs["object"];
    let expected = v.expected.as_str().unwrap();

    match canonical_json(obj) {
        Ok(bytes) => {
            let got = String::from_utf8(bytes).unwrap();
            if got != expected {
                eprintln!("    got  {got}");
                eprintln!("    want {expected}");
                false
            } else {
                true
            }
        }
        Err(e) => {
            eprintln!("    CanonicalJSON error: {e}");
            false
        }
    }
}

// ── CV-06: core_fingerprint ───────────────────────────────────────────────────

fn run_core_fingerprint_vector(v: &Vector) -> bool {
    let core_fields = &v.inputs["core_fields"];
    let expected    = v.expected.as_str().unwrap();

    // Determine algorithm from expected value
    let (alg, _) = match parse_hash_prefix(expected) {
        Ok(pair) => pair,
        Err(e) => {
            eprintln!("    parse expected hash: {e}");
            return false;
        }
    };

    // Build a Value::Object containing only CORE_HASH_FIELDS
    let mut subset = serde_json::Map::new();
    if let Some(obj) = core_fields.as_object() {
        for &field in CORE_HASH_FIELDS {
            if let Some(val) = obj.get(field) {
                subset.insert(field.to_string(), val.clone());
            }
        }
    }
    let subset_val = Value::Object(subset);

    let canonical = match canonical_core_fields(&subset_val) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("    canonical_core_fields error: {e}");
            return false;
        }
    };

    match compute_hash(&canonical, alg) {
        Ok(got) => {
            if got != expected {
                eprintln!("    got  {got}");
                eprintln!("    want {expected}");
                false
            } else {
                true
            }
        }
        Err(e) => {
            eprintln!("    ComputeHash error: {e}");
            false
        }
    }
}

// ── CV-07..CV-18: Manifest verification ────────────────────────────────────

fn run_manifest_verify_vector(v: &Vector) -> bool {
    let asset_hex     = v.inputs["asset_hex"].as_str().unwrap();
    let manifest_val  = &v.inputs["manifest"];
    let exp_success   = v.expected["success"].as_bool().unwrap();

    let asset_data = match hex::decode(asset_hex) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("    decode asset_hex: {e}");
            return false;
        }
    };

    let manifest: Manifest = match serde_json::from_value(manifest_val.clone()) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("    deserialize manifest: {e}");
            if !exp_success {
                return true;
            }
            return false;
        }
    };

    // Decode public key if provided
    let pub_key_bytes: Option<Vec<u8>> = v.inputs
        .get("public_key_b64")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(|s| base64::engine::general_purpose::STANDARD.decode(s).unwrap());
    let opts = VerifyOptions {
        public_key: pub_key_bytes.as_deref(),
        ..VerifyOptions::default()
    };

    let result = match verify_manifest(&asset_data, &manifest, &opts) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("    verify_manifest returned Err: {e}");
            return false;
        }
    };

    if result.success != exp_success {
        eprintln!(
            "    success={} (want {}): {}",
            result.success, exp_success, result.message
        );
        return false;
    }

    // If vector specifies match_type, check it when successful
    if let Some(exp_mt) = v.expected.get("match_type").and_then(|v| v.as_str()) {
        if result.success {
            let got_mt = result
                .match_type
                .as_ref()
                .map(|m| m.to_string())
                .unwrap_or_default();
            if got_mt != exp_mt {
                eprintln!("    match_type={got_mt} (want {exp_mt})");
                return false;
            }
        }
    }

    // If vector specifies message_contains, check it
    if let Some(exp_msg) = v.expected.get("message_contains").and_then(|v| v.as_str()) {
        if !result.message.contains(exp_msg) {
            eprintln!("    message does not contain {exp_msg}: {}", result.message);
            return false;
        }
    }

    true
}
// -- end aioschema/rust v0.5.6 | AIOSchema spec v0.5.6 --
