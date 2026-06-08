// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ovidiu Ancuta
//
// aioschema/rust v0.5.6 | AIOSchema spec v0.5.6
// https://aioschema.org

use crate::algorithms::{
    canonical_core_fields, canonical_manifest_bytes, compute_hash,
    parse_hash_prefix, safe_equal, CREATOR_ID_ATTRIBUTED_PATTERN, HASH_PATTERN,
    SIGNATURE_PATTERN, TIMESTAMP_PATTERN, UUID_PATTERN,
};
use crate::types::{
    AiosError, MatchType, VerificationResult, VerifyOptions, Manifest,
    SOFT_BINDING_THRESHOLD_DEFAULT, SOFT_BINDING_THRESHOLD_MAX, SUPPORTED_VERSIONS,
    MAX_EXTENSION_SIZE_BYTES,
};
use ed25519_dalek::{Signature, VerifyingKey};
use serde_json::Value;
use sha2::{Digest, Sha256};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};

/// Execute the AIOSchema §10 verification procedure.
pub fn verify_manifest(
    asset_data: &[u8],
    manifest: &Manifest,
    opts: &VerifyOptions<'_>,
) -> Result<VerificationResult, AiosError> {
    let mut warns: Vec<String> = Vec::new();

    let threshold = opts
        .soft_binding_threshold
        .unwrap_or(SOFT_BINDING_THRESHOLD_DEFAULT)
        .min(SOFT_BINDING_THRESHOLD_MAX);

    let core = &manifest.core;
    let ext = &manifest.extensions;

    // §6.3 — Extension size limit
    if !ext.is_empty() {
        let ext_json = serde_json::to_vec(ext)
            .map_err(|e| AiosError::Other(e.to_string()))?;
        if ext_json.len() > MAX_EXTENSION_SIZE_BYTES {
            return Ok(VerificationResult {
                success: false,
                message: format!(
                    "extensions size ({} bytes) exceeds limit of {} bytes (§6.3)",
                    ext_json.len(), MAX_EXTENSION_SIZE_BYTES
                ),
                match_type: None,
                signature_verified: false,
                manifest_signature_verified: false,
                anchor_checked: false,
                anchor_verified: false,
                warnings: warns,
            });
        }
    }

    // §11.1 — ai_declaration constraint validation
    if !ext.is_empty() {
        if let Some(ai_decl) = ext.get("ai_declaration") {
            if let Some(decl) = ai_decl.as_object() {
                let standard_editing = decl.get("standard_editing").and_then(|v| v.as_bool()).unwrap_or(false);
                let disclosure_required = decl.get("disclosure_required").and_then(|v| v.as_bool()).unwrap_or(false);
                if standard_editing && disclosure_required {
                    return Ok(VerificationResult {
                        success: false,
                        message: "ai_declaration constraint violation: standard_editing is true but disclosure_required is also true. Per Article 50.2, standard editing does not trigger AI disclosure obligations.".to_string(),
                        match_type: None,
                        signature_verified: false,
                        manifest_signature_verified: false,
                        anchor_checked: false,
                        anchor_verified: false,
                        warnings: warns,
                    });
                }
                let human_reviewed = decl.get("human_reviewed").and_then(|v| v.as_bool()).unwrap_or(false);
                if human_reviewed {
                    let has_art50 = ext.get("compliance_eu_art50").is_some();
                    if !has_art50 {
                        warns.push("ai_declaration.human_reviewed is true but compliance_eu_art50 extension is absent (SHOULD be present per §11.1)".to_string());
                    }
                }
            }
        }
    }

    // §11.3 — public_key fingerprint cross-check
    let mut embedded_public_key: Option<Vec<u8>> = None;
    if !ext.is_empty() {
        if let Some(pk_b64) = ext.get("public_key").and_then(|v| v.as_str()) {
            match BASE64.decode(pk_b64) {
                Ok(pk_bytes) => {
                    if pk_bytes.len() != 32 {
                        return Ok(VerificationResult {
                            success: false,
                            message: format!("extensions.public_key decoded to {} bytes, expected 32 (Ed25519)", pk_bytes.len()),
                            match_type: None,
                            signature_verified: false,
                            manifest_signature_verified: false,
                            anchor_checked: false,
                            anchor_verified: false,
                            warnings: warns,
                        });
                    }
                    let mut hasher = Sha256::new();
                    hasher.update(&pk_bytes);
                    let hash = hasher.finalize();
                    let fp_hex = hex::encode(&hash[..16]);
                    let expected_creator_id = format!("ed25519-fp-{}", fp_hex);
                    if !safe_equal(&core.creator_id, &expected_creator_id) {
                        return Ok(VerificationResult {
                            success: false,
                            message: format!(
                                "extensions.public_key fingerprint cross-check failed: embedded key does not belong to declared creator_id. Expected ed25519-fp derived from key: {}, manifest creator_id: {}",
                                expected_creator_id, core.creator_id
                            ),
                            match_type: None,
                            signature_verified: false,
                            manifest_signature_verified: false,
                            anchor_checked: false,
                            anchor_verified: false,
                            warnings: warns,
                        });
                    }
                    embedded_public_key = Some(pk_bytes);
                }
                Err(_) => {
                    return Ok(VerificationResult {
                        success: false,
                        message: "extensions.public_key is not valid Base64".to_string(),
                        match_type: None,
                        signature_verified: false,
                        manifest_signature_verified: false,
                        anchor_checked: false,
                        anchor_verified: false,
                        warnings: warns,
                    });
                }
            }
        }
    }

    // §10 Step 1 — Schema version
    if !SUPPORTED_VERSIONS.contains(&core.schema_version.as_str()) {
        return Ok(VerificationResult::fail(format!(
            "unsupported schema_version {:?}; supported: {}",
            core.schema_version,
            SUPPORTED_VERSIONS.join(", ")
        )));
    }

    // §10 Step 2 — Required fields presence
    if core.asset_id.is_empty() {
        return Ok(VerificationResult::fail("missing required field: asset_id"));
    }
    if core.creation_timestamp.is_empty() {
        return Ok(VerificationResult::fail("missing required field: creation_timestamp"));
    }
    if core.creator_id.is_empty() {
        return Ok(VerificationResult::fail("missing required field: creator_id"));
    }
    if core.hash_original.as_slice().is_empty() {
        return Ok(VerificationResult::fail("missing required field: hash_original"));
    }

    // §10 Step 3 — Timestamp format
    if !TIMESTAMP_PATTERN.is_match(&core.creation_timestamp) {
        return Ok(VerificationResult::fail(format!(
            "creation_timestamp {:?} is not a valid UTC ISO-8601 timestamp (must end with Z)",
            core.creation_timestamp
        )));
    }

    // §10 Step 4 — creator_id format
    let cid = &core.creator_id;
    if !CREATOR_ID_ATTRIBUTED_PATTERN.is_match(cid) && !UUID_PATTERN.is_match(cid) {
        return Ok(VerificationResult::fail(format!(
            "creator_id {cid:?} has invalid format"
        )));
    }

    // §10 Step 5 — hash_original format
    for h in core.hash_original.as_slice() {
        if !HASH_PATTERN.is_match(h) {
            return Ok(VerificationResult::fail(format!(
                "hash_original value {h:?} has invalid format"
            )));
        }
    }

    // §10 Step 6
    let core_value: Value = serde_json::to_value(core)?;

    // §10 Step 7 — Content hash verification (hard match)
    let mut hard_match = false;
    let mut supported_found = false;

    for h in core.hash_original.as_slice() {
        let (alg, _) = match parse_hash_prefix(h) {
            Ok(pair) => pair,
            Err(_) => {
                warns.push(format!("skipping malformed hash {h:?}"));
                continue;
            }
        };
        supported_found = true;
        let computed = match compute_hash(asset_data, alg) {
            Ok(c) => c,
            Err(_) => {
                warns.push(format!("hash algorithm {alg:?} not supported, skipping"));
                continue;
            }
        };
        if safe_equal(&computed, h) {
            hard_match = true;
            break;
        }
    }

    if !supported_found {
        return Ok(VerificationResult::fail(
            "no supported hash algorithm found in hash_original; cannot verify content",
        ));
    }

    // §10 Step 8 — Soft binding fallback
    let soft_match = false;
    if !hard_match {
        if manifest.extensions.contains_key("soft_binding") {
            warns.push(format!(
                "soft_binding present but not evaluated \
                 (image processing not available; threshold={threshold})"
            ));
        }
    }

    // §10 Step 9
    if !hard_match && !soft_match {
        return Ok(VerificationResult::fail(
            "content mismatch: hash did not match asset. Asset may be tampered or replaced.",
        ));
    }

    let match_type = if hard_match { MatchType::Hard } else { MatchType::Soft };

    // §10 Step 10 — core_fingerprint integrity
    let cfp_val = match core.effective_core_fingerprint() {
        Some(v) => v,
        None => {
            return Ok(VerificationResult {
                success: false,
                message: "missing required field: core_fingerprint".to_string(),
                match_type: Some(match_type),
                signature_verified: false,
                manifest_signature_verified: false,
                anchor_checked: false,
                anchor_verified: false,
                warnings: warns,
            });
        }
    };

    let (cfp_alg, _) = match parse_hash_prefix(cfp_val) {
        Ok(pair) => pair,
        Err(e) => {
            return Ok(VerificationResult {
                success: false,
                message: format!("core_fingerprint has invalid format: {e}"),
                match_type: Some(match_type),
                signature_verified: false,
                manifest_signature_verified: false,
                anchor_checked: false,
                anchor_verified: false,
                warnings: warns,
            });
        }
    };

    let core_field_bytes = canonical_core_fields(&core_value)?;
    let computed_cfp = compute_hash(&core_field_bytes, cfp_alg)?;

    if !safe_equal(&computed_cfp, cfp_val) {
        return Ok(VerificationResult {
            success: false,
            message: "manifest integrity check failed: core_fingerprint mismatch. \
                         Core metadata may have been tampered."
                .to_string(),
            match_type: Some(match_type),
            signature_verified: false,
            manifest_signature_verified: false,
            anchor_checked: false,
            anchor_verified: false,
            warnings: warns,
        });
    }

    // §10 Step 11 — Core signature verification (§11.3: prefer embedded key)
    let mut signature_verified = false;
    if let Some(sig_str) = &core.signature {
        if !SIGNATURE_PATTERN.is_match(sig_str) {
            return Ok(VerificationResult {
                success: false,
                message: "signature has invalid format; expected ed25519-<128hex>".to_string(),
                match_type: Some(match_type),
                signature_verified: false,
                manifest_signature_verified: false,
                anchor_checked: false,
                anchor_verified: false,
                warnings: warns,
            });
        }
        // Resolve verification key: external > embedded > error
        let pub_bytes: &[u8] = match opts.public_key {
            Some(b) => b,
            None => match &embedded_public_key {
                Some(emb) => emb.as_slice(),
                None => {
                    return Ok(VerificationResult {
                        success: false,
                        message: "manifest is signed but no public key was provided (neither externally nor via extensions.public_key)".to_string(),
                        match_type: Some(match_type),
                        signature_verified: false,
                        manifest_signature_verified: false,
                        anchor_checked: false,
                        anchor_verified: false,
                        warnings: warns,
                    });
                }
            }
        };
        let vk = verifying_key(pub_bytes).map_err(|e| AiosError::Other(e.to_string()))?;
        let sig = parse_ed25519_sig(&sig_str["ed25519-".len()..])?;
        match vk.verify_strict(&core_field_bytes, &sig) {
            Ok(()) => signature_verified = true,
            Err(_) => {
                return Ok(VerificationResult {
                    success: false,
                    message: "core signature verification failed: invalid signature or wrong key"
                        .to_string(),
                    match_type: Some(match_type),
                    signature_verified: false,
                    manifest_signature_verified: false,
                    anchor_checked: false,
                    anchor_verified: false,
                    warnings: warns,
                });
            }
        }
    }

    // §10 Step 12 — Manifest signature verification (§11.3: prefer embedded key)
    let mut manifest_sig_verified = false;
    if let Some(msig_str) = &core.manifest_signature {
        if !SIGNATURE_PATTERN.is_match(msig_str) {
            return Ok(VerificationResult {
                success: false,
                message: "manifest_signature has invalid format; expected ed25519-<128hex>"
                    .to_string(),
                match_type: Some(match_type),
                signature_verified: false,
                manifest_signature_verified: false,
                anchor_checked: false,
                anchor_verified: false,
                warnings: warns,
            });
        }
        // Resolve verification key: external > embedded > error
        let pub_bytes: &[u8] = match opts.public_key {
            Some(b) => b,
            None => match &embedded_public_key {
                Some(emb) => emb.as_slice(),
                None => {
                    return Ok(VerificationResult {
                        success: false,
                        message: "manifest_signature present but no public key was provided (neither externally nor via extensions.public_key)".to_string(),
                        match_type: Some(match_type),
                        signature_verified: false,
                        manifest_signature_verified: false,
                        anchor_checked: false,
                        anchor_verified: false,
                        warnings: warns,
                    });
                }
            }
        };
        let vk = verifying_key(pub_bytes).map_err(|e| AiosError::Other(e.to_string()))?;
        let sig = parse_ed25519_sig(&msig_str["ed25519-".len()..])?;

        let manifest_value: Value = serde_json::to_value(manifest)?;
        let m_bytes = canonical_manifest_bytes(&manifest_value)?;

        match vk.verify_strict(&m_bytes, &sig) {
            Ok(()) => manifest_sig_verified = true,
            Err(_) => {
                return Ok(VerificationResult {
                    success: false,
                    message: "manifest signature verification failed: invalid or extensions tampered"
                        .to_string(),
                    match_type: Some(match_type),
                    signature_verified: false,
                    manifest_signature_verified: false,
                    anchor_checked: false,
                    anchor_verified: false,
                    warnings: warns,
                });
            }
        }
    }

    // §10 Step 13 — Anchor verification
    let mut anchor_checked = false;
    let mut anchor_verified = false;

    if let Some(anchor) = &core.anchor_reference {
        if !anchor.is_empty() {
            if opts.verify_anchor {
                if let Some(resolver) = opts.resolver {
                    anchor_checked = true;
                    match resolver(anchor) {
                        Err(e) => {
                            warns.push(format!("anchor verification error: {e}"));
                        }
                        Ok(None) => {
                            warns.push(format!("anchor record not found: {anchor:?}"));
                        }
                        Ok(Some(record)) => {
                            let id_match = safe_equal(&record.asset_id, &core.asset_id);
                            let cfp_match = safe_equal(&record.core_fingerprint, cfp_val);
                            if id_match && cfp_match {
                                anchor_verified = true;
                            } else {
                                warns.push(format!(
                                    "anchor record mismatch for {anchor:?}. Asset may have been re-signed."
                                ));
                            }
                        }
                    }
                }
            } else {
                warns.push(format!(
                    "anchor_reference present ({anchor:?}) but not verified. \
                     Pass verify_anchor=true and resolver= for Level 3 compliance."
                ));
            }
        }
    }

    // §10 Step 14 — Build success result
    let content_desc = if soft_match { "perceptual (soft)" } else { "bit-exact" };
    let sig_desc = match (signature_verified, manifest_sig_verified) {
        (true, true) => "core + manifest signatures verified",
        (true, false) => "core signature verified",
        _ => "unsigned",
    };

    Ok(VerificationResult {
        success:                     true,
        message:                     format!(
            "Verified: {content_desc} content match, {sig_desc}. Provenance intact."
        ),
        match_type:                  Some(match_type),
        signature_verified,
        manifest_signature_verified: manifest_sig_verified,
        anchor_checked,
        anchor_verified,
        warnings:                    warns,
    })
}

// ── Ed25519 helpers ───────────────────────────────────────────────────────────

fn verifying_key(bytes: &[u8]) -> Result<VerifyingKey, String> {
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| format!("public key must be 32 bytes, got {}", bytes.len()))?;
    VerifyingKey::from_bytes(&arr).map_err(|e| e.to_string())
}

fn parse_ed25519_sig(hex_str: &str) -> Result<Signature, AiosError> {
    let bytes = hex::decode(hex_str)?;
    let arr: [u8; 64] = bytes
        .try_into()
        .map_err(|_| AiosError::Other("ed25519 signature must be 64 bytes".to_string()))?;
    Ok(Signature::from_bytes(&arr))
}
// -- end aioschema/rust v0.5.6 | AIOSchema spec v0.5.6 --
