<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 Ovidiu Ancuta -->
<!--
     AIOSchema v0.5.6 Conformance Test Vector Registry
     https://aioschema.org
-->

# AIOSchema v0.5.6 Conformance Test Vector Registry

This document maps the canonical test vector identifiers (TV-01 through TV-25) to their
implementations in all six reference test suites, and to the cross-verification
deterministic vectors (CV-01 through CV-18).

Any conforming AIOSchema v0.5.6 implementation must pass all 25 test vectors to be
considered spec-compliant.

---

## v0.4 Test Vectors (TV-01 to TV-12)

| ID | Description | Python | TypeScript | Node.js | Go | Rust |
|---|---|---|---|---|---|---|
| TV-01 | Valid L1 manifest: all required fields present, `hash_original` correct, `core_fingerprint` correct. Unsigned. | `test_tv01_valid_roundtrip` | `verifyManifest passes on correct asset` | `TV-01: Valid manifest roundtrip` | `TestVerifyManifest_ValidHardMatch` | `verify_valid_hard_match` |
| TV-02 | `hash_original` wrong (single byte changed). Must fail with hash mismatch. | `test_tv02_tampered_hash_original` | `verifyManifest fails on tampered hash_original` | `TV-02: Tampered hash_original fails` | `TestVerifyManifest_TamperedHashOriginal` | `verify_tampered_hash_original` |
| TV-03 | `hash_original` correct but `core_fingerprint` tampered. Must fail fingerprint check. | `test_tv03_tampered_core_fingerprint` | `verifyManifest fails on tampered core_fingerprint` | `TV-03: Tampered core_fingerprint fails` | `TestVerifyManifest_TamperedCoreFingerprint` | `verify_tampered_core_fingerprint` |
| TV-04 | Soft binding: pHash distance=0, within threshold=5. Must pass with `match_type="soft"`. | `test_tv04_soft_match_within_threshold` | `verifyManifest soft binding fallback on transformed asset` | `TV-04: Soft binding skipped` | *(image processing not available)* | *(image processing not available)* |
| TV-05 | Soft binding: pHash distance=60, exceeds threshold=5. Must fail. | `test_tv05_soft_match_outside_threshold` | *(covered by TV-02 path)* | `TV-05: Soft binding skipped` | *(image processing not available)* | *(image processing not available)* |
| TV-06 | Valid L2 manifest with Ed25519 `signature` and `manifest_signature`. Both must verify. | `test_tv06_signature_success` | *(covered by TV-07 inverse)* | `TV-06: Valid signature passes` | *(covered by TV-07 inverse)* | *(covered by TV-07 inverse)* |
| TV-07 | Same signed manifest as TV-06 but verifier supplies a different public key. Must fail. | `test_tv07_signature_wrong_key` | `TV-07: Signature wrong key — must not verify` | `TV-07: Wrong public key fails` | `TestVerifyManifest_SignatureWrongKey` | `verify_signature_wrong_key` |
| TV-08 | Unsigned manifest (`signature=null`, `manifest_signature=null`). Must pass; `signature_verified=false`. | `test_tv08_null_signature_unsigned_pass` | `verifyManifest passes on correct asset` | `TV-08: Unsigned manifest passes` | `TestVerifyManifest_UnsignedPassesWithoutKey` | `verify_unsigned_passes_without_key` |
| TV-09 | `creator_id` field absent. Must fail with missing required field error. | `test_tv09_missing_required_fields` | `verifyManifest fails on tampered core_fingerprint` | `TV-09: Missing required fields fail` | `TestVerifyManifest_MissingCreatorID` | `verify_missing_creator_id` |
| TV-10 | `creation_timestamp` has no trailing `Z` (not UTC). Must fail. | `test_tv10_invalid_timestamp` | `verifyManifest rejects invalid asset_id` | `TV-10: Invalid timestamp rejected` | `TestVerifyManifest_InvalidTimestamp` | `verify_invalid_timestamp` |
| TV-11 | `creation_timestamp` uses timezone offset (`+02:00`) instead of UTC `Z`. Must fail. | `test_tv11_non_utc_timestamp` | `TV-11: Non-UTC timestamp (+02:00 offset) rejected` | `TV-11: Non-UTC timestamp rejected` | `TestVerifyManifest_NonUTCTimestamp` | `verify_non_utc_timestamp` |
| TV-12 | `schema_version` `"0.9"` is not in the supported version list. Must fail. | `test_tv12_unknown_schema_version` | `verifyManifest rejects unsupported schema_version` | `TV-12: Unknown schema_version rejected` | `TestVerifyManifest_UnsupportedSchemaVersion` | `verify_unsupported_schema_version` |

---

## v0.5 Test Vectors (TV-13 to TV-18)

| ID | Description | Python | TypeScript | Node.js | Go | Rust |
|---|---|---|---|---|---|---|
| TV-13 | Multi-hash manifest (SHA-256 + SHA-384). Part A: both correct, must pass. Part B: SHA-256 wrong, SHA-384 correct, must still pass (any match succeeds). | `test_tv13_multi_hash_manifest` | `generateManifest multi-algorithm produces array` | `TV-13: Multi-hash manifest` | *(covered by CV-11)* | `verify_multi_hash` |
| TV-14 | `manifest_signature` covers core + extensions. Valid signature with extensions present. `manifest_signature_verified` must be true. | `test_tv14_manifest_signature_valid` | *(see TV-15 inverse)* | `TV-14: manifest_signature valid` | *(covered by TV-15 inverse)* | *(covered by TV-15 inverse)* |
| TV-15 | Same as TV-14 but `extensions.license` tampered after signing. `manifest_signature` must fail. | `test_tv15_manifest_signature_extensions_tampered` | `TV-15: manifest_signature invalidated by extensions tampering` | `TV-15: manifest_signature tampered fails` | *(covered by CV-09 path)* | *(covered by CV-09 path)* |
| TV-16 | Single SHA-384 hash (no SHA-256). Must verify correctly. | `test_tv16_sha384_single_hash` | `generateManifest hash_original has sha256 prefix by default` | `TV-16: SHA-384 manifest` | *(covered by CV-02)* | *(covered by CV-02)* |
| TV-17 | L3 manifest with `anchor_reference` present and matching `anchor_record` supplied. `anchor_verified` must be true. | `test_tv17_anchor_verified_success` | `verifyManifest with anchor_resolver verifies anchor` | `TV-17: Anchor verified` | *(anchor resolver not implemented)* | *(anchor resolver not implemented)* |
| TV-18 | Same L3 manifest as TV-17 but `verify_anchor=false`. Must pass with `anchor_verified=false` and a warning. | `test_tv18_anchor_present_not_verified_warning` | `TV-18: anchor present, verifyAnchor=false — warning not failure` | `TV-18: Anchor present no verify — warning` | `TestVerifyManifest_AnchorWarningNotFailure` | `verify_anchor_warning_not_failure` |

---

## v0.5.6 Test Vectors (TV-19 to TV-25)

These vectors cover features canonicalized in v0.5.6: public key binding, `ai_declaration`
constraints, extension size limits, and `compliance_eu_art50`.

| ID | Category | Description | Python | TypeScript | Node.js | Go | Rust | .NET |
|---|---|---|---|---|---|---|---|---|
| TV-19 | public-key | `extensions.public_key` fingerprint matches `creator_id`; both signatures must verify | `TestTV19_PublicKeyFingerprintMatch` | `testTV19` | `TV-19: public_key fingerprint match` | `TestTV19_PublicKeyFingerprintMatch` | `tv19_public_key_fingerprint_match` | `RunTV19()` |
| TV-20 | public-key | `extensions.public_key` fingerprint does NOT match `creator_id`; MUST fail | `TestTV20_PublicKeyFingerprintMismatch` | `testTV20` | `TV-20: public_key fingerprint mismatch` | `TestTV20_PublicKeyFingerprintMismatch` | `tv20_public_key_fingerprint_mismatch` | `RunTV20()` |
| TV-21 | ai-declaration | `disclosure_required=true`, `ai_generated=true`, `human_reviewed=true`, `standard_editing=false`; constraint satisfied; MUST pass | `TestTV21_AiDeclarationValid` | `testTV21` | `TV-21: ai_declaration valid` | `TestTV21_AiDeclarationValid` | `tv21_ai_declaration_valid` | `RunTV21()` |
| TV-22 | ai-declaration | `standard_editing=true` AND `disclosure_required=true`; violates §11.1 constraint; MUST fail | `TestTV22_AiDeclarationStandardEditingConflict` | `testTV22` | `TV-22: standard_editing conflict fails` | `TestTV22_AiDeclarationStandardEditingConflict` | `tv22_ai_declaration_standard_editing_conflict` | `RunTV22()` |
| TV-23 | extension-size | Extensions serialized to exactly 4096 bytes; MUST pass | `TestTV23_ExtensionSizeAtLimit` | `testTV23` | `TV-23: extensions at 4096 bytes pass` | `TestTV23_ExtensionSizeAtLimit` | `tv23_extension_size_at_limit` | `RunTV23()` |
| TV-24 | extension-size | Extensions serialized to 4097 bytes, one byte over limit; MUST fail | `TestTV24_ExtensionSizeOverLimit` | `testTV24` | `TV-24: extensions over 4096 bytes fail` | `TestTV24_ExtensionSizeOverLimit` | `tv24_extension_size_over_limit` | `RunTV24()` |
| TV-25 | compliance | `extensions.compliance_eu_art50` present; `human_reviewed=true`; MUST emit warning | `TestTV25_ComplianceEuArt50` | `testTV25` | `TV-25: compliance_eu_art50 warning` | `TestTV25_ComplianceEuArt50` | `tv25_compliance_eu_art50` | `RunTV25()` |

---

## Cross-Implementation Deterministic Vectors (CV-01 to CV-18)

These vectors use fixed inputs so all six implementations must produce byte-for-byte
identical outputs. They live in `conformance/cross_verify_vectors.json` and are run by
each language's cross-verify module.

| ID | Description | Expected output |
|---|---|---|
| CV-01 | SHA-256 of `"The quick brown fox..."` | `sha256-d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592` |
| CV-02 | SHA-384 of `"The quick brown fox..."` | `sha384-ca737f1014a48f4c0b6dd43cb177b0afd9e5169367544c494011e3317dbf9a509cb1e5dc1e85a941bbee3d7f2afbc9b1` |
| CV-03 | SHA-256 of empty bytes | `sha256-e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| CV-04 | SHA-256 of bytes 0x00 to 0xFF | See `cross_verify_vectors.json` |
| CV-05 | Canonical JSON of known object | Compact, sorted keys, no whitespace |
| CV-06 | `core_fingerprint` of known core fields | See `cross_verify_vectors.json` |
| CV-07 | Deterministic manifest verification (fixed inputs) | `success: true, match_type: "hard"` |
| CV-08 | Tampered `hash_original` fails | `success: false` |
| CV-09 | Tampered `core_fingerprint` fails | `success: false` |
| CV-10 | `hash_schema_block` alias accepted | `success: true` |
| CV-11 | Multi-hash array verification | `success: true` |
| CV-12 | Unsupported `schema_version` fails | `success: false` |
| CV-13 | Missing required field (`creator_id`) fails | `success: false` |
| CV-14 | Invalid timestamp format fails | `success: false` |
| CV-15 | `extensions.public_key` fingerprint match | `success: true, public_key_fingerprint_match: true` |
| CV-16 | `extensions.public_key` fingerprint mismatch fails | `success: false` |
| CV-17 | `ai_declaration` `standard_editing` constraint violation fails | `success: false` |
| CV-18 | Extensions serialized size at boundary (4096 bytes) passes | `success: true` |

The canonical shared vectors file with all 18 vectors lives at:
`conformance/cross_verify_vectors.json`

Each implementation carries a local copy. All local copies must match the canonical file.

---

## Test suite counts

| Suite | Language | Unit tests | CV vectors | Status |
|---|---|---|---|---|
| `test_aioschema_v056.py` | Python | 117 | 18/18 | All passing |
| `test_aioschema_v056.ts` | TypeScript | 70+ | 18/18 | All passing |
| `unit_tests_node.js` | Node.js | 36 | 18/18 | All passing |
| `aioschema_test.go` + `cross_verify_test.go` | Go | 27+ | 18/18 | All passing |
| `unit_tests.rs` + `cross_verify.rs` | Rust | 30+ | 18/18 | All passing |
| `TestSuite.cs` + `CrossVerify.cs` | .NET (C#) | 56 unit + 62 suite | 18/18 | All passing |

---

## Bootstrap rule verification

All six suites independently verify the bootstrap rule: `core_fingerprint` is **not**
included in the set of fields used to compute `core_fingerprint`.

```
CORE_HASH_FIELDS = [
  "asset_id",
  "schema_version",
  "creation_timestamp",
  "hash_original",
  "creator_id"
]
```

Confirmed by:
- Python: `test_core_hash_fields_bootstrap_rule`
- TypeScript: `XC-08`
- Node.js: `TV-03` path (core_fingerprint tamper detection)
- Go: `TestCoreHashFields_BootstrapRule`
- Rust: `core_hash_fields_bootstrap_rule`
- .NET: `TestCoreHashFields_BootstrapRule`

---

## Adding new test vectors

When a new spec version introduces behavior changes:

1. Assign the next TV number sequentially.
2. Add the test to all six suites with the TV number in the function name.
3. Add a corresponding CV vector to `cross_verify_vectors.json` if the behavior
   involves deterministic outputs.
4. Update this registry.
5. Bump the spec version if the new vector changes any existing verification outcome.

<!-- end AIOSchema v0.5.6 Conformance Test Vector Registry | https://aioschema.org -->
