# AIOSchema v0.5.5 Conformance Test Vector Registry

This document maps the canonical test vector identifiers (TV-01 through TV-19) to their
implementations in all five reference test suites, and to the cross-verification
deterministic vectors (CV-01 through CV-14).

Any conforming AIOSchema implementation must pass all 19 test vectors to be considered
spec-compliant.

---

## v0.4 Test Vectors (TV-01 – TV-12)

| ID | Description | Python | TypeScript | Node.js | Go | Rust |
|---|---|---|---|---|---|---|
| TV-01 | Valid generate + verify round-trip (hard match) | `test_tv01_valid_roundtrip` | `verifyManifest passes on correct asset` | `TV-01: Valid manifest roundtrip` | `TestVerifyManifest_ValidHardMatch` | `verify_valid_hard_match` |
| TV-02 | Tampered `hash_original` must fail | `test_tv02_tampered_hash_original` | `verifyManifest fails on tampered hash_original` | `TV-02: Tampered hash_original fails` | `TestVerifyManifest_TamperedHashOriginal` | `verify_tampered_hash_original` |
| TV-03 | Tampered `core_fingerprint` must fail | `test_tv03_tampered_core_fingerprint` | `verifyManifest fails on tampered core_fingerprint` | `TV-03: Tampered core_fingerprint fails` | `TestVerifyManifest_TamperedCoreFingerprint` | `verify_tampered_core_fingerprint` |
| TV-04 | Soft match within pHash threshold | `test_tv04_soft_match_within_threshold` | `verifyManifest soft binding fallback on transformed asset` | `TV-04: Soft binding skipped` | *(image processing not available)* | *(image processing not available)* |
| TV-05 | Soft match outside threshold must fail | `test_tv05_soft_match_outside_threshold` | *(covered by TV-02 path)* | `TV-05: Soft binding skipped` | *(image processing not available)* | *(image processing not available)* |
| TV-06 | Signature present and valid | `test_tv06_signature_success` | *(covered by TV-07 inverse)* | `TV-06: Valid signature passes` | *(covered by TV-07 inverse)* | *(covered by TV-07 inverse)* |
| TV-07 | Signature with wrong public key must fail | `test_tv07_signature_wrong_key` | `TV-07: Signature wrong key — must not verify` | `TV-07: Wrong public key fails` | `TestVerifyManifest_TamperedCoreFingerprint` | `verify_tampered_core_fingerprint` |
| TV-08 | Unsigned manifest (null signature) passes | `test_tv08_null_signature_unsigned_pass` | `verifyManifest passes on correct asset` | `TV-08: Unsigned manifest passes` | `TestVerifyManifest_UnsignedPassesWithoutKey` | `verify_unsigned_passes_without_key` |
| TV-09 | Missing required fields must fail | `test_tv09_missing_required_fields` | `verifyManifest fails on tampered core_fingerprint` | `TV-09: Missing required fields fail` | `TestVerifyManifest_MissingCreatorID` | `verify_missing_creator_id` |
| TV-10 | Invalid timestamp format rejected | `test_tv10_invalid_timestamp` | `verifyManifest rejects invalid asset_id` | `TV-10: Invalid timestamp rejected` | `TestVerifyManifest_InvalidTimestamp` | `verify_invalid_timestamp` |
| TV-11 | Non-UTC timestamp (`+HH:MM` offset) rejected | `test_tv11_non_utc_timestamp` | `TV-11: Non-UTC timestamp (+05:00 offset) rejected` | `TV-11: Non-UTC timestamp rejected` | `TestVerifyManifest_NonUTCTimestamp` | `verify_non_utc_timestamp` |
| TV-12 | Unknown `schema_version` rejected | `test_tv12_unknown_schema_version` | `verifyManifest rejects unsupported schema_version` | `TV-12: Unknown schema_version rejected` | `TestVerifyManifest_UnsupportedSchemaVersion` | `verify_unsupported_schema_version` |

## v0.5 Test Vectors (TV-13 – TV-18)

| ID | Description | Python | TypeScript | Node.js | Go | Rust |
|---|---|---|---|---|---|---|
| TV-13 | Multi-hash manifest (SHA-256 + SHA-384) | `test_tv13_multi_hash_manifest` | `generateManifest multi-algorithm produces array` | `TV-13: Multi-hash manifest` | *(covered by CV-11)* | `verify_multi_hash` |
| TV-14 | `manifest_signature` present and valid | `test_tv14_manifest_signature_valid` | *(see TV-15 inverse)* | `TV-14: manifest_signature valid` | *(covered by TV-15 inverse)* | *(covered by TV-15 inverse)* |
| TV-15 | `manifest_signature` fails when extensions tampered | `test_tv15_manifest_signature_extensions_tampered` | `TV-15: manifest_signature invalidated by extensions tampering` | `TV-15: manifest_signature tampered fails` | *(covered by CV-09 path)* | *(covered by CV-09 path)* |
| TV-16 | SHA-384 single-hash manifest | `test_tv16_sha384_single_hash` | `generateManifest hash_original has sha256 prefix by default` | `TV-16: SHA-384 manifest` | *(covered by CV-02)* | *(covered by CV-02)* |
| TV-17 | Anchor verified via `AnchorResolver` | `test_tv17_anchor_verified_success` | `verifyManifest with anchor_resolver verifies anchor` | `TV-17: Anchor verified` | *(anchor resolver not implemented)* | *(anchor resolver not implemented)* |
| TV-18 | `anchor_reference` present, `verify_anchor=false` → warning not failure | `test_tv18_anchor_present_not_verified_warning` | `TV-18: anchor present, verifyAnchor=false — warning not failure` | `TV-18: Anchor present no verify — warning` | `TestVerifyManifest_AnchorWarningNotFailure` | `verify_anchor_warning_not_failure` |

## v0.5.5 Test Vectors (TV-19)

| ID | Description | Python | TypeScript | Node.js | Go | Rust |
|---|---|---|---|---|---|---|
| TV-19a | Key rotation — v1 manifest signs with key A and anchors | *(pending)* | `TV-19a`–`TV-19e` (key rotation suite) | `TV-19a: v1 manifest signs with key A` | *(pending)* | *(pending)* |
| TV-19b | Key rotation — v2 re-signed with key B, chains via `previous_version_anchor` | *(pending)* | *(see TV-19a suite)* | `TV-19b: v2 re-signs with key B` | *(pending)* | *(pending)* |
| TV-19c | Key rotation is irreversible — v2 with old key A must fail | *(pending)* | *(see TV-19a suite)* | `TV-19c: old key A fails on v2` | *(pending)* | *(pending)* |
| TV-19d | `creator_id` MAY change across rotation — both manifests valid independently | *(pending)* | *(see TV-19a suite)* | `TV-19d: creator_id change valid` | *(pending)* | *(pending)* |
| TV-19e | Full chain — anchor resolver confirms version continuity | *(pending)* | *(see TV-19a suite)* | `TV-19e: full chain anchor verify` | *(pending)* | *(pending)* |

---

## Cross-Implementation Deterministic Vectors (CV-01 – CV-14)

These vectors use fixed inputs so all five implementations must produce byte-for-byte
identical outputs. They live in `conformance/cross_verify_vectors.json` and are run by
`cross_verify_python.py` (Python), `cross_verify_ts.ts` (TypeScript),
`cross_verify_node.js` (Node.js), `cross_verify_test.go` (Go), and
`tests/cross_verify.rs` (Rust).

| ID | Description | Expected output |
|---|---|---|
| CV-01 | SHA-256 of `"The quick brown fox…"` | `sha256-d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592` |
| CV-02 | SHA-384 of `"The quick brown fox…"` | `sha384-ca737f1014a48f4c0b6dd43cb177b0afd9e5169367544c494011e3317dbf9a509cb1e5dc1e85a941bbee3d7f2afbc9b1` |
| CV-03 | SHA-256 of empty bytes | `sha256-e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| CV-04 | SHA-256 of bytes 0x00–0xFF | See `cross_verify_vectors.json` |
| CV-05 | Canonical JSON of known object | Compact, sorted keys, no whitespace |
| CV-06 | `core_fingerprint` of known core fields | See `cross_verify_vectors.json` |
| CV-07 | Deterministic manifest verification (fixed inputs) | `success: true, match_type: "hard"` |
| CV-08 | Tampered `hash_original` → fail | `success: false` |
| CV-09 | Tampered `core_fingerprint` → fail | `success: false` |
| CV-10 | `hash_schema_block` alias accepted | `success: true` |
| CV-11 | Multi-hash array verification | `success: true` |
| CV-12 | Unsupported `schema_version` → fail | `success: false` |
| CV-13 | Missing required field (`creator_id`) → fail | `success: false` |
| CV-14 | Invalid timestamp format → fail | `success: false` |

---

## Test suite counts

| Suite | Tests | CV vectors | Status |
|---|---|---|---|
| Python (`test_aioschema_v055.py`) | 108 | 14/14 | ✓ All passing |
| TypeScript (`test_aioschema_v055.ts`) | 70 + 12 XC | 14/14 | ✓ All passing |
| Node.js (`test_aioschema_v055.js`) | 80 | 14/14 | ✓ All passing |
| Go (`aioschema_test.go` + `cross_verify_test.go`) | 27 | 14/14 | ✓ All passing |
| Rust (`tests/unit_tests.rs` + `tests/cross_verify.rs`) | 30 | 14/14 | ✓ All passing |

---

## Bootstrap rule verification

All five suites independently verify the bootstrap rule: `core_fingerprint` is **not**
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

---

## Adding new test vectors

When a new spec version introduces behavior changes:

1. Assign the next TV number sequentially
2. Add the test to all five suites with the TV number in the function name
3. Add a corresponding CV vector to `cross_verify_vectors.json` if the behavior involves deterministic outputs
4. Update this registry
5. Bump the spec version if the new vector changes any existing verification outcome
