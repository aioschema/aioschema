<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 Ovidiu Ancuta -->
<!-- aioschema/rust v0.5.6 | AIOSchema spec v0.5.6 | https://aioschema.org -->

# aioschema (Rust)

**AIOSchema v0.5.6 — Rust reference implementation.**

Requires Rust 1.70 or later. Uses `serde`, `sha2`, `sha3`, `ed25519-dalek`, `hex`, `base64`, `regex`, and `once_cell`. No network dependencies.

- Spec: [aioschema.org](https://aioschema.org)

---

## Install

Add to your `Cargo.toml`:

```toml
[dependencies]
aioschema = { path = "implementations/rust" }
```

Or from crates.io once published:

```toml
[dependencies]
aioschema = "0.5.6"
```

---

## API

```rust
use aioschema::{verify_manifest, Manifest, VerifyOptions};

// Verify an asset against its manifest
let asset_data = std::fs::read("asset.jpg").unwrap();
let manifest: Manifest = serde_json::from_str(
    &std::fs::read_to_string("asset.jpg.aios.json").unwrap()
).unwrap();

let result = verify_manifest(&asset_data, &manifest, &VerifyOptions::default()).unwrap();
assert!(result.success);
assert_eq!(result.match_type, Some(aioschema::MatchType::Hard));

// Verify with embedded public key (Level 2)
let result = verify_manifest(&asset_data, &manifest, &VerifyOptions {
    public_key: Some(&pub_key_bytes),
    ..VerifyOptions::default()
}).unwrap();
assert!(result.signature_verified);
```

---

## Full API reference

```rust
// Verification
aioschema::verify_manifest(asset_data: &[u8], manifest: &Manifest, opts: &VerifyOptions) -> Result<VerificationResult, AiosError>

// Hashing
aioschema::compute_hash(data: &[u8], algorithm: &str) -> Result<String, AiosError>
aioschema::parse_hash_prefix(value: &str) -> Result<(&str, &str), AiosError>

// Canonical serialization
aioschema::canonical_json(value: &Value) -> Result<Vec<u8>, AiosError>
aioschema::canonical_core_fields(core: &Value) -> Result<Vec<u8>, AiosError>
aioschema::canonical_manifest_bytes(manifest: &Value) -> Result<Vec<u8>, AiosError>

// Timing-safe comparison
aioschema::safe_equal(a: &str, b: &str) -> bool

// Constants
aioschema::SPEC_VERSION                 // "0.5.6"
aioschema::SUPPORTED_VERSIONS           // &[&str]
aioschema::CORE_HASH_FIELDS             // &[&str]
aioschema::DEFAULT_HASH_ALG             // "sha256"
aioschema::MAX_EXTENSION_SIZE_BYTES     // 4096
aioschema::SOFT_BINDING_THRESHOLD_DEFAULT // 5
aioschema::SOFT_BINDING_THRESHOLD_MAX   // 10
aioschema::SIDECAR_SUFFIX               // ".aios.json"

// Compiled regex patterns
aioschema::HASH_PATTERN
aioschema::SIGNATURE_PATTERN
aioschema::ANCHOR_PATTERN
aioschema::TIMESTAMP_PATTERN
aioschema::CREATOR_ID_ATTRIBUTED_PATTERN
aioschema::UUID_PATTERN
```

---

## Running tests

```bash
# Unit tests
cargo test

# Cross-implementation verification (18 deterministic vectors)
AIOSCHEMA_VECTORS=/path/to/cross_verify_vectors.json cargo test test_cross_verify

# Verbose output
cargo test -- --nocapture
```

---

## File structure

```
implementations/rust/
├── src/
│   ├── lib.rs              # Crate root, public API exports
│   ├── types.rs            # Type definitions and constants
│   ├── algorithms.rs       # Hash computation, canonical JSON, regex patterns
│   ├── verify.rs           # §10 verification procedure
│   ├── unit_tests.rs       # Unit tests
│   └── cross_verify.rs     # 18 cross-implementation vectors
├── Cargo.toml
├── Cargo.lock
├── cross_verify_vectors.json
├── README.md
└── LICENSE.md
```

**Never commit:** `target/`, `**/_rustc_info.json`

---

## License

Apache 2.0. See [LICENSE.md](./LICENSE.md).

Specification: CC-BY 4.0 — [aioschema.org](https://aioschema.org)

<!-- end aioschema/rust v0.5.6 | AIOSchema spec v0.5.6 -->
