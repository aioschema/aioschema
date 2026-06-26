<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 Ovidiu Ancuta -->
<!-- aioschema/python v0.5.6 | AIOSchema spec v0.5.6 | https://aioschema.org -->

# aioschema (Python)

**AIOSchema v0.5.6 — Python reference implementation.**

Requires Python 3.10 or later. Dependencies: `cryptography`, `Pillow`, `numpy`.

- Spec: [aioschema.org](https://aioschema.org)

---

## Install

```bash
pip install cryptography Pillow numpy
```

Copy `aioschema_v055.py` into your project or install from the repo root.

---

## API

```python
from aioschema_v055 import generate_manifest, verify_manifest, generate_keypair, Manifest

# Generate a manifest
manifest = generate_manifest("asset.jpg")

# Generate with Ed25519 signing
private_key, public_key = generate_keypair()
manifest = generate_manifest(
    "asset.jpg",
    private_key=private_key,
    save_sidecar=True,
)

# Verify
result = verify_manifest("asset.jpg", manifest)
print(result.success)     # True
print(result.match_type)  # "hard"

# Verify with explicit public key
result = verify_manifest("asset.jpg", manifest, public_key=public_key)
print(result.signature_verified)  # True

# Print structured summary
print(result.summary())
```

---

## Full API reference

```python
# Manifest generation and verification
generate_manifest(file_path, *, private_key=None, hash_algorithms="sha256",
                  creator_id=None, extensions=None, anchor_ref=None,
                  previous_version_anchor=None, save_sidecar=False) -> Manifest

verify_manifest(file_path, manifest, *, public_key=None,
                soft_binding_threshold=5, verify_anchor=False,
                anchor_resolver=None) -> VerificationResult

# Keys
generate_keypair() -> tuple[Ed25519PrivateKey, Ed25519PublicKey]

# Batch operations
generate_batch(directory, *, glob_pattern="*", private_key=None, overwrite=False)
verify_batch(directory, *, glob_pattern="*", public_key=None)

# RFC 3161 anchoring
anchor_rfc3161(core_fingerprint, tsa_url="https://rfc3161.ai.moda", out_path=None) -> dict
verify_rfc3161(tsr_path, core_fingerprint) -> dict

# Constants
SPEC_VERSION                    # "0.5.6"
SUPPORTED_VERSIONS              # frozenset
CORE_HASH_FIELDS                # tuple[str, ...]
DEFAULT_HASH_ALG                # "sha256"
MAX_EXTENSION_SIZE_BYTES        # 4096
SOFT_BINDING_THRESHOLD_DEFAULT  # 5
SOFT_BINDING_THRESHOLD_MAX      # 10
SIDECAR_SUFFIX                  # ".aios.json"
```

---

## Running tests

```bash
# Unit and conformance tests (117 test methods)
python test_aioschema_v055.py

# Or with pytest
pytest test_aioschema_v055.py -v

# Cross-implementation verification (18 deterministic vectors)
AIOSCHEMA_VECTORS=/path/to/cross_verify_vectors.json python run_cross_verify.py

# Generate vectors file (Python side)
python cross_verify_python.py > cross_verify_vectors.json
```

---

## File structure

```
implementations/python/
├── aioschema_v055.py       # Main implementation
├── test_aioschema_v055.py  # Unit and conformance tests (117 test methods)
├── cross_verify_python.py  # Generates cross-verification vectors
├── run_cross_verify.py     # Runs cross-verification against vectors file
├── cross_verify_vectors.json
├── README.md
└── LICENSE.md
```

**Never commit:** `__pycache__/`, `*.pyc`, `.pytest_cache/`

---

## Links
- **Specification:** [aioschema.org](https://aioschema.org)
- **Field reference:** [aioschema.org/field-reference/v0-5-6/](https://aioschema.org/field-reference/v0-5-6/)
- **All implementations:** [github.com/aioschema/aioschema](https://github.com/aioschema/aioschema)

---

## License

Apache 2.0. See [LICENSE.md](./LICENSE.md).

Specification: CC-BY 4.0 — [aioschema.org](https://aioschema.org)

<!-- end aioschema/python v0.5.6 | AIOSchema spec v0.5.6 -->
