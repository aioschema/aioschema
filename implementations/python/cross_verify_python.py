#!/usr/bin/env python3
"""
AIOSchema v0.5.5 — Cross-verification harness (Python side)
Produces a JSON file of test vectors and expected outputs for verification
against the TypeScript implementation.

Run:  python3 cross_verify_python.py > vectors.json
"""

import sys, json, hashlib, os, tempfile
sys.path.insert(0, '/home/claude')
import aioschema_v055 as aios

# ── Helpers ───────────────────────────────────────────────────────────────────

def canonical_json(obj):
    """Compact sorted-key JSON — matches TypeScript canonicalJson()"""
    def sort_obj(v):
        if isinstance(v, dict):
            return {k: sort_obj(v[k]) for k in sorted(v)}
        if isinstance(v, list):
            return [sort_obj(x) for x in v]
        return v
    return json.dumps(sort_obj(obj), separators=(',', ':'))

def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def sha384_hex(data: bytes) -> str:
    return hashlib.sha384(data).hexdigest()

# ── Vector 1: SHA-256 hash of known content ───────────────────────────────────

ASSET_CONTENT_A = b"The quick brown fox jumps over the lazy dog"
ASSET_CONTENT_B = b"AIOSchema cross-verification test vector"
ASSET_CONTENT_EMPTY = b""
ASSET_CONTENT_BINARY = bytes(range(256))

v1 = {
    "id": "CV-01",
    "name": "SHA-256 hash of known content",
    "description": "computeHash(data, 'sha256') must produce identical prefixed hex",
    "inputs": {
        "data_hex": ASSET_CONTENT_A.hex(),
        "algorithm": "sha256"
    },
    "expected": f"sha256-{sha256_hex(ASSET_CONTENT_A)}"
}

# ── Vector 2: SHA-384 hash of known content ───────────────────────────────────

v2 = {
    "id": "CV-02",
    "name": "SHA-384 hash of known content",
    "description": "computeHash(data, 'sha384') must produce identical prefixed hex",
    "inputs": {
        "data_hex": ASSET_CONTENT_A.hex(),
        "algorithm": "sha384"
    },
    "expected": f"sha384-{sha384_hex(ASSET_CONTENT_A)}"
}

# ── Vector 3: SHA-256 of empty bytes ─────────────────────────────────────────

v3 = {
    "id": "CV-03",
    "name": "SHA-256 of empty bytes",
    "inputs": {
        "data_hex": "",
        "algorithm": "sha256"
    },
    "expected": f"sha256-{sha256_hex(b'')}"
}

# ── Vector 4: SHA-256 of binary content ──────────────────────────────────────

v4 = {
    "id": "CV-04",
    "name": "SHA-256 of full byte range (0x00–0xFF)",
    "inputs": {
        "data_hex": ASSET_CONTENT_BINARY.hex(),
        "algorithm": "sha256"
    },
    "expected": f"sha256-{sha256_hex(ASSET_CONTENT_BINARY)}"
}

# ── Vector 5: Canonical JSON of known object ──────────────────────────────────

canonical_input = {
    "hash_original": "sha256-abc123",
    "asset_id": "urn:test:001",
    "creator_id": "ed25519-fp-" + "a" * 32,
    "schema_version": "0.5.5",
    "creation_timestamp": "2026-02-22T12:00:00Z",
}
canonical_expected = canonical_json(canonical_input)
v5 = {
    "id": "CV-05",
    "name": "Canonical JSON of CORE_HASH_FIELDS object",
    "description": "canonicalJson must sort keys and use compact separators",
    "inputs": {
        "object": canonical_input
    },
    "expected": canonical_expected
}

# ── Vector 6: core_fingerprint of known core fields ──────────────────────────

core_fields = {k: canonical_input[k] for k in ["asset_id", "schema_version",
    "creation_timestamp", "hash_original", "creator_id"]}
core_canon = canonical_json(core_fields).encode("utf-8")
core_fp = f"sha256-{sha256_hex(core_canon)}"

v6 = {
    "id": "CV-06",
    "name": "core_fingerprint of known core fields",
    "description": "SHA-256 of canonicalJson({CORE_HASH_FIELDS...}) must match exactly",
    "inputs": {
        "core_fields": core_fields
    },
    "expected": core_fp
}

# ── Vector 7: Generate manifest, verify canonical fields ──────────────────────

# Use fixed inputs so both sides produce same deterministic content
FIXED_ASSET = b"CV-07 fixed asset content for cross-verification"
fixed_hash_sha256 = f"sha256-{sha256_hex(FIXED_ASSET)}"
fixed_hash_sha384 = f"sha384-{sha384_hex(FIXED_ASSET)}"
fixed_asset_id = "00000000-0000-7000-8000-000000000001"
fixed_creator_id = "ed25519-fp-" + "0" * 32
fixed_ts = "2026-02-22T12:00:00Z"
fixed_schema = "0.5.5"

# Build a fully deterministic manifest (no random elements)
fixed_core_for_fp = {
    "asset_id": fixed_asset_id,
    "schema_version": fixed_schema,
    "creation_timestamp": fixed_ts,
    "hash_original": fixed_hash_sha256,
    "creator_id": fixed_creator_id,
}
fixed_fp = f"sha256-{sha256_hex(canonical_json(fixed_core_for_fp).encode('utf-8'))}"

fixed_manifest = {
    "core": {
        "asset_id": fixed_asset_id,
        "schema_version": fixed_schema,
        "creation_timestamp": fixed_ts,
        "hash_original": fixed_hash_sha256,
        "creator_id": fixed_creator_id,
        "core_fingerprint": fixed_fp,
        "signature": None,
        "manifest_signature": None,
        "anchor_reference": None,
        "previous_version_anchor": None,
    },
    "extensions": {}
}

# Verify this manifest using Python implementation
with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
    f.write(FIXED_ASSET)
    tmppath = f.name

try:
    m = aios.Manifest.from_dict(fixed_manifest)
    result = aios.verify_manifest(tmppath, m)
    python_verify_success = result.success
    python_verify_message = result.message
finally:
    os.unlink(tmppath)

v7 = {
    "id": "CV-07",
    "name": "Deterministic manifest verification",
    "description": "Both implementations must successfully verify this fixed manifest",
    "inputs": {
        "asset_hex": FIXED_ASSET.hex(),
        "manifest": fixed_manifest
    },
    "expected": {
        "success": True,
        "match_type": "hard"
    },
    "python_result": {
        "success": python_verify_success,
        "message": python_verify_message
    }
}

# ── Vector 8: Tampered hash_original must fail ────────────────────────────────

tampered_hash_manifest = json.loads(json.dumps(fixed_manifest))
tampered_hash_manifest["core"]["hash_original"] = "sha256-" + "0" * 64

with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
    f.write(FIXED_ASSET)
    tmppath = f.name

try:
    m2 = aios.Manifest.from_dict(tampered_hash_manifest)
    r2 = aios.verify_manifest(tmppath, m2)
    python_tampered_success = r2.success
finally:
    os.unlink(tmppath)

v8 = {
    "id": "CV-08",
    "name": "Tampered hash_original must fail",
    "inputs": {
        "asset_hex": FIXED_ASSET.hex(),
        "manifest": tampered_hash_manifest
    },
    "expected": {
        "success": False
    },
    "python_result": {
        "success": python_tampered_success
    }
}

# ── Vector 9: Tampered core_fingerprint must fail ────────────────────────────

tampered_cfp_manifest = json.loads(json.dumps(fixed_manifest))
tampered_cfp_manifest["core"]["core_fingerprint"] = "sha256-" + "f" * 64

with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
    f.write(FIXED_ASSET)
    tmppath = f.name

try:
    m3 = aios.Manifest.from_dict(tampered_cfp_manifest)
    r3 = aios.verify_manifest(tmppath, m3)
    python_cfp_success = r3.success
finally:
    os.unlink(tmppath)

v9 = {
    "id": "CV-09",
    "name": "Tampered core_fingerprint must fail",
    "inputs": {
        "asset_hex": FIXED_ASSET.hex(),
        "manifest": tampered_cfp_manifest
    },
    "expected": {
        "success": False
    },
    "python_result": {
        "success": python_cfp_success
    }
}

# ── Vector 10: hash_schema_block alias accepted ───────────────────────────────

alias_manifest = json.loads(json.dumps(fixed_manifest))
alias_manifest["core"]["hash_schema_block"] = alias_manifest["core"].pop("core_fingerprint")

with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
    f.write(FIXED_ASSET)
    tmppath = f.name

try:
    m4 = aios.Manifest.from_dict(alias_manifest)
    r4 = aios.verify_manifest(tmppath, m4)
    python_alias_success = r4.success
finally:
    os.unlink(tmppath)

v10 = {
    "id": "CV-10",
    "name": "hash_schema_block alias accepted",
    "description": "Manifests using deprecated hash_schema_block must verify successfully",
    "inputs": {
        "asset_hex": FIXED_ASSET.hex(),
        "manifest": alias_manifest
    },
    "expected": {
        "success": True
    },
    "python_result": {
        "success": python_alias_success
    }
}

# ── Vector 11: Multi-hash verification ───────────────────────────────────────

multi_hash_core_for_fp = {
    "asset_id": fixed_asset_id,
    "schema_version": fixed_schema,
    "creation_timestamp": fixed_ts,
    "hash_original": [fixed_hash_sha256, fixed_hash_sha384],
    "creator_id": fixed_creator_id,
}
multi_hash_fp = f"sha256-{sha256_hex(canonical_json(multi_hash_core_for_fp).encode('utf-8'))}"

multi_hash_manifest = {
    "core": {
        "asset_id": fixed_asset_id,
        "schema_version": fixed_schema,
        "creation_timestamp": fixed_ts,
        "hash_original": [fixed_hash_sha256, fixed_hash_sha384],
        "creator_id": fixed_creator_id,
        "core_fingerprint": multi_hash_fp,
        "signature": None,
        "manifest_signature": None,
        "anchor_reference": None,
        "previous_version_anchor": None,
    },
    "extensions": {}
}

with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
    f.write(FIXED_ASSET)
    tmppath = f.name

try:
    m5 = aios.Manifest.from_dict(multi_hash_manifest)
    r5 = aios.verify_manifest(tmppath, m5)
    python_multi_success = r5.success
finally:
    os.unlink(tmppath)

v11 = {
    "id": "CV-11",
    "name": "Multi-hash manifest verification",
    "description": "Array hash_original — any match is sufficient",
    "inputs": {
        "asset_hex": FIXED_ASSET.hex(),
        "manifest": multi_hash_manifest
    },
    "expected": {
        "success": True
    },
    "python_result": {
        "success": python_multi_success
    }
}

# ── Vector 12: Unsupported schema_version rejected ───────────────────────────

bad_version_manifest = json.loads(json.dumps(fixed_manifest))
bad_version_manifest["core"]["schema_version"] = "99.0"

with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
    f.write(FIXED_ASSET)
    tmppath = f.name

try:
    m6 = aios.Manifest.from_dict(bad_version_manifest)
    r6 = aios.verify_manifest(tmppath, m6)
    python_badver_success = r6.success
finally:
    os.unlink(tmppath)

v12 = {
    "id": "CV-12",
    "name": "Unsupported schema_version rejected",
    "inputs": {
        "asset_hex": FIXED_ASSET.hex(),
        "manifest": bad_version_manifest
    },
    "expected": {
        "success": False
    },
    "python_result": {
        "success": python_badver_success
    }
}

# ── Vector 13: Missing required field rejected ────────────────────────────────

missing_field_manifest = json.loads(json.dumps(fixed_manifest))
del missing_field_manifest["core"]["creator_id"]

with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
    f.write(FIXED_ASSET)
    tmppath = f.name

try:
    m7 = aios.Manifest.from_dict(missing_field_manifest)
    r7 = aios.verify_manifest(tmppath, m7)
    python_missing_success = r7.success
finally:
    os.unlink(tmppath)

v13 = {
    "id": "CV-13",
    "name": "Missing required field (creator_id) rejected",
    "inputs": {
        "asset_hex": FIXED_ASSET.hex(),
        "manifest": missing_field_manifest
    },
    "expected": {
        "success": False
    },
    "python_result": {
        "success": python_missing_success
    }
}

# ── Vector 14: Invalid timestamp format rejected ──────────────────────────────

# Build a valid manifest then mutate timestamp
invalid_ts_manifest = json.loads(json.dumps(fixed_manifest))
invalid_ts_manifest["core"]["creation_timestamp"] = "2026-02-22 12:00:00"  # missing T and Z

with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
    f.write(FIXED_ASSET)
    tmppath = f.name

try:
    m8 = aios.Manifest.from_dict(invalid_ts_manifest)
    r8 = aios.verify_manifest(tmppath, m8)
    python_badts_success = r8.success
finally:
    os.unlink(tmppath)

v14 = {
    "id": "CV-14",
    "name": "Invalid timestamp format rejected",
    "description": "Non-UTC or non-ISO-8601 timestamp must fail",
    "inputs": {
        "asset_hex": FIXED_ASSET.hex(),
        "manifest": invalid_ts_manifest
    },
    "expected": {
        "success": False
    },
    "python_result": {
        "success": python_badts_success
    }
}

# ── Emit results ──────────────────────────────────────────────────────────────

vectors = [v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14]

# Self-check: all Python results must match expected
errors = []
for v in vectors:
    if "python_result" in v:
        for key, val in v["expected"].items():
            if key in v["python_result"]:
                if v["python_result"][key] != val:
                    errors.append(f"{v['id']}: Python result mismatch — "
                                  f"expected {key}={val}, got {v['python_result'][key]}")

if errors:
    print("PYTHON SELF-CHECK FAILED:", file=sys.stderr)
    for e in errors:
        print(" ", e, file=sys.stderr)
    sys.exit(1)

print(json.dumps({"spec_version": "0.5.5", "vectors": vectors}, indent=2))

# Print summary to stderr
print(f"\nPython self-check: {len(vectors)} vectors, all PASS", file=sys.stderr)
