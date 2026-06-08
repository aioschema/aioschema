# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ovidiu Ancuta
#
# aioschema/python v0.5.6 | AIOSchema spec v0.5.6
# https://aioschema.org

import json, os, sys, tempfile, base64, pathlib

# Find vectors file
candidates = [
    os.environ.get("AIOSCHEMA_VECTORS"),
    os.path.join(os.path.dirname(__file__), "cross_verify_vectors.json"),
    "/mnt/project/cross_verify_vectors.json",
]
vectors_path = None
for p in candidates:
    if p and os.path.exists(p):
        vectors_path = p
        break

if not vectors_path:
    print("cross_verify_vectors.json not found. Set AIOSCHEMA_VECTORS env var.", file=sys.stderr)
    sys.exit(1)

from aioschema_v056 import (
    _compute_hash as compute_hash,
    verify_manifest,
    _canonical_bytes as canonical_bytes,
    CORE_HASH_FIELDS,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

vectors = json.load(open(vectors_path))["vectors"]
passed = 0
failed = 0
lines = []

for v in vectors:
    vid = v["id"]
    name = v["name"]
    try:
        # CV-01 to CV-04: hash computation
        if "data_hex" in v.get("inputs", {}) and "algorithm" in v.get("inputs", {}):
            data = bytes.fromhex(v["inputs"]["data_hex"])
            alg = v["inputs"]["algorithm"]
            result = compute_hash(data, alg)
            ok = result == v["expected"]
            if ok:
                passed += 1; lines.append(f"  ✓ {vid}: {name}")
            else:
                failed += 1; lines.append(f"  ✗ {vid}: {name}\n    expected: {v['expected']}\n    got:      {result}")
            continue

        # CV-05: canonical JSON
        if "object" in v.get("inputs", {}):
            result = canonical_bytes(v["inputs"]["object"]).decode("utf-8")
            ok = result == v["expected"]
            if ok:
                passed += 1; lines.append(f"  ✓ {vid}: {name}")
            else:
                failed += 1; lines.append(f"  ✗ {vid}: {name}\n    expected: {v['expected']}\n    got:      {result}")
            continue

        # CV-06: core_fingerprint
        if "core_fields" in v.get("inputs", {}):
            subset = {k: v["inputs"]["core_fields"][k] for k in CORE_HASH_FIELDS if k in v["inputs"]["core_fields"]}
            canon = canonical_bytes(subset)
            result = compute_hash(canon, "sha256")
            ok = result == v["expected"]
            if ok:
                passed += 1; lines.append(f"  ✓ {vid}: {name}")
            else:
                failed += 1; lines.append(f"  ✗ {vid}: {name}\n    expected: {v['expected']}\n    got:      {result}")
            continue

        # CV-07+: manifest verification
        if "asset_hex" in v.get("inputs", {}) and "manifest" in v.get("inputs", {}):
            asset = bytes.fromhex(v["inputs"]["asset_hex"])
            manifest = v["inputs"]["manifest"]
            pub_key_b64 = v["inputs"].get("public_key_b64")

            # Write asset to temp file
            with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
                f.write(asset)
                tmppath = f.name

            # Decode public key if provided
            pub_key = None
            if pub_key_b64:
                raw = base64.b64decode(pub_key_b64)
                pub_key = Ed25519PublicKey.from_public_bytes(raw)

            try:
                result = verify_manifest(tmppath, manifest, public_key=pub_key)
            finally:
                os.unlink(tmppath)

            exp = v["expected"]

            # Check success
            ok = result.success == exp["success"]
            # Check match_type if specified
            if "match_type" in exp:
                ok = ok and result.match_type == exp["match_type"]
            # Check message_contains if specified
            if "message_contains" in exp:
                ok = ok and exp["message_contains"] in (result.message or "")
            # Check signature_verified if specified
            if "signature_verified" in exp:
                ok = ok and result.signature_verified == exp["signature_verified"]
            # Check manifest_signature_verified if specified
            if "manifest_signature_verified" in exp:
                ok = ok and result.manifest_signature_verified == exp["manifest_signature_verified"]

            if ok:
                passed += 1; lines.append(f"  ✓ {vid}: {name}")
            else:
                failed += 1
                lines.append(f"  ✗ {vid}: {name}\n"
                             f"    expected: success={exp['success']}"
                             f" match_type={exp.get('match_type', 'any')}"
                             f" sig={exp.get('signature_verified', 'any')}"
                             f" msig={exp.get('manifest_signature_verified', 'any')}\n"
                             f"    got:      success={result.success}"
                             f" match_type={result.match_type}"
                             f" sig={getattr(result, 'signature_verified', 'N/A')}"
                             f" msig={getattr(result, 'manifest_signature_verified', 'N/A')}"
                             f" msg={result.message}")
            continue

        lines.append(f"  ? {vid}: unrecognised vector shape")
    except Exception as e:
        failed += 1
        lines.append(f"  ✗ {vid}: {name} — ERROR: {e}")

print("\nAIOSchema v0.5.6 — Python Cross-Verify")
print("=" * 50)
for l in lines:
    print(l)
print("=" * 50)
print(f"Vectors: {len(vectors)}  |  PASS: {passed}  |  FAIL: {failed}")
print("✓ ALL PASS" if failed == 0 else "✗ FAILURES DETECTED")
sys.exit(0 if failed == 0 else 1)
# -- end aioschema/python v0.5.6 | AIOSchema spec v0.5.6 --
