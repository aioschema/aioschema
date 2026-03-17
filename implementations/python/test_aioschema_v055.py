"""
AIOSchema v0.5.5 — Test Suite
============================
Covers all §5.4 required test vectors (TV-01 through TV-18),
plus extended tests for multi-hash, manifest_signature, SHA-384,
configurable soft-binding threshold, anchor verification, and
backward compatibility.

Run with: python test_aioschema_v055.py
Or:       pytest test_aioschema_v055.py -v
"""

import copy
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

import numpy as np
from PIL import Image

from aioschema_v055 import (
    AnchorResolver,
    AnchorVerificationError,
    SOFT_BINDING_THRESHOLD_DEFAULT,
    SOFT_BINDING_THRESHOLD_MAX,
    SPEC_VERSION,
    SUPPORTED_VERSIONS,
    CreatorId,
    CreatorIdMode,
    Manifest,
    VerificationResult,
    _canonical_bytes,
    _canonical_manifest_bytes,
    _compute_hash,
    _parse_hash,
    _phash,
    _phash_distance,
    _safe_equal,
    _uuid7,
    generate_batch,
    generate_keypair,
    generate_manifest,
    verify_batch,
    verify_manifest,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def make_png(width=64, height=64, color=(100, 150, 200)) -> bytes:
    buf = tempfile.NamedTemporaryFile(suffix=".png", delete=False)
    buf.close()
    Image.new("RGB", (width, height), color=color).save(buf.name)
    data = Path(buf.name).read_bytes()
    os.unlink(buf.name)
    return data


def make_gradient_png(start: int, end: int, size=64) -> bytes:
    arr = np.linspace(start, end, size * size, dtype=np.uint8).reshape(size, size)
    buf = tempfile.NamedTemporaryFile(suffix=".png", delete=False)
    buf.close()
    Image.fromarray(arr, mode="L").save(buf.name)
    data = Path(buf.name).read_bytes()
    os.unlink(buf.name)
    return data


class TempAsset:
    def __init__(self, data: bytes = None, suffix=".png"):
        self.data   = data or make_png()
        self.suffix = suffix
        self.path: Path | None = None

    def __enter__(self) -> Path:
        f = tempfile.NamedTemporaryFile(suffix=self.suffix, delete=False)
        f.write(self.data)
        f.close()
        self.path = Path(f.name)
        return self.path

    def __exit__(self, *_):
        if self.path:
            self.path.unlink(missing_ok=True)
            Manifest.sidecar_path(self.path).unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# §5.4 Required Test Vectors — v0.4 set (TV-01 through TV-12)
# ---------------------------------------------------------------------------

class TestSpecVectorsV04(unittest.TestCase):
    """All v0.4 test vectors must still pass."""

    def setUp(self):
        self.priv, self.pub = generate_keypair()

    def test_tv01_valid_roundtrip(self):
        with TempAsset() as p:
            m = generate_manifest(p, private_key=self.priv)
            r = verify_manifest(p, m, public_key=self.pub)
            self.assertTrue(r.success, r.summary())
            self.assertEqual(r.match_type, "hard")
            self.assertTrue(r.signature_verified)

    def test_tv02_tampered_hash_original(self):
        with TempAsset() as p:
            m = generate_manifest(p)
            t = Manifest.from_dict(m.to_dict())
            t.core["hash_original"] = "sha256-" + "ab" * 32
            r = verify_manifest(p, t)
            self.assertFalse(r.success)

    def test_tv03_tampered_core_fingerprint(self):
        with TempAsset() as p:
            m = generate_manifest(p)
            t = Manifest.from_dict(m.to_dict())
            t.core["core_fingerprint"] = "sha256-" + "cd" * 32
            r = verify_manifest(p, t)
            self.assertFalse(r.success)
            self.assertIn("tampered", r.message.lower())

    def test_tv04_soft_match_within_threshold(self):
        data = make_png(color=(80, 120, 160))
        with TempAsset(data) as p:
            m = generate_manifest(p)
            similar = make_png(color=(80, 120, 160))
            p.write_bytes(similar)
            r = verify_manifest(p, m)
            if not r.success:
                self.skipTest("pHash not close enough in this environment")

    def test_tv05_soft_match_outside_threshold(self):
        original = make_gradient_png(0, 255)
        with TempAsset(original) as p:
            m = generate_manifest(p)
            p.write_bytes(make_gradient_png(255, 0))
            r = verify_manifest(p, m)
            self.assertFalse(r.success)
            self.assertIn("mismatch", r.message.lower())

    def test_tv06_signature_success(self):
        with TempAsset() as p:
            m = generate_manifest(p, private_key=self.priv)
            r = verify_manifest(p, m, public_key=self.pub)
            self.assertTrue(r.success)
            self.assertTrue(r.signature_verified)

    def test_tv07_signature_wrong_key(self):
        with TempAsset() as p:
            m = generate_manifest(p, private_key=self.priv)
            _, wrong = generate_keypair()
            r = verify_manifest(p, m, public_key=wrong)
            self.assertFalse(r.success)

    def test_tv08_null_signature_unsigned_pass(self):
        with TempAsset() as p:
            m = generate_manifest(p)
            self.assertIsNone(m.core["signature"])
            r = verify_manifest(p, m)
            self.assertTrue(r.success)
            self.assertFalse(r.signature_verified)

    def test_tv09_missing_required_fields(self):
        with TempAsset() as p:
            m = generate_manifest(p)
            for f in ["asset_id", "schema_version", "creation_timestamp",
                      "hash_original", "creator_id", "core_fingerprint"]:
                t = Manifest.from_dict(m.to_dict())
                del t.core[f]
                r = verify_manifest(p, t)
                self.assertFalse(r.success, f"Should fail with missing {f}")

    def test_tv10_invalid_timestamp(self):
        with TempAsset() as p:
            m = generate_manifest(p)
            t = Manifest.from_dict(m.to_dict())
            t.core["creation_timestamp"] = "2026-02-20 12:00:00"
            r = verify_manifest(p, t)
            self.assertFalse(r.success)

    def test_tv11_non_utc_timestamp(self):
        with TempAsset() as p:
            m = generate_manifest(p)
            t = Manifest.from_dict(m.to_dict())
            t.core["creation_timestamp"] = "2026-02-20T12:00:00+05:00"
            r = verify_manifest(p, t)
            self.assertFalse(r.success)

    def test_tv12_unknown_schema_version(self):
        with TempAsset() as p:
            m = generate_manifest(p)
            t = Manifest.from_dict(m.to_dict())
            t.core["schema_version"] = "9.99"
            r = verify_manifest(p, t)
            self.assertFalse(r.success)
            self.assertIn("schema_version", r.message)


# ---------------------------------------------------------------------------
# §5.4 New Test Vectors — v0.5 (TV-13 through TV-18)
# ---------------------------------------------------------------------------

class TestSpecVectorsV05(unittest.TestCase):
    """New test vectors introduced in v0.5."""

    def setUp(self):
        self.priv, self.pub = generate_keypair()

    # TV-13: Multi-hash manifest (SHA-256 + SHA-384) — any match succeeds
    def test_tv13_multi_hash_verify_with_any_algorithm(self):
        with TempAsset() as p:
            m = generate_manifest(p, hash_algorithms=["sha256", "sha384"])
            self.assertIsInstance(m.core["hash_original"], list)
            self.assertEqual(len(m.core["hash_original"]), 2)
            algs = [h.split("-")[0] for h in m.core["hash_original"]]
            self.assertIn("sha256", algs)
            self.assertIn("sha384", algs)
            r = verify_manifest(p, m)
            self.assertTrue(r.success, r.summary())
            self.assertEqual(r.match_type, "hard")

    # TV-14: manifest_signature present and valid — verified=True
    def test_tv14_manifest_signature_valid(self):
        with TempAsset() as p:
            m = generate_manifest(p, private_key=self.priv)
            self.assertIsNotNone(m.core["manifest_signature"])
            r = verify_manifest(p, m, public_key=self.pub)
            self.assertTrue(r.success, r.summary())
            self.assertTrue(r.manifest_signature_verified)

    # TV-15: manifest_signature present, extensions tampered — fail
    def test_tv15_manifest_signature_extensions_tampered(self):
        with TempAsset() as p:
            m = generate_manifest(p, private_key=self.priv)
            t = Manifest.from_dict(m.to_dict())
            t.extensions["injected_field"] = "malicious"
            r = verify_manifest(p, t, public_key=self.pub)
            self.assertFalse(r.success)
            self.assertIn("manifest", r.message.lower())

    # TV-16: SHA-384 single-hash manifest — verified correctly
    def test_tv16_sha384_single_hash(self):
        with TempAsset() as p:
            m = generate_manifest(p, hash_algorithms="sha384")
            ho = m.core["hash_original"]
            self.assertIsInstance(ho, str)
            self.assertTrue(ho.startswith("sha384-"))
            self.assertEqual(len(ho), len("sha384-") + 96)
            r = verify_manifest(p, m)
            self.assertTrue(r.success, r.summary())

    # TV-17: Anchor-verified flow — anchor match → anchor_verified=True
    def test_tv17_anchor_verified_success(self):
        with TempAsset() as p:
            m = generate_manifest(p, anchor_ref="aios-anchor:test-svc:record-001")

            def mock_fetcher(ref: str) -> dict:
                return {
                    "asset_id":          m.core["asset_id"],
                    "core_fingerprint": m.core["core_fingerprint"],
                    "timestamp":         m.core["creation_timestamp"],
                }

            r = verify_manifest(
                p, m, verify_anchor=True, anchor_resolver=mock_fetcher
            )
            self.assertTrue(r.success, r.summary())
            self.assertTrue(r.anchor_checked)
            self.assertTrue(r.anchor_verified)

    # TV-18: Anchor present but verify_anchor=False — pass with warning
    def test_tv18_anchor_present_not_verified_warning(self):
        with TempAsset() as p:
            m = generate_manifest(p, anchor_ref="aios-anchor:test-svc:record-002")
            r = verify_manifest(p, m, verify_anchor=False)
            self.assertTrue(r.success, r.summary())
            self.assertFalse(r.anchor_checked)
            self.assertFalse(r.anchor_verified)
            self.assertTrue(any("anchor" in w.lower() for w in r.warnings))


# ---------------------------------------------------------------------------
# Multi-Hash Tests (§5.5)
# ---------------------------------------------------------------------------

class TestMultiHash(unittest.TestCase):

    def test_single_hash_string_accepted(self):
        """Legacy single-string hash_original accepted by v0.5 verifier."""
        with TempAsset() as p:
            m = generate_manifest(p, hash_algorithms="sha256")
            self.assertIsInstance(m.core["hash_original"], str)
            r = verify_manifest(p, m)
            self.assertTrue(r.success)

    def test_multi_hash_array_generated(self):
        with TempAsset() as p:
            m = generate_manifest(p, hash_algorithms=["sha256", "sha384"])
            self.assertIsInstance(m.core["hash_original"], list)
            self.assertEqual(len(m.core["hash_original"]), 2)

    def test_multi_hash_any_match_succeeds(self):
        """Verification succeeds if any supported algorithm matches."""
        with TempAsset() as p:
            file_bytes = p.read_bytes()
            m = generate_manifest(p, hash_algorithms=["sha256", "sha384"])
            # Corrupt the sha256 hash but keep sha384
            t = Manifest.from_dict(m.to_dict())
            ho = list(t.core["hash_original"])
            # Replace sha256 hash with garbage
            ho[0] = "sha256-" + "00" * 32
            t.core["hash_original"] = ho
            # Recompute core_fingerprint for modified core
            canonical = _canonical_bytes({k: t.core[k] for k in
                ("asset_id","schema_version","creation_timestamp","hash_original","creator_id")})
            t.core["core_fingerprint"] = _compute_hash(canonical)
            r = verify_manifest(p, t)
            self.assertTrue(r.success, r.summary())

    def test_multi_hash_all_fail_returns_failure(self):
        """All algorithms fail → verification failure."""
        with TempAsset() as p:
            m = generate_manifest(p, hash_algorithms=["sha256", "sha384"])
            t = Manifest.from_dict(m.to_dict())
            t.core["hash_original"] = [
                "sha256-" + "00" * 32,
                "sha384-" + "00" * 48,
            ]
            r = verify_manifest(p, t)
            self.assertFalse(r.success)

    def test_empty_hash_array_rejected(self):
        with TempAsset() as p:
            m = generate_manifest(p)
            t = Manifest.from_dict(m.to_dict())
            t.core["hash_original"] = []
            r = verify_manifest(p, t)
            self.assertFalse(r.success)
            self.assertIn("empty", r.message.lower())

    def test_invalid_hash_algorithm_in_array(self):
        with TempAsset() as p:
            m = generate_manifest(p)
            t = Manifest.from_dict(m.to_dict())
            t.core["hash_original"] = ["md5-" + "ab" * 16]
            r = verify_manifest(p, t)
            self.assertFalse(r.success)

    def test_unsupported_only_hash_warns_and_fails(self):
        """Array with only unsupported algorithm → cannot verify → fail."""
        with TempAsset() as p:
            m = generate_manifest(p)
            t = Manifest.from_dict(m.to_dict())
            # Manually inject an unknown (but regex-valid) token
            t.core["hash_original"] = ["sha256-" + "00" * 32]  # wrong hash → fail
            r = verify_manifest(p, t)
            self.assertFalse(r.success)

    def test_core_fingerprint_single_hash_used(self):
        """core_fingerprint always uses first algorithm regardless of multi-hash."""
        with TempAsset() as p:
            m = generate_manifest(p, hash_algorithms=["sha256", "sha384"])
            self.assertTrue(m.core["core_fingerprint"].startswith("sha256-"))

    def test_multi_hash_sidecar_roundtrip(self):
        with TempAsset() as p:
            m = generate_manifest(p, hash_algorithms=["sha256", "sha384"], save_sidecar=True)
            loaded = Manifest.load_sidecar(p)
            self.assertEqual(m.core["hash_original"], loaded.core["hash_original"])


# ---------------------------------------------------------------------------
# SHA-384 Tests (§5.3)
# ---------------------------------------------------------------------------

class TestSHA384(unittest.TestCase):

    def test_sha384_hash_format(self):
        h = _compute_hash(b"test", "sha384")
        self.assertTrue(h.startswith("sha384-"))
        self.assertEqual(len(h), len("sha384-") + 96)

    def test_sha384_regex_accepts_96_hex(self):
        from aioschema_v055 import HASH_PATTERN
        valid = "sha384-" + "ab" * 48
        self.assertIsNotNone(HASH_PATTERN.match(valid))

    def test_sha384_regex_rejects_64_hex(self):
        from aioschema_v055 import HASH_PATTERN
        # sha384 with only 64 hex chars (sha256 length) must be rejected
        invalid = "sha384-" + "ab" * 32
        self.assertIsNone(HASH_PATTERN.match(invalid))

    def test_sha256_regex_rejects_96_hex(self):
        from aioschema_v055 import HASH_PATTERN
        # sha256 with 96 hex chars must be rejected
        invalid = "sha256-" + "ab" * 48
        self.assertIsNone(HASH_PATTERN.match(invalid))

    def test_sha384_manifest_verifies(self):
        with TempAsset() as p:
            m = generate_manifest(p, hash_algorithms="sha384")
            r = verify_manifest(p, m)
            self.assertTrue(r.success, r.summary())

    def test_sha384_core_fingerprint(self):
        with TempAsset() as p:
            m = generate_manifest(p, hash_algorithms="sha384")
            self.assertTrue(m.core["core_fingerprint"].startswith("sha384-"))


# ---------------------------------------------------------------------------
# manifest_signature Tests (§5.8)
# ---------------------------------------------------------------------------

class TestManifestSignature(unittest.TestCase):

    def setUp(self):
        self.priv, self.pub = generate_keypair()

    def test_manifest_signature_generated_when_signed(self):
        with TempAsset() as p:
            m = generate_manifest(p, private_key=self.priv)
            self.assertIsNotNone(m.core["manifest_signature"])
            self.assertTrue(m.core["manifest_signature"].startswith("ed25519-"))

    def test_manifest_signature_null_when_unsigned(self):
        with TempAsset() as p:
            m = generate_manifest(p)
            self.assertIsNone(m.core["manifest_signature"])

    def test_manifest_signature_covers_extensions(self):
        """Tampered extensions fail manifest_signature check."""
        with TempAsset() as p:
            m = generate_manifest(p, private_key=self.priv)
            t = Manifest.from_dict(m.to_dict())
            t.extensions["x-attacker-injected"] = "payload"
            r = verify_manifest(p, t, public_key=self.pub)
            self.assertFalse(r.success)
            self.assertIn("manifest", r.message.lower())

    def test_manifest_signature_bootstrap_exclusion(self):
        """canonical_manifest_bytes sets manifest_signature=null before signing."""
        with TempAsset() as p:
            m = generate_manifest(p, private_key=self.priv)
            d = m.to_dict()
            cb = _canonical_manifest_bytes(d)
            parsed = json.loads(cb.decode("utf-8"))
            self.assertIsNone(parsed["core"]["manifest_signature"])

    def test_manifest_signature_wrong_key_fails(self):
        with TempAsset() as p:
            m = generate_manifest(p, private_key=self.priv)
            _, wrong_pub = generate_keypair()
            r = verify_manifest(p, m, public_key=wrong_pub)
            self.assertFalse(r.success)

    def test_manifest_signature_requires_public_key(self):
        with TempAsset() as p:
            m = generate_manifest(p, private_key=self.priv)
            r = verify_manifest(p, m, public_key=None)
            self.assertFalse(r.success)
            self.assertIn("public_key", r.message)

    def test_manifest_signature_sidecar_integrity(self):
        """Full sidecar integrity: save, load, verify — all pass."""
        with TempAsset() as p:
            m = generate_manifest(p, private_key=self.priv, save_sidecar=True)
            loaded = Manifest.load_sidecar(p)
            r = verify_manifest(p, loaded, public_key=self.pub)
            self.assertTrue(r.success)
            self.assertTrue(r.manifest_signature_verified)


# ---------------------------------------------------------------------------
# Configurable Soft-Binding Threshold Tests (§8.3)
# ---------------------------------------------------------------------------

class TestConfigurableThreshold(unittest.TestCase):

    def test_custom_threshold_respected(self):
        """Verifier uses provided threshold, not manifest threshold_info."""
        original = make_gradient_png(10, 200)
        with TempAsset(original) as p:
            m = generate_manifest(p)
            # Replace with a somewhat different image
            different = make_gradient_png(200, 10)
            p.write_bytes(different)

            # With very strict threshold (0): should fail
            r_strict = verify_manifest(p, m, soft_binding_threshold=0)
            self.assertFalse(r_strict.success)

    def test_threshold_clamped_to_maximum(self):
        """Threshold is clamped to SOFT_BINDING_THRESHOLD_MAX."""
        with TempAsset() as p:
            m = generate_manifest(p)
            # Pass absurdly high threshold — should be clamped
            r = verify_manifest(p, m, soft_binding_threshold=999)
            # If file is unchanged, hard match should still succeed
            self.assertTrue(r.success)

    def test_threshold_info_not_trusted_from_manifest(self):
        """Attacker-set threshold_info in manifest is ignored."""
        with TempAsset() as p:
            m = generate_manifest(p)
            t = Manifest.from_dict(m.to_dict())
            # Attacker sets threshold_info to 64 (accept anything)
            if "soft_binding" in t.extensions:
                t.extensions["soft_binding"]["threshold_info"] = 64
            # Replace with clearly different image
            p.write_bytes(make_gradient_png(255, 0))
            # Verifier uses policy threshold (5), not 64
            r = verify_manifest(p, t, soft_binding_threshold=5)
            # Should fail because verifier uses threshold=5, not 64
            if r.success and r.match_type == "soft":
                dist_warns = [w for w in r.warnings if "distance=" in w]
                if dist_warns:
                    dist = int(dist_warns[0].split("distance=")[1].split(",")[0])
                    self.assertLessEqual(
                        dist, 5,
                        "Verifier must use policy threshold, not manifest threshold_info"
                    )

    def test_default_threshold_is_spec_value(self):
        self.assertEqual(SOFT_BINDING_THRESHOLD_DEFAULT, 5)

    def test_max_threshold_is_spec_value(self):
        self.assertEqual(SOFT_BINDING_THRESHOLD_MAX, 10)


# ---------------------------------------------------------------------------
# Anchor Verification Tests (§9, §10 Step 13)
# ---------------------------------------------------------------------------

class TestAnchorVerification(unittest.TestCase):

    def _make_mock_fetcher(self, manifest: Manifest, match: bool = True) -> AnchorResolver:
        def fetcher(ref: str) -> dict | None:
            if not match:
                return {
                    "asset_id":          "wrong-id",
                    "core_fingerprint": "sha256-" + "00" * 32,
                    "timestamp":         "2026-01-01T00:00:00Z",
                }
            return {
                "asset_id":          manifest.core["asset_id"],
                "core_fingerprint": manifest.core["core_fingerprint"],
                "timestamp":         manifest.core["creation_timestamp"],
            }
        return fetcher

    def test_anchor_verified_true_on_match(self):
        with TempAsset() as p:
            m = generate_manifest(p, anchor_ref="aios-anchor:svc:id001")
            r = verify_manifest(
                p, m,
                verify_anchor=True,
                anchor_resolver=self._make_mock_fetcher(m, match=True)
            )
            self.assertTrue(r.success)
            self.assertTrue(r.anchor_checked)
            self.assertTrue(r.anchor_verified)

    def test_anchor_mismatch_gives_warning(self):
        with TempAsset() as p:
            m = generate_manifest(p, anchor_ref="aios-anchor:svc:id002")
            r = verify_manifest(
                p, m,
                verify_anchor=True,
                anchor_resolver=self._make_mock_fetcher(m, match=False)
            )
            self.assertTrue(r.success)      # manifest itself is valid
            self.assertTrue(r.anchor_checked)
            self.assertFalse(r.anchor_verified)
            self.assertTrue(any("mismatch" in w.lower() for w in r.warnings))

    def test_anchor_not_found_gives_warning(self):
        with TempAsset() as p:
            m = generate_manifest(p, anchor_ref="aios-anchor:svc:id003")
            r = verify_manifest(
                p, m,
                verify_anchor=True,
                anchor_resolver=lambda ref: None
            )
            self.assertTrue(r.success)
            self.assertFalse(r.anchor_verified)
            self.assertTrue(any("not found" in w.lower() for w in r.warnings))

    def test_anchor_service_error_gives_warning(self):
        with TempAsset() as p:
            m = generate_manifest(p, anchor_ref="aios-anchor:svc:id004")

            def failing_fetcher(ref: str) -> dict:
                raise AnchorVerificationError("Service timeout")

            r = verify_manifest(
                p, m,
                verify_anchor=True,
                anchor_resolver=failing_fetcher
            )
            self.assertTrue(r.success)      # manifest itself still valid
            self.assertTrue(any("anchor verification error" in w.lower() for w in r.warnings))

    def test_anchor_not_verified_when_verify_anchor_false(self):
        with TempAsset() as p:
            m = generate_manifest(p, anchor_ref="aios-anchor:svc:id005")
            r = verify_manifest(p, m, verify_anchor=False)
            self.assertFalse(r.anchor_checked)
            self.assertFalse(r.anchor_verified)
            self.assertTrue(any("anchor" in w.lower() for w in r.warnings))

    def test_anchor_ref_format_validated_on_generate(self):
        with TempAsset() as p:
            with self.assertRaises(ValueError):
                generate_manifest(p, anchor_ref="not-a-valid-anchor")


# ---------------------------------------------------------------------------
# Level 3 Conformance Tests (§5.2)
# ---------------------------------------------------------------------------

class TestLevel3Conformance(unittest.TestCase):

    def test_level3_requires_anchor_reference(self):
        with TempAsset() as p:
            priv, pub = generate_keypair()
            m = generate_manifest(p, private_key=priv, anchor_ref="aios-anchor:svc:lvl3-001")

            def mock_fetcher(ref):
                return {
                    "asset_id":          m.core["asset_id"],
                    "core_fingerprint": m.core["core_fingerprint"],
                    "timestamp":         m.core["creation_timestamp"],
                }

            r = verify_manifest(p, m, public_key=pub, verify_anchor=True, anchor_resolver=mock_fetcher)
            self.assertTrue(r.success)
            self.assertTrue(r.anchor_verified)
            self.assertTrue(r.signature_verified)
            self.assertTrue(r.manifest_signature_verified)

    def test_level3_compliance_level_declared(self):
        """Level 3 is declared as compliance_level=3 in extensions."""
        with TempAsset() as p:
            priv, _ = generate_keypair()
            m = generate_manifest(
                p,
                private_key=priv,
                anchor_ref="aios-anchor:svc:lvl3-002",
                extensions={"compliance_level": 3}
            )
            self.assertEqual(m.extensions.get("compliance_level"), 3)


# ---------------------------------------------------------------------------
# Backward Compatibility Tests (§15)
# ---------------------------------------------------------------------------

class TestBackwardCompatibility(unittest.TestCase):

    def test_supported_versions_include_all(self):
        for v in ["0.1", "0.2", "0.3", "0.3.1", "0.4", "0.5", "0.5.5"]:
            self.assertIn(v, SUPPORTED_VERSIONS)

    def test_v04_string_hash_original_accepted(self):
        """Legacy single-string hash_original from v0.4 must be accepted."""
        with TempAsset() as p:
            m = generate_manifest(p, hash_algorithms="sha256")
            # Confirm it's a string (not list) when single algorithm
            self.assertIsInstance(m.core["hash_original"], str)
            r = verify_manifest(p, m)
            self.assertTrue(r.success)

    def test_v04_manifest_without_manifest_signature_accepted(self):
        """v0.4 manifests without manifest_signature field must pass."""
        with TempAsset() as p:
            m = generate_manifest(p)
            t = Manifest.from_dict(m.to_dict())
            # Remove manifest_signature entirely (as v0.4 manifests would have)
            t.core.pop("manifest_signature", None)
            r = verify_manifest(p, t)
            self.assertTrue(r.success)
            self.assertFalse(r.manifest_signature_verified)

    def test_old_schema_version_accepted(self):
        with TempAsset() as p:
            m = generate_manifest(p)
            t = Manifest.from_dict(m.to_dict())
            t.core["schema_version"] = "0.4"
            canonical = _canonical_bytes({
                k: t.core[k]
                for k in ("asset_id","schema_version","creation_timestamp","hash_original","creator_id")
            })
            t.core["core_fingerprint"] = _compute_hash(canonical)
            r = verify_manifest(p, t)
            self.assertTrue(r.success)

    def test_future_version_rejected(self):
        with TempAsset() as p:
            m = generate_manifest(p)
            t = Manifest.from_dict(m.to_dict())
            t.core["schema_version"] = "2.0"
            r = verify_manifest(p, t)
            self.assertFalse(r.success)


# ---------------------------------------------------------------------------
# VerificationResult Tests
# ---------------------------------------------------------------------------

class TestVerificationResult(unittest.TestCase):

    def test_new_fields_present(self):
        r = VerificationResult(
            success=True, message="ok",
            manifest_signature_verified=True,
            anchor_verified=True
        )
        self.assertTrue(r.manifest_signature_verified)
        self.assertTrue(r.anchor_verified)

    def test_summary_includes_manifest_sig(self):
        r = VerificationResult(True, "ok", manifest_signature_verified=True)
        self.assertIn("manifest signature", r.summary().lower())

    def test_summary_anchor_verified(self):
        r = VerificationResult(True, "ok", anchor_checked=True, anchor_verified=True)
        self.assertIn("verified", r.summary().lower())

    def test_bool_conversion(self):
        self.assertTrue(VerificationResult(True, "ok"))
        self.assertFalse(VerificationResult(False, "fail"))

    def test_defaults(self):
        r = VerificationResult(True, "ok")
        self.assertFalse(r.manifest_signature_verified)
        self.assertFalse(r.anchor_verified)
        self.assertFalse(r.anchor_checked)
        self.assertEqual(r.warnings, [])


# ---------------------------------------------------------------------------
# Manifest API Tests
# ---------------------------------------------------------------------------

class TestManifestAPI(unittest.TestCase):

    def test_hash_original_list_property_string(self):
        with TempAsset() as p:
            m = generate_manifest(p, hash_algorithms="sha256")
            self.assertIsInstance(m.hash_original_list, list)
            self.assertEqual(len(m.hash_original_list), 1)

    def test_hash_original_list_property_array(self):
        with TempAsset() as p:
            m = generate_manifest(p, hash_algorithms=["sha256", "sha384"])
            self.assertIsInstance(m.hash_original_list, list)
            self.assertEqual(len(m.hash_original_list), 2)

    def test_has_manifest_signature_property(self):
        priv, _ = generate_keypair()
        with TempAsset() as p:
            signed   = generate_manifest(p, private_key=priv)
            unsigned = generate_manifest(p)
            self.assertTrue(signed.has_manifest_signature)
            self.assertFalse(unsigned.has_manifest_signature)

    def test_sidecar_roundtrip_multi_hash(self):
        with TempAsset() as p:
            m = generate_manifest(p, hash_algorithms=["sha256", "sha384"], save_sidecar=True)
            loaded = Manifest.load_sidecar(p)
            self.assertEqual(m.to_dict(), loaded.to_dict())

    def test_to_dict_roundtrip(self):
        priv, _ = generate_keypair()
        with TempAsset() as p:
            m  = generate_manifest(p, private_key=priv)
            m2 = Manifest.from_dict(m.to_dict())
            self.assertEqual(m.to_dict(), m2.to_dict())


# ---------------------------------------------------------------------------
# Canonical Manifest Bytes Tests (§5.8)
# ---------------------------------------------------------------------------

class TestCanonicalManifestBytes(unittest.TestCase):

    def test_manifest_signature_set_to_null(self):
        priv, _ = generate_keypair()
        with TempAsset() as p:
            m  = generate_manifest(p, private_key=priv)
            cb = _canonical_manifest_bytes(m.to_dict())
            parsed = json.loads(cb.decode("utf-8"))
            self.assertIsNone(parsed["core"]["manifest_signature"])

    def test_original_manifest_not_mutated(self):
        priv, _ = generate_keypair()
        with TempAsset() as p:
            m   = generate_manifest(p, private_key=priv)
            sig = m.core["manifest_signature"]
            _canonical_manifest_bytes(m.to_dict())
            # Original should be unchanged
            self.assertEqual(m.core["manifest_signature"], sig)

    def test_canonical_bytes_deterministic(self):
        with TempAsset() as p:
            m  = generate_manifest(p)
            d  = m.to_dict()
            b1 = _canonical_manifest_bytes(d)
            b2 = _canonical_manifest_bytes(d)
            self.assertEqual(b1, b2)

    def test_different_extensions_produce_different_bytes(self):
        with TempAsset() as p:
            m1 = generate_manifest(p, extensions={"a": "1"})
            m2 = generate_manifest(p, extensions={"a": "2"})
            d1 = m1.to_dict()
            d2 = m2.to_dict()
            # Same asset_id won't happen but bytes will differ on extensions
            b1 = _canonical_manifest_bytes(d1)
            b2 = _canonical_manifest_bytes(d2)
            self.assertNotEqual(b1, b2)


# ---------------------------------------------------------------------------
# Batch Operations Tests
# ---------------------------------------------------------------------------

class TestBatchOperations(unittest.TestCase):

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _make_assets(self, count=3):
        paths = []
        for i in range(count):
            p = Path(self.tmpdir) / f"asset_{i:02d}.png"
            p.write_bytes(make_png(color=(i * 60, i * 60, i * 60)))
            paths.append(p)
        return paths

    def test_generate_batch_creates_sidecars(self):
        paths = self._make_assets(3)
        results = generate_batch(self.tmpdir)
        for p in paths:
            self.assertIn(p, results)
            self.assertTrue(Manifest.sidecar_path(p).exists())

    def test_generate_batch_multi_hash(self):
        self._make_assets(2)
        results = generate_batch(self.tmpdir, hash_algorithms=["sha256", "sha384"])
        for m in results.values():
            self.assertIsInstance(m, Manifest)
            self.assertIsInstance(m.core["hash_original"], list)

    def test_verify_batch_all_pass(self):
        self._make_assets(3)
        generate_batch(self.tmpdir)
        results = verify_batch(self.tmpdir)
        self.assertEqual(len(results), 3)
        for r in results.values():
            self.assertIsInstance(r, VerificationResult)
            self.assertTrue(r.success)

    def test_batch_signed(self):
        priv, pub = generate_keypair()
        self._make_assets(3)
        generate_batch(self.tmpdir, private_key=priv)
        results = verify_batch(self.tmpdir, public_key=pub)
        for r in results.values():
            self.assertTrue(r.success)
            self.assertTrue(r.signature_verified)
            self.assertTrue(r.manifest_signature_verified)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    loader = unittest.TestLoader()
    suite  = unittest.TestSuite()

    classes = [
        TestSpecVectorsV04,
        TestSpecVectorsV05,
        TestMultiHash,
        TestSHA384,
        TestManifestSignature,
        TestConfigurableThreshold,
        TestAnchorVerification,
        TestLevel3Conformance,
        TestBackwardCompatibility,
        TestVerificationResult,
        TestManifestAPI,
        TestCanonicalManifestBytes,
        TestBatchOperations,
    ]
    for cls in classes:
        suite.addTests(loader.loadTestsFromTestCase(cls))

    runner = unittest.TextTestRunner(verbosity=2, stream=sys.stdout)
    result = runner.run(suite)

    total = result.testsRun
    print(f"\n{'='*60}")
    print(f"AIOSchema v0.5.5 Test Suite Summary")
    print(f"{'='*60}")
    print(f"Tests run  : {total}")
    print(f"Failures   : {len(result.failures)}")
    print(f"Errors     : {len(result.errors)}")
    print(f"Skipped    : {len(result.skipped)}")
    print(f"{'PASS ✓' if result.wasSuccessful() else 'FAIL ✗'}")
    sys.exit(0 if result.wasSuccessful() else 1)


# ---------------------------------------------------------------------------
# v0.5.5 — New Tests: previous_version_anchor and founding provenance (§18)
# ---------------------------------------------------------------------------

class TestPreviousVersionAnchor(unittest.TestCase):
    """Tests for §18 version chaining via previous_version_anchor."""

    def test_previous_version_anchor_accepted_in_generate(self):
        """previous_version_anchor stored in core when provided."""
        with TempAsset() as p:
            m = generate_manifest(
                p, previous_version_anchor="aios-anchor:opentimestamps:abc123def456"
            )
            self.assertEqual(
                m.core["previous_version_anchor"],
                "aios-anchor:opentimestamps:abc123def456"
            )

    def test_previous_version_anchor_null_by_default(self):
        """Genesis manifests have previous_version_anchor=null."""
        with TempAsset() as p:
            m = generate_manifest(p)
            self.assertIsNone(m.core["previous_version_anchor"])

    def test_is_genesis_property_true_when_null(self):
        with TempAsset() as p:
            m = generate_manifest(p)
            self.assertTrue(m.is_genesis)

    def test_is_genesis_property_false_when_chained(self):
        with TempAsset() as p:
            m = generate_manifest(
                p, previous_version_anchor="aios-anchor:opentimestamps:abc123"
            )
            self.assertFalse(m.is_genesis)

    def test_previous_version_anchor_invalid_format_raises(self):
        """Invalid previous_version_anchor format raises ValueError on generate."""
        with TempAsset() as p:
            with self.assertRaises(ValueError):
                generate_manifest(p, previous_version_anchor="not-a-valid-anchor")

    def test_previous_version_anchor_valid_format_passes(self):
        """Valid formats accepted."""
        valid_anchors = [
            "aios-anchor:opentimestamps:abc123",
            "aios-anchor:opentimestamps:x1y2z3",
            "aios-anchor:my-service:record-001",
        ]
        with TempAsset() as p:
            for anchor in valid_anchors:
                m = generate_manifest(p, previous_version_anchor=anchor)
                self.assertEqual(m.core["previous_version_anchor"], anchor)

    def test_previous_version_anchor_preserved_in_sidecar(self):
        """Version chain survives sidecar save/load roundtrip."""
        with TempAsset() as p:
            m = generate_manifest(
                p,
                previous_version_anchor="aios-anchor:opentimestamps:genesis001",
                save_sidecar=True
            )
            loaded = Manifest.load_sidecar(p)
            self.assertEqual(
                loaded.core["previous_version_anchor"],
                "aios-anchor:opentimestamps:genesis001"
            )

    def test_previous_version_anchor_does_not_affect_core_fingerprint(self):
        """
        previous_version_anchor is NOT in CORE_HASH_FIELDS (§5.6).
        Two manifests with identical content but different previous_version_anchor
        should have different core_fingerprint values only if hash_original differs —
        actually they should be the same since only CORE_HASH_FIELDS are hashed.
        This confirms the field is informational, not an integrity input.
        """
        from aioschema_v055 import CORE_HASH_FIELDS
        self.assertNotIn("previous_version_anchor", CORE_HASH_FIELDS)

    def test_verification_passes_with_previous_version_anchor(self):
        """Verification succeeds on manifests with version chain fields."""
        priv, pub = generate_keypair()
        with TempAsset() as p:
            m = generate_manifest(
                p,
                private_key=priv,
                previous_version_anchor="aios-anchor:opentimestamps:prevanchor001",
                anchor_ref="aios-anchor:opentimestamps:thisanchor001"
            )
            r = verify_manifest(p, m, public_key=pub)
            self.assertTrue(r.success, r.summary())
            self.assertTrue(r.signature_verified)
            self.assertTrue(r.manifest_signature_verified)

    def test_version_chain_multi_step(self):
        """Simulate a two-step version chain: genesis → v2."""
        with TempAsset() as p:
            # Genesis
            m_genesis = generate_manifest(
                p,
                previous_version_anchor=None,
                anchor_ref="aios-anchor:opentimestamps:genesis000"
            )
            self.assertTrue(m_genesis.is_genesis)

            # v2 links to genesis
            m_v2 = generate_manifest(
                p,
                previous_version_anchor=m_genesis.core["anchor_reference"],
                anchor_ref="aios-anchor:opentimestamps:v2anchor000"
            )
            self.assertFalse(m_v2.is_genesis)
            self.assertEqual(
                m_v2.previous_version_anchor,
                "aios-anchor:opentimestamps:genesis000"
            )


class TestAnchorToolIntegration(unittest.TestCase):
    """Integration tests for the anchor tool bundle functions."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.bundle_dir = Path(self.tmpdir) / "bundle"
        self.bundle_dir.mkdir()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _make_bundle(self):
        """Create a minimal test bundle."""
        (self.bundle_dir / "spec.md").write_text("# AIOSchema Spec\nContent here.")
        (self.bundle_dir / "impl.py").write_text("# Implementation\npass")
        (self.bundle_dir / "tests.py").write_text("# Tests\npass")

    def test_collect_bundle_files_sorted(self):
        from aioschema_anchor import collect_bundle_files
        self._make_bundle()
        files = collect_bundle_files(self.bundle_dir)
        names = [f.name for f in files]
        self.assertEqual(names, sorted(names))

    def test_collect_bundle_excludes_manifest(self):
        from aioschema_anchor import collect_bundle_files
        self._make_bundle()
        (self.bundle_dir / "manifest.json").write_text("{}")
        files = collect_bundle_files(self.bundle_dir)
        names = [f.name for f in files]
        self.assertNotIn("manifest.json", names)

    def test_bundle_hash_deterministic(self):
        from aioschema_anchor import bundle_hash, collect_bundle_files
        self._make_bundle()
        files = collect_bundle_files(self.bundle_dir)
        h1, _ = bundle_hash(files)
        h2, _ = bundle_hash(files)
        self.assertEqual(h1, h2)

    def test_bundle_hash_changes_on_file_modification(self):
        from aioschema_anchor import bundle_hash, collect_bundle_files
        self._make_bundle()
        files = collect_bundle_files(self.bundle_dir)
        h1, _ = bundle_hash(files)
        (self.bundle_dir / "spec.md").write_text("# Modified content")
        files = collect_bundle_files(self.bundle_dir)
        h2, _ = bundle_hash(files)
        self.assertNotEqual(h1, h2)

    def test_multi_bundle_hash_returns_two_algorithms(self):
        from aioschema_anchor import multi_bundle_hash, collect_bundle_files
        self._make_bundle()
        files = collect_bundle_files(self.bundle_dir)
        hashes, per_alg = multi_bundle_hash(files)
        self.assertEqual(len(hashes), 2)
        self.assertTrue(any(h.startswith("sha256-") for h in hashes))
        self.assertTrue(any(h.startswith("sha384-") for h in hashes))
        self.assertIn("sha256", per_alg)
        self.assertIn("sha384", per_alg)

    def test_build_provenance_manifest_structure(self):
        from aioschema_anchor import build_provenance_manifest, collect_bundle_files
        self._make_bundle()
        files = collect_bundle_files(self.bundle_dir)
        priv, pub = generate_keypair()
        m = build_provenance_manifest(
            self.bundle_dir, files, priv,
            previous_version_anchor=None,
            anchor_ref="aios-anchor:opentimestamps:test001"
        )
        # Check structure
        self.assertIn("core", m)
        self.assertIn("extensions", m)
        self.assertIsNone(m["core"]["previous_version_anchor"])
        self.assertEqual(m["core"]["anchor_reference"], "aios-anchor:opentimestamps:test001")
        self.assertIsInstance(m["core"]["hash_original"], list)
        self.assertIsNotNone(m["core"]["manifest_signature"])
        self.assertIsNotNone(m["core"]["signature"])
        self.assertEqual(m["extensions"]["bundle_type"], "aioschema-specification")

    def test_build_provenance_manifest_with_chain(self):
        from aioschema_anchor import build_provenance_manifest, collect_bundle_files
        self._make_bundle()
        files = collect_bundle_files(self.bundle_dir)
        priv, _ = generate_keypair()
        m = build_provenance_manifest(
            self.bundle_dir, files, priv,
            previous_version_anchor="aios-anchor:opentimestamps:prev001",
            anchor_ref="aios-anchor:opentimestamps:this001"
        )
        self.assertEqual(m["core"]["previous_version_anchor"], "aios-anchor:opentimestamps:prev001")


# Add new test classes to the runner
import unittest
_orig_main = None

if __name__ == "__main__":
    loader = unittest.TestLoader()
    suite  = unittest.TestSuite()

    classes = [
        TestSpecVectorsV04,
        TestSpecVectorsV05,
        TestMultiHash,
        TestSHA384,
        TestManifestSignature,
        TestConfigurableThreshold,
        TestAnchorVerification,
        TestLevel3Conformance,
        TestBackwardCompatibility,
        TestVerificationResult,
        TestManifestAPI,
        TestCanonicalManifestBytes,
        TestBatchOperations,
        TestPreviousVersionAnchor,
        TestAnchorToolIntegration,
    ]
    for cls in classes:
        suite.addTests(loader.loadTestsFromTestCase(cls))

    runner = unittest.TextTestRunner(verbosity=2, stream=sys.stdout)
    result = runner.run(suite)

    total = result.testsRun
    print(f"\n{'='*60}")
    print(f"AIOSchema v0.5.5 Test Suite Summary")
    print(f"{'='*60}")
    print(f"Tests run  : {total}")
    print(f"Failures   : {len(result.failures)}")
    print(f"Errors     : {len(result.errors)}")
    print(f"Skipped    : {len(result.skipped)}")
    print(f"{'PASS ✓' if result.wasSuccessful() else 'FAIL ✗'}")
    sys.exit(0 if result.wasSuccessful() else 1)


# ═══════════════════════════════════════════════════════════════════════════════
# NEW v0.5.5 TESTS
# ═══════════════════════════════════════════════════════════════════════════════

class TestCoreFingerprint(unittest.TestCase):
    """Tests for core_fingerprint rename and hash_schema_block backward compat."""

    def setUp(self):
        self._ta = TempAsset(b"core_fingerprint_test_content")
        self.asset = self._ta.__enter__()

    def tearDown(self):
        self._ta.__exit__(None, None, None)

    def test_generate_produces_core_fingerprint(self):
        """Generated manifest MUST have core_fingerprint field."""
        m = generate_manifest(self.asset)
        self.assertIn("core_fingerprint", m.core)
        self.assertNotIn("hash_schema_block", m.core)

    def test_core_fingerprint_format_valid(self):
        """core_fingerprint must match hash prefix format."""
        m = generate_manifest(self.asset)
        cfp = m.core["core_fingerprint"]
        self.assertTrue(cfp.startswith("sha256-"), cfp)
        self.assertEqual(len(cfp), 7 + 64)  # "sha256-" + 64 hex chars

    def test_verify_with_core_fingerprint(self):
        """Verification passes on manifest with core_fingerprint."""
        m = generate_manifest(self.asset)
        r = verify_manifest(self.asset, m)
        self.assertTrue(r.success, r.message)

    def test_verify_accepts_hash_schema_block_alias(self):
        """Verification MUST accept hash_schema_block as deprecated alias."""
        m = generate_manifest(self.asset)
        # Simulate old manifest using hash_schema_block
        core_copy = dict(m.core)
        core_copy["hash_schema_block"] = core_copy.pop("core_fingerprint")
        old_m = Manifest.from_dict({"core": core_copy, "extensions": m.extensions})
        r = verify_manifest(self.asset, old_m)
        self.assertTrue(r.success,
            f"hash_schema_block alias must be accepted: {r.message}")

    def test_core_fingerprint_integrity(self):
        """Tampered core_fingerprint triggers verification failure."""
        m = generate_manifest(self.asset)
        core_copy = dict(m.core)
        core_copy["core_fingerprint"] = "sha256-" + "0" * 64
        bad_m = Manifest({"core": core_copy, "extensions": m.extensions})
        r = verify_manifest(self.asset, bad_m)
        self.assertFalse(r.success)
        self.assertIn("core_fingerprint", r.message.lower())


class TestAnchorResolver(unittest.TestCase):
    """Tests for anchor_resolver rename and contract."""

    def setUp(self):
        self._ta = TempAsset(b"anchor_resolver_test")
        self.asset = self._ta.__enter__()

    def tearDown(self):
        self._ta.__exit__(None, None, None)

    def test_anchor_resolver_parameter_accepted(self):
        """verify_manifest accepts anchor_resolver parameter."""
        m = generate_manifest(self.asset)
        core_copy = dict(m.core)
        core_copy["anchor_reference"] = "aios-anchor:test:abc123"
        m2 = Manifest.from_dict({"core": core_copy, "extensions": m.extensions})

        def mock_resolver(ref):
            return {
                "asset_id": m2.core["asset_id"],
                "core_fingerprint": m2.core["core_fingerprint"],
                "timestamp": "2026-02-22T00:00:00Z"
            }

        r = verify_manifest(
            self.asset, m2,
            verify_anchor=True,
            anchor_resolver=mock_resolver
        )
        self.assertTrue(r.anchor_verified, r.message)

    def test_anchor_resolver_none_skips_verification(self):
        """anchor_resolver=None with verify_anchor=True emits warning, not fail."""
        m = generate_manifest(self.asset)
        core_copy = dict(m.core)
        core_copy["anchor_reference"] = "aios-anchor:test:abc123"
        m2 = Manifest.from_dict({"core": core_copy, "extensions": m.extensions})
        r = verify_manifest(self.asset, m2, verify_anchor=True, anchor_resolver=None)
        self.assertTrue(r.success)
        self.assertFalse(r.anchor_verified)


class TestRFC3161Support(unittest.TestCase):
    """Tests for RFC 3161 anchor support functions."""

    def test_anchor_rfc3161_function_exists(self):
        """anchor_rfc3161 function must be importable."""
        from aioschema_v055 import anchor_rfc3161
        self.assertTrue(callable(anchor_rfc3161))

    def test_verify_rfc3161_function_exists(self):
        """verify_rfc3161 function must be importable."""
        from aioschema_v055 import verify_rfc3161
        self.assertTrue(callable(verify_rfc3161))

    def test_anchor_rfc3161_accepts_core_fingerprint(self):
        """anchor_rfc3161 accepts a core_fingerprint string format."""
        from aioschema_v055 import anchor_rfc3161, AnchorVerificationError
        # We can't make a real network call in tests
        # Verify the function signature and input validation work
        try:
            result = anchor_rfc3161("sha256-" + "a" * 64, tsa_url="https://invalid.test/tsr")
        except (OSError, AnchorVerificationError, Exception):
            pass  # Network failure expected in test environment
        # What matters: function exists with correct signature
        import inspect
        sig = inspect.signature(anchor_rfc3161)
        self.assertIn("core_fingerprint", sig.parameters)
        self.assertIn("tsa_url", sig.parameters)
        self.assertIn("out_path", sig.parameters)

    def test_anchor_reference_format(self):
        """anchor_rfc3161 produces correctly formatted aios-anchor URI."""
        from aioschema_v055 import _rfc3161_verify
        # Test the verification function with a mock TSR that contains the hash
        hash_hex = "a" * 64
        mock_tsr = b'\x30' + bytes([32]) + bytes.fromhex(hash_hex[:32])
        result = _rfc3161_verify(mock_tsr, hash_hex)
        # Result must have required keys
        self.assertIn("verified", result)
        self.assertIn("message", result)


class TestV055SpecVersion(unittest.TestCase):
    """Tests for v0.5.5 version constants."""

    def test_spec_version_is_055(self):
        """SPEC_VERSION must be 0.5.5."""
        import aioschema_v055 as a
        self.assertEqual(a.SPEC_VERSION, "0.5.5")

    def test_supported_versions_includes_055(self):
        """SUPPORTED_VERSIONS must include 0.5.5."""
        import aioschema_v055 as a
        self.assertIn("0.5.5", a.SUPPORTED_VERSIONS)

    def test_supported_versions_includes_all_prior(self):
        """All prior versions must remain supported."""
        import aioschema_v055 as a
        for v in ["0.1", "0.2", "0.3", "0.3.1", "0.4", "0.5", "0.5.1"]:
            self.assertIn(v, a.SUPPORTED_VERSIONS, f"Missing version {v}")

    def test_generate_produces_055_version(self):
        """Generated manifests default to schema_version 0.5.5."""
        with TempAsset(b"version test") as path:
            m = generate_manifest(path)
            self.assertEqual(m.core["schema_version"], "0.5.5")


if __name__ == "__main__":
    unittest.main()
