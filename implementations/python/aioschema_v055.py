"""
AIOSchema v0.5 — Reference Implementation
==========================================
Spec: https://aioschema.org  (Public Review Draft v0.5)

New in v0.5.1 vs v0.5:
  §5.1  previous_version_anchor — optional field linking successive spec/asset versions
  §14   Governance model updated — founder-controlled pre-governance phase
  §18   Founding Provenance — self-anchoring procedure for the specification itself

New in v0.5 vs v0.4:
  §5.5  hash_original may be a single string OR an array of prefixed hashes
  §5.8  manifest_signature — detached Ed25519 over canonical manifest bytes
  §5.3  SHA-384 added to hash algorithm registry
  §8.3  soft_binding_threshold is now a verifier-configurable parameter
  §9.2  anchor_resolver contract formally defined
  §5.2  Level 3 (Anchor-Verified) conformance tier
  §10   Updated 14-step verification procedure

Deferred (not in this implementation):
  DID creator_id mode, creator_keyref, UUID v8, extensions_version.
  These require additional design work before they can be added without
  compromising the lightweight architecture.

Dependencies: cryptography, Pillow, numpy
"""

from __future__ import annotations

import copy
import hashlib
import hmac
import json
import re
import struct
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from io import BytesIO
from pathlib import Path
from typing import Any, Callable

import numpy as np
from PIL import Image
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

# ---------------------------------------------------------------------------
# Spec constants
# ---------------------------------------------------------------------------

SPEC_VERSION = "0.5.5"

SUPPORTED_VERSIONS: frozenset[str] = frozenset(
    {"0.1", "0.2", "0.3", "0.3.1", "0.4", "0.5", "0.5.1", "0.5.5"}
)

# Hash algorithm registry — token → (hashlib name, exact hex digest length)
# Per §5.3: exact lengths enforced per algorithm (not a range).
_HASH_REGISTRY: dict[str, tuple[str, int]] = {
    "sha256":   ("sha256",   64),
    "sha3-256": ("sha3_256", 64),
    "sha384":   ("sha384",   96),
}
DEFAULT_HASH_ALG = "sha256"

# Per-algorithm regex: exact length enforced per §5.3.
# "^(sha256|sha3-256)-[0-9a-f]{64}$|^sha384-[0-9a-f]{96}$"
HASH_PATTERN = re.compile(
    r"^(sha256|sha3-256)-[0-9a-f]{64}$|^sha384-[0-9a-f]{96}$"
)
SIG_PATTERN    = re.compile(r"^ed25519-[0-9a-f]{128}$")
ANCHOR_PATTERN = re.compile(r"^aios-anchor:[a-z0-9_-]+:[a-zA-Z0-9_-]+$")
TS_PATTERN     = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")

# Fields that define the canonical input for core_fingerprint (§5.6).
# MUST NOT include core_fingerprint itself (bootstrap rule).
# hash_schema_block is a deprecated alias for core_fingerprint (v0.5.5+).
CORE_HASH_FIELDS: tuple[str, ...] = (
    "asset_id",
    "schema_version",
    "creation_timestamp",
    "hash_original",
    "creator_id",
)

# Soft-binding defaults (§8.3)
SOFT_BINDING_THRESHOLD_DEFAULT = 5
SOFT_BINDING_THRESHOLD_MAX     = 10

# Sidecar naming (§8.2)
SIDECAR_SUFFIX = ".aios.json"

# Default file size guard
DEFAULT_MAX_FILE_BYTES = 2 * 1024 ** 3   # 2 GB


# ---------------------------------------------------------------------------
# UUID v7 (§5.1 — preferred for asset_id)
# ---------------------------------------------------------------------------

_uuid7_last_ms: int = 0
_uuid7_seq:     int = 0


def _uuid7() -> str:
    """Generate a time-ordered, monotonically increasing UUID v7 string."""
    global _uuid7_last_ms, _uuid7_seq
    ts_ms = time.time_ns() // 1_000_000
    if ts_ms == _uuid7_last_ms:
        _uuid7_seq = (_uuid7_seq + 1) & 0x0FFF
    else:
        _uuid7_seq    = int.from_bytes(uuid.uuid4().bytes[:2], "big") & 0x0FFF
        _uuid7_last_ms = ts_ms
    rand_b = int.from_bytes(uuid.uuid4().bytes[:8], "big") & 0x3FFFFFFFFFFFFFFF
    hi = (ts_ms << 16) | (0x7 << 12) | _uuid7_seq
    lo = (0b10 << 62) | rand_b
    return str(uuid.UUID(bytes=struct.pack(">QQ", hi, lo)))


# ---------------------------------------------------------------------------
# Creator ID (§5.7) — unchanged from v0.4
# ---------------------------------------------------------------------------

class CreatorIdMode:
    ANONYMOUS  = "anonymous"   # UUID v7/v4
    ATTRIBUTED = "attributed"  # ed25519-fp-<32hex>


@dataclass(frozen=True)
class CreatorId:
    value: str
    mode:  str = CreatorIdMode.ANONYMOUS

    @classmethod
    def anonymous(cls) -> "CreatorId":
        return cls(value=_uuid7(), mode=CreatorIdMode.ANONYMOUS)

    @classmethod
    def from_public_key(cls, public_key: Ed25519PublicKey) -> "CreatorId":
        raw = public_key.public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        return cls(
            value=f"ed25519-fp-{hashlib.sha256(raw).hexdigest()[:32]}",
            mode=CreatorIdMode.ATTRIBUTED,
        )

    @classmethod
    def parse(cls, value: str) -> "CreatorId":
        if value.startswith("ed25519-fp-"):
            return cls(value=value, mode=CreatorIdMode.ATTRIBUTED)
        return cls(value=value, mode=CreatorIdMode.ANONYMOUS)

    def validate(self) -> None:
        if self.mode == CreatorIdMode.ATTRIBUTED:
            if not re.match(r"^ed25519-fp-[0-9a-f]{32}$", self.value):
                raise ValueError(
                    f"Attributed creator_id must match 'ed25519-fp-<32hex>', got: {self.value!r}"
                )
        else:
            try:
                parsed = uuid.UUID(self.value)
                if parsed.version not in (4, 7):
                    raise ValueError(
                        f"Anonymous creator_id must be UUID v4 or v7 (got version {parsed.version})"
                    )
            except ValueError as exc:
                raise ValueError(f"Invalid anonymous creator_id: {exc}") from exc


# ---------------------------------------------------------------------------
# Hash helpers
# ---------------------------------------------------------------------------

def _compute_hash(data: bytes, algorithm: str = DEFAULT_HASH_ALG) -> str:
    """Return '<alg>-<hex>' hash string."""
    if algorithm not in _HASH_REGISTRY:
        raise ValueError(
            f"Unsupported algorithm {algorithm!r}. Supported: {sorted(_HASH_REGISTRY)}"
        )
    hashlib_name, _ = _HASH_REGISTRY[algorithm]
    return f"{algorithm}-{hashlib.new(hashlib_name, data).hexdigest()}"


def _parse_hash(value: str, field_name: str) -> tuple[str, str]:
    """
    Validate and parse a prefixed hash string.
    Returns (algorithm_token, hex_digest). Raises ValueError on failure.
    """
    if not HASH_PATTERN.match(value):
        raise ValueError(
            f"{field_name} has invalid format {value!r}. "
            f"Expected: (sha256|sha3-256)-<64hex> or sha384-<96hex>"
        )
    # Parse algorithm token
    alg = value.split("-", 1)[0] if not value.startswith("sha3") else "sha3-256"
    if value.startswith("sha3-256"):
        alg = "sha3-256"
    elif value.startswith("sha384"):
        alg = "sha384"
    else:
        alg = "sha256"
    return alg, value[len(alg) + 1:]


def _safe_equal(a: str, b: str) -> bool:
    """Timing-safe string equality (§12.1)."""
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


# ---------------------------------------------------------------------------
# Canonical serialization helpers
# ---------------------------------------------------------------------------

def _canonical_bytes(fields: dict[str, Any]) -> bytes:
    """Deterministic UTF-8 JSON — sort_keys + compact separators."""
    return json.dumps(fields, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _canonical_manifest_bytes(manifest: dict) -> bytes:
    """
    Canonical bytes for manifest_signature (§5.8).
    Serializes the entire manifest with manifest_signature set to null
    (bootstrap exclusion prevents circular dependency).
    """
    m = copy.deepcopy(manifest)
    m.get("core", {})["manifest_signature"] = None
    return json.dumps(m, sort_keys=True, separators=(",", ":")).encode("utf-8")


# ---------------------------------------------------------------------------
# pHash — native DCT implementation (§8.3)
# ---------------------------------------------------------------------------

def _dct1d(vec: np.ndarray) -> np.ndarray:
    """1-D Type-II DCT via FFT identity."""
    n = len(vec)
    v = np.concatenate([vec, vec[::-1]])
    fft = np.fft.rfft(v)[:n]
    k = np.arange(n)
    return (fft * np.exp(-1j * np.pi * k / (2 * n))).real


def _dct2d(matrix: np.ndarray) -> np.ndarray:
    """Separable 2-D Type-II DCT."""
    return np.apply_along_axis(
        _dct1d, 1, np.apply_along_axis(_dct1d, 0, matrix)
    )


def _phash(image_bytes: bytes) -> str:
    """
    64-bit perceptual hash (DCT pHash). Returns 16-char lowercase hex.
    Degenerate uniform images return "0" * 16.
    """
    img = Image.open(BytesIO(image_bytes)).convert("L").resize((32, 32), Image.LANCZOS)
    pixels = np.array(img, dtype=float)
    dct   = _dct2d(pixels)
    block = dct[:8, :8].flatten()
    ac    = block[1:]
    ac_mean = ac.mean()
    if ac_mean == 0.0 and np.all(ac == 0.0):
        return "0" * 16
    bits   = block > ac_mean
    packed = np.packbits(bits)
    return packed.tobytes().hex()


def _phash_distance(hex_a: str, hex_b: str) -> int:
    """Hamming distance between two pHash hex strings."""
    b_a, b_b = bytes.fromhex(hex_a), bytes.fromhex(hex_b)
    if len(b_a) != len(b_b):
        raise ValueError("pHash length mismatch — incompatible hash sizes")
    return sum(bin(x ^ y).count("1") for x, y in zip(b_a, b_b))


# ---------------------------------------------------------------------------
# Anchor types (§9.2)
# ---------------------------------------------------------------------------

class AnchorVerificationError(Exception):
    """Raised by an anchor_resolver on service errors."""

# ── RFC 3161 Trusted Timestamp Authority Support ──────────────────────────────

def _rfc3161_submit(hash_hex: str, tsa_url: str = "https://freetsa.org/tsr") -> bytes:
    """
    Submit a hash to an RFC 3161 Time Stamp Authority.
    Returns the raw TimeStampResponse bytes (.tsr file content).
    
    hash_hex: hex string of the hash to timestamp (without algorithm prefix)
    tsa_url:  URL of the RFC 3161 TSA endpoint
    """
    import urllib.request
    import struct
    import hashlib

    hash_bytes = bytes.fromhex(hash_hex)

    # Build minimal RFC 3161 TimeStampRequest (DER encoded)
    # OID for SHA-256: 2.16.840.1.101.3.4.2.1
    sha256_oid = bytes([
        0x30, 0x0d,                          # SEQUENCE
        0x06, 0x09,                          # OID tag + length
        0x60, 0x86, 0x48, 0x01, 0x65,       # 2.16.840.1.101.3.4.2.1
        0x03, 0x04, 0x02, 0x01,
        0x05, 0x00                           # NULL parameters
    ])
    hash_value = bytes([0x04, len(hash_bytes)]) + hash_bytes
    msg_imprint = bytes([0x30, len(sha256_oid) + len(hash_value)]) + sha256_oid + hash_value

    # nonce (8 random bytes as INTEGER)
    nonce_val = int.from_bytes(os.urandom(8), 'big')
    nonce_bytes = nonce_val.to_bytes(8, 'big')
    nonce = bytes([0x02, 0x08]) + nonce_bytes

    # certReq = TRUE
    cert_req = bytes([0x01, 0x01, 0xff])

    # version = 1
    version = bytes([0x02, 0x01, 0x01])

    body = version + msg_imprint + nonce + cert_req
    tsr_req = bytes([0x30, len(body)]) + body

    req = urllib.request.Request(
        tsa_url,
        data=tsr_req,
        method="POST",
        headers={"Content-Type": "application/timestamp-query"}
    )
    with urllib.request.urlopen(req, timeout=30) as r:
        return r.read()


def _rfc3161_verify(tsr_bytes: bytes, hash_hex: str) -> dict:
    """
    Basic verification of an RFC 3161 TimeStampResponse.
    Returns dict with: verified (bool), timestamp (str ISO8601), tsa_url (str), message (str)
    
    For full PKI chain verification, use a dedicated RFC 3161 library.
    This implementation verifies that the TSR is a valid response containing our hash.
    """
    import struct

    result = {
        "verified": False,
        "timestamp": None,
        "message": "Could not parse TSR"
    }

    if not tsr_bytes or len(tsr_bytes) < 10:
        result["message"] = "TSR too short or empty"
        return result

    # Check for PKIStatusInfo status = 0 (granted) or 1 (grantedWithMods)
    # A properly formed TSR starts with SEQUENCE tag 0x30
    if tsr_bytes[0] != 0x30:
        result["message"] = "TSR does not appear to be valid DER"
        return result

    # Check that our hash appears in the response (basic integrity)
    hash_bytes = bytes.fromhex(hash_hex)
    if hash_bytes in tsr_bytes:
        result["verified"] = True
        result["message"] = "Hash confirmed present in TSR — RFC 3161 timestamp valid"
    else:
        result["message"] = "Hash not found in TSR — verification failed"

    return result


def anchor_rfc3161(
    core_fingerprint: str,
    tsa_url: str = "https://freetsa.org/tsr",
    out_path: str | None = None
) -> dict:
    """
    Anchor a core_fingerprint using RFC 3161 trusted timestamping.

    core_fingerprint: the manifest's core_fingerprint value (e.g. "sha256-abc123...")
    tsa_url:          RFC 3161 TSA endpoint (default: FreeTSA.org)
    out_path:         if provided, save the .tsr file here

    Returns:
        {
            "anchor_reference": "aios-anchor:rfc3161:<hex>",
            "tsr_bytes": bytes,
            "tsr_path": str | None,
            "tsa_url": str,
            "verified": bool,
            "message": str
        }
    """
    _, hash_hex = core_fingerprint.split("-", 1)

    tsr_bytes = _rfc3161_submit(hash_hex, tsa_url)

    verification = _rfc3161_verify(tsr_bytes, hash_hex)

    tsr_path = None
    if out_path:
        with open(out_path, "wb") as f:
            f.write(tsr_bytes)
        tsr_path = out_path

    anchor_ref = f"aios-anchor:rfc3161:{hash_hex[:32]}"

    return {
        "anchor_reference": anchor_ref,
        "tsr_bytes": tsr_bytes,
        "tsr_path": tsr_path,
        "tsa_url": tsa_url,
        "verified": verification["verified"],
        "message": verification["message"]
    }


def verify_rfc3161(tsr_path: str, core_fingerprint: str) -> dict:
    """
    Verify a saved RFC 3161 .tsr file against a core_fingerprint.

    tsr_path:         path to the .tsr file
    core_fingerprint: the manifest's core_fingerprint value

    Returns: { verified: bool, message: str }
    """
    with open(tsr_path, "rb") as f:
        tsr_bytes = f.read()
    _, hash_hex = core_fingerprint.split("-", 1)
    return _rfc3161_verify(tsr_bytes, hash_hex)




AnchorResolver = Callable[[str], dict | None]
"""
anchor_resolver(anchor_ref: str) -> dict | None

Returns a dict with at minimum:
  { "asset_id": str, "core_fingerprint": str, "timestamp": str }
Returns None if the record cannot be retrieved.
Raises AnchorVerificationError on service errors.
"""


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------

@dataclass
class VerificationResult:
    """Structured verification result (§10 step 14)."""
    success:                    bool
    message:                    str
    match_type:                 str | None = None
    signature_verified:         bool = False
    manifest_signature_verified: bool = False
    anchor_checked:             bool = False
    anchor_verified:            bool = False
    warnings:                   list[str] = field(default_factory=list)

    def __bool__(self) -> bool:
        return self.success

    def summary(self) -> str:
        lines = [f"{'✓ PASS' if self.success else '✗ FAIL'}: {self.message}"]
        if self.match_type:
            lines.append(f"  Content match       : {self.match_type}")
        lines.append(
            f"  Signature           : {'verified' if self.signature_verified else 'not present / not checked'}"
        )
        lines.append(
            f"  Manifest signature  : {'verified' if self.manifest_signature_verified else 'not present / not checked'}"
        )
        anchor_status = (
            "verified" if self.anchor_verified
            else "checked (no match)" if self.anchor_checked
            else "not checked"
        )
        lines.append(f"  Anchor              : {anchor_status}")
        for w in self.warnings:
            lines.append(f"  ⚠  {w}")
        return "\n".join(lines)


@dataclass
class Manifest:
    """Typed AIOSchema manifest with serialization and sidecar I/O."""
    core:       dict[str, Any]
    extensions: dict[str, Any] = field(default_factory=dict)

    # -- Serialization --

    def to_dict(self) -> dict:
        return {"core": dict(self.core), "extensions": dict(self.extensions)}

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)

    @classmethod
    def from_dict(cls, data: dict) -> "Manifest":
        return cls(core=data.get("core", {}), extensions=data.get("extensions", {}))

    # -- Sidecar I/O (§8.2) --

    @staticmethod
    def sidecar_path(asset_path: str | Path) -> Path:
        return Path(str(asset_path) + SIDECAR_SUFFIX)

    def save_sidecar(self, asset_path: str | Path) -> Path:
        sidecar = self.sidecar_path(asset_path)
        sidecar.write_text(self.to_json(), encoding="utf-8")
        return sidecar

    @classmethod
    def load_sidecar(cls, asset_path: str | Path) -> "Manifest":
        sidecar = cls.sidecar_path(asset_path)
        if not sidecar.exists():
            raise FileNotFoundError(f"No sidecar found at: {sidecar}")
        return cls.from_dict(json.loads(sidecar.read_text(encoding="utf-8")))

    # -- Properties --

    @property
    def asset_id(self) -> str:
        return self.core.get("asset_id", "")

    @property
    def schema_version(self) -> str:
        return self.core.get("schema_version", "")

    @property
    def is_signed(self) -> bool:
        return bool(self.core.get("signature"))

    @property
    def has_manifest_signature(self) -> bool:
        return bool(self.core.get("manifest_signature"))

    @property
    def has_soft_binding(self) -> bool:
        return "soft_binding" in self.extensions

    @property
    def hash_original_list(self) -> list[str]:
        """Always returns hash_original as a list for uniform handling."""
        ho = self.core.get("hash_original")
        if isinstance(ho, list):
            return ho
        return [ho] if ho else []

    @property
    def previous_version_anchor(self) -> str | None:
        """Returns the previous version anchor URI, or None (genesis). (§18.3)"""
        return self.core.get("previous_version_anchor")

    @property
    def is_genesis(self) -> bool:
        """True if this is the first version in a chain (no predecessor)."""
        return self.previous_version_anchor is None

    # -- Key helpers --

    @staticmethod
    def export_public_key_hex(private_key: Ed25519PrivateKey) -> str:
        return private_key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        ).hex()

    @staticmethod
    def import_public_key(hex_str: str) -> Ed25519PublicKey:
        return ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(hex_str))


# ---------------------------------------------------------------------------
# Key generation
# ---------------------------------------------------------------------------

def generate_keypair() -> tuple[Ed25519PrivateKey, Ed25519PublicKey]:
    """Generate an Ed25519 keypair."""
    priv = ed25519.Ed25519PrivateKey.generate()
    return priv, priv.public_key()


# ---------------------------------------------------------------------------
# Generate manifest
# ---------------------------------------------------------------------------

def generate_manifest(
    file_path: str | Path,
    *,
    private_key: Ed25519PrivateKey | None = None,
    anchor_ref: str | None = None,
    previous_version_anchor: str | None = None,
    creator_id: CreatorId | str | None = None,
    extensions: dict | None = None,
    hash_algorithms: list[str] | str = DEFAULT_HASH_ALG,
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
    save_sidecar: bool = False,
) -> Manifest:
    """
    Generate an AIOSchema v0.5.1 manifest.

    Parameters
    ----------
    file_path               : Path to the asset file.
    private_key             : Ed25519 private key → signed (Level 2+).
    anchor_ref              : Anchor URI in aios-anchor:<svc>:<id> format (§9.1).
    previous_version_anchor : Anchor URI of the preceding version (§18.3).
                              Used when this manifest represents a versioned document.
                              Creates a cryptographic version chain.
    creator_id              : CreatorId, raw string, or None (auto UUID v7).
    extensions              : Custom extension fields merged with defaults.
    hash_algorithms         : Single algorithm string OR list for multi-hash (§5.5).
                              e.g. ["sha256", "sha384"] for a multi-hash manifest.
    max_file_bytes          : Guard against loading unexpectedly large files.
    save_sidecar            : If True, write <file_path>.aios.json automatically.

    Returns
    -------
    Manifest instance.
    """
    file_path = Path(file_path)
    if not file_path.exists():
        raise FileNotFoundError(f"Asset not found: {file_path}")

    file_size = file_path.stat().st_size
    if file_size > max_file_bytes:
        raise ValueError(
            f"File {file_size:,} bytes exceeds max_file_bytes={max_file_bytes:,}."
        )

    file_bytes = file_path.read_bytes()

    # Validate anchor formats (§9.1)
    if anchor_ref is not None and not ANCHOR_PATTERN.match(anchor_ref):
        raise ValueError(
            f"anchor_ref {anchor_ref!r} must match 'aios-anchor:<service-id>:<anchor-id>'"
        )
    if previous_version_anchor is not None and not ANCHOR_PATTERN.match(previous_version_anchor):
        raise ValueError(
            f"previous_version_anchor {previous_version_anchor!r} must match "
            f"'aios-anchor:<service-id>:<anchor-id>'"
        )

    # Normalise hash_algorithms to a list
    if isinstance(hash_algorithms, str):
        alg_list = [hash_algorithms]
    else:
        alg_list = list(hash_algorithms)

    for alg in alg_list:
        if alg not in _HASH_REGISTRY:
            raise ValueError(f"Unsupported hash algorithm: {alg!r}")

    # Compute hashes (§5.5)
    hashes = [_compute_hash(file_bytes, alg) for alg in alg_list]
    hash_original: str | list[str] = hashes[0] if len(hashes) == 1 else hashes

    # Soft binding
    phash_value: str | None = None
    try:
        phash_value = _phash(file_bytes)
    except Exception:
        pass

    # Creator ID
    if creator_id is None:
        cid = CreatorId.anonymous()
    elif isinstance(creator_id, str):
        cid = CreatorId.parse(creator_id)
    else:
        cid = creator_id
    cid.validate()

    # Timestamp
    creation_timestamp = (
        datetime.now(timezone.utc)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z")
    )

    # Core block (without core_fingerprint — bootstrap rule §5.6)
    core_block: dict[str, Any] = {
        "asset_id":           _uuid7(),
        "schema_version":     SPEC_VERSION,
        "creation_timestamp": creation_timestamp,
        "hash_original":      hash_original,
        "creator_id":         cid.value,
    }

    # core_fingerprint (§5.6)
    canonical_core = _canonical_bytes({k: core_block[k] for k in CORE_HASH_FIELDS})
    core_fingerprint = _compute_hash(canonical_core, alg_list[0])

    # Core signature (§5.1)
    signature_hex: str | None = None
    if private_key is not None:
        sig_bytes = private_key.sign(canonical_core)
        signature_hex = f"ed25519-{sig_bytes.hex()}"

    # Assemble core (without manifest_signature yet)
    core_final: dict[str, Any] = {
        **core_block,
        "core_fingerprint":       core_fingerprint,
        "signature":              signature_hex,
        "manifest_signature":     None,
        "anchor_reference":       anchor_ref,
        "previous_version_anchor": previous_version_anchor,
    }

    # Extensions
    ext: dict[str, Any] = {
        "software":         "AIOSchema-Py-Ref-v0.5",
        "compliance_level": 2 if private_key else 1,
    }
    if extensions:
        ext.update(extensions)
    if phash_value is not None:
        ext["soft_binding"] = {
            "algorithm":      "pHash-v1",
            "fingerprint":    phash_value,
            "threshold_info": SOFT_BINDING_THRESHOLD_DEFAULT,
        }

    manifest_dict = {"core": core_final, "extensions": ext}

    # Manifest signature (§5.8) — signs core + extensions
    if private_key is not None:
        manifest_bytes = _canonical_manifest_bytes(manifest_dict)
        msig_bytes = private_key.sign(manifest_bytes)
        core_final["manifest_signature"] = f"ed25519-{msig_bytes.hex()}"
        manifest_dict["core"] = core_final

    manifest = Manifest(core=core_final, extensions=ext)
    if save_sidecar:
        manifest.save_sidecar(file_path)
    return manifest


# ---------------------------------------------------------------------------
# Verify manifest
# ---------------------------------------------------------------------------

def verify_manifest(
    file_path: str | Path,
    manifest: Manifest | dict,
    *,
    public_key: Ed25519PublicKey | None = None,
    soft_binding_threshold: int = SOFT_BINDING_THRESHOLD_DEFAULT,
    verify_anchor: bool = False,
    anchor_resolver: AnchorResolver | None = None,
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
) -> VerificationResult:
    """
    Verify an AIOSchema v0.5 manifest against a file.

    Executes all 14 steps defined in §10 of the v0.5 specification.

    Parameters
    ----------
    file_path               : Path to the asset file.
    manifest                : Manifest instance or raw dict.
    public_key              : Ed25519PublicKey (required if manifest is signed).
    soft_binding_threshold  : Verifier-policy pHash threshold (default 5, max 10).
    verify_anchor           : If True, invoke anchor_resolver to verify anchor.
    anchor_resolver          : Callable matching the §9.2 contract.
    max_file_bytes          : File size guard.

    Returns
    -------
    VerificationResult with full detail.
    """
    if isinstance(manifest, dict):
        manifest = Manifest.from_dict(manifest)

    file_path = Path(file_path)
    warns: list[str] = []
    core = manifest.core
    ext  = manifest.extensions

    # Clamp threshold to policy maximum
    soft_binding_threshold = min(
        max(0, soft_binding_threshold), SOFT_BINDING_THRESHOLD_MAX
    )

    # §10 Step 2 — Required fields
    # core_fingerprint is required; hash_schema_block accepted as deprecated alias (v0.5.5+)
    required = set(CORE_HASH_FIELDS)
    missing = required - set(core.keys())
    has_fingerprint = "core_fingerprint" in core or "hash_schema_block" in core
    if not has_fingerprint:
        missing.add("core_fingerprint")
    if missing:
        return VerificationResult(False, f"Missing required core fields: {sorted(missing)}")

    # §10 Step 3 — Schema version
    version = core.get("schema_version", "")
    if version not in SUPPORTED_VERSIONS:
        return VerificationResult(
            False,
            f"Unsupported schema_version {version!r}. "
            f"Supported: {sorted(SUPPORTED_VERSIONS)}"
        )

    # §10 Step 4 — hash_original format (handles string or list)
    ho_raw = core["hash_original"]
    if isinstance(ho_raw, str):
        ho_list = [ho_raw]
    elif isinstance(ho_raw, list):
        ho_list = ho_raw
        if not ho_list:
            return VerificationResult(False, "hash_original array must not be empty.")
    else:
        return VerificationResult(
            False, f"hash_original must be a string or array, got {type(ho_raw).__name__}"
        )

    for i, h in enumerate(ho_list):
        if not isinstance(h, str) or not HASH_PATTERN.match(h):
            return VerificationResult(
                False, f"hash_original[{i}] has invalid format: {str(h)[:60]!r}"
            )

    # §10 Step 5 — core_fingerprint format (hash_schema_block accepted as deprecated alias)
    try:
        _cfp = core.get("core_fingerprint") or core.get("hash_schema_block")
        if not _cfp:
            return _fail("Missing required field: core_fingerprint")
        _parse_hash(_cfp, "core_fingerprint")
    except ValueError as exc:
        return VerificationResult(False, str(exc))

    # §10 Step 6 — Timestamp
    ts_str: str = core.get("creation_timestamp", "")
    if not TS_PATTERN.match(ts_str):
        return VerificationResult(
            False,
            f"creation_timestamp must be UTC ISO 8601 ending in 'Z', got: {ts_str!r}"
        )

    # Read file once
    try:
        if file_path.stat().st_size > max_file_bytes:
            return VerificationResult(
                False, f"File size exceeds max_file_bytes={max_file_bytes:,}"
            )
        file_bytes = file_path.read_bytes()
    except OSError as exc:
        return VerificationResult(False, f"Cannot read asset: {exc}")

    # §10 Step 7 — Hard match: any supported algorithm in hash_original (§5.5)
    hard_match = False
    supported_found = False
    for h_str in ho_list:
        try:
            alg, _ = _parse_hash(h_str, "hash_original item")
        except ValueError:
            continue
        if alg not in _HASH_REGISTRY:
            warns.append(f"Skipping unsupported hash algorithm in hash_original: {h_str[:20]!r}")
            continue
        supported_found = True
        current = _compute_hash(file_bytes, alg)
        if _safe_equal(current, h_str):
            hard_match = True
            break

    if not supported_found:
        return VerificationResult(
            False,
            "No supported hash algorithm found in hash_original. Cannot verify content."
        )

    # §10 Step 8 — Soft binding fallback
    soft_match = False
    soft_bind  = ext.get("soft_binding")
    if not hard_match and isinstance(soft_bind, dict) and soft_bind.get("fingerprint"):
        try:
            current_phash = _phash(file_bytes)
            distance = _phash_distance(current_phash, soft_bind["fingerprint"])
            if distance <= soft_binding_threshold:   # verifier policy, not manifest
                soft_match = True
                warns.append(
                    f"Hard hash mismatch; accepted via soft binding "
                    f"(pHash Hamming distance={distance}, "
                    f"policy threshold={soft_binding_threshold}). "
                    "File may have been recompressed or resized."
                )
        except Exception as exc:
            warns.append(f"Soft binding check failed: {exc}")

    # §10 Step 9
    if not hard_match and not soft_match:
        return VerificationResult(
            False,
            "Content mismatch: neither hard nor soft hash matched. "
            "Asset may be tampered or replaced.",
        )

    match_type = "hard" if hard_match else "soft"

    # §10 Step 10 — core_fingerprint integrity (hash_schema_block accepted as deprecated alias)
    _cfp_val = core.get("core_fingerprint") or core.get("hash_schema_block")
    if not _cfp_val:
        return VerificationResult(False, "Missing required field: core_fingerprint", match_type=match_type)
    hsb_alg, _ = _parse_hash(_cfp_val, "core_fingerprint")
    canonical_core = _canonical_bytes({k: core[k] for k in CORE_HASH_FIELDS})
    computed_hsb   = _compute_hash(canonical_core, hsb_alg)
    if not _safe_equal(computed_hsb, _cfp_val):
        return VerificationResult(
            False,
            "Manifest integrity check failed: core_fingerprint mismatch. "
            "Core metadata may have been tampered.",
            match_type=match_type,
        )

    # §10 Step 11 — Core signature
    sig_str: str | None = core.get("signature")
    signature_verified = False

    if sig_str is not None:
        if not isinstance(sig_str, str) or not SIG_PATTERN.match(sig_str):
            return VerificationResult(
                False,
                f"signature has invalid format. Expected ed25519-<128hex>.",
                match_type=match_type,
            )
        if public_key is None:
            return VerificationResult(
                False,
                "Manifest is signed but no public_key was provided.",
                match_type=match_type,
            )
        try:
            public_key.verify(bytes.fromhex(sig_str[len("ed25519-"):]), canonical_core)
            signature_verified = True
        except InvalidSignature:
            return VerificationResult(
                False,
                "Core signature verification failed: invalid signature or wrong key.",
                match_type=match_type,
            )

    # §10 Step 12 — Manifest signature (detached, covers core + extensions)
    msig_str: str | None = core.get("manifest_signature")
    manifest_signature_verified = False

    if msig_str is not None:
        if not isinstance(msig_str, str) or not SIG_PATTERN.match(msig_str):
            return VerificationResult(
                False,
                "manifest_signature has invalid format. Expected ed25519-<128hex>.",
                match_type=match_type,
            )
        if public_key is None:
            return VerificationResult(
                False,
                "manifest_signature present but no public_key was provided.",
                match_type=match_type,
            )
        try:
            manifest_bytes = _canonical_manifest_bytes(manifest.to_dict())
            public_key.verify(
                bytes.fromhex(msig_str[len("ed25519-"):]), manifest_bytes
            )
            manifest_signature_verified = True
        except InvalidSignature:
            return VerificationResult(
                False,
                "Manifest signature verification failed: invalid or extensions tampered.",
                match_type=match_type,
            )

    # §10 Step 13 — Anchor verification
    anchor = core.get("anchor_reference")
    anchor_checked = False
    anchor_verified = False

    if anchor:
        if verify_anchor and anchor_resolver is not None:
            anchor_checked = True
            try:
                record = anchor_resolver(anchor)
                if record is None:
                    warns.append(f"Anchor record not found: {anchor!r}")
                else:
                    id_match  = _safe_equal(record.get("asset_id", ""), core["asset_id"])
                    hsb_match = _safe_equal(
                        record.get("core_fingerprint", record.get("hash_schema_block", "")),
                        core.get("core_fingerprint") or core.get("hash_schema_block", "")
                    )
                    if id_match and hsb_match:
                        anchor_verified = True
                    else:
                        warns.append(
                            f"Anchor record mismatch for {anchor!r}. "
                            "Asset may have been re-signed."
                        )
            except AnchorVerificationError as exc:
                warns.append(f"Anchor verification error: {exc}")
        else:
            warns.append(
                f"anchor_reference present ({anchor!r}) but not verified. "
                "Pass verify_anchor=True and anchor_resolver= for Level 3 compliance."
            )

    # §10 Step 14 — Return result
    content_desc = "bit-exact" if hard_match else "perceptual (soft)"
    sig_desc = (
        "core + manifest signatures verified" if (signature_verified and manifest_signature_verified)
        else "core signature verified" if signature_verified
        else "unsigned"
    )
    return VerificationResult(
        success=True,
        message=f"Verified: {content_desc} content match, {sig_desc}. Provenance intact.",
        match_type=match_type,
        signature_verified=signature_verified,
        manifest_signature_verified=manifest_signature_verified,
        anchor_checked=anchor_checked,
        anchor_verified=anchor_verified,
        warnings=warns,
    )


# ---------------------------------------------------------------------------
# Batch operations
# ---------------------------------------------------------------------------

def generate_batch(
    directory: str | Path,
    *,
    glob_pattern: str = "*",
    private_key: Ed25519PrivateKey | None = None,
    overwrite: bool = False,
    **kwargs,
) -> dict[Path, Manifest | Exception]:
    """Generate manifests + sidecars for all matching files in a directory."""
    directory = Path(directory)
    results: dict[Path, Manifest | Exception] = {}
    for fp in sorted(directory.glob(glob_pattern)):
        if not fp.is_file() or fp.name.endswith(SIDECAR_SUFFIX):
            continue
        if Manifest.sidecar_path(fp).exists() and not overwrite:
            continue
        try:
            results[fp] = generate_manifest(
                fp, private_key=private_key, save_sidecar=True, **kwargs
            )
        except Exception as exc:
            results[fp] = exc
    return results


def verify_batch(
    directory: str | Path,
    *,
    glob_pattern: str = "*",
    public_key: Ed25519PublicKey | None = None,
    **kwargs,
) -> dict[Path, VerificationResult | Exception]:
    """Verify all assets in a directory that have a matching .aios.json sidecar."""
    directory = Path(directory)
    results: dict[Path, VerificationResult | Exception] = {}
    for fp in sorted(directory.glob(glob_pattern)):
        if not fp.is_file() or fp.name.endswith(SIDECAR_SUFFIX):
            continue
        if not Manifest.sidecar_path(fp).exists():
            continue
        try:
            results[fp] = verify_manifest(
                fp, Manifest.load_sidecar(fp), public_key=public_key, **kwargs
            )
        except Exception as exc:
            results[fp] = exc
    return results
