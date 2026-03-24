# AIOSchema Field Reference Guide
## v0.5.5

**Document ID:** as-doc-ref-field-v0.5.5
**Spec:** AIOSchema v0.5.5 Specification — https://aioschema.org
**License:** CC-BY 4.0

This document is a complete field-by-field reference for AIOSchema v0.5.5 manifests.
It is a companion to the specification — not a replacement. For normative requirements,
consult the specification directly.

---

## Manifest Structure

Every AIOSchema manifest is a JSON object with two top-level keys:

```json
{
  "core":       { ... },   // required
  "extensions": { ... }    // optional
}
```

---

## Core Block Fields

The Core Block is required and immutable once created. No Core Block field may be
modified after `core_fingerprint` is computed without invalidating the manifest.

The five fields included in the `core_fingerprint` computation are marked **[FP]**.
These are the mathematically sealed fields — changing any one of them invalidates
the fingerprint and fails Level 1 verification.

---

### `asset_id` [FP]

| Property | Value |
|---|---|
| **Type** | String |
| **Required** | MUST |
| **Format** | UUID v7 (SHOULD) or UUID v4 (MAY) |
| **Verification level** | L1 |
| **If absent** | Verification MUST fail |
| **If malformed** | Verification MUST fail |

A universally unique identifier for this asset manifest. UUID v7 is preferred — it is
time-ordered and sortable. UUID v4 is acceptable. No other formats are permitted in
conforming implementations.

**Example:**
```json
"asset_id": "019d0d52-1d18-7024-abe3-ba37ea4796ba"
```

---

### `schema_version` [FP]

| Property | Value |
|---|---|
| **Type** | String |
| **Required** | MUST |
| **Accepted values** | `"0.1"` `"0.2"` `"0.3"` `"0.3.1"` `"0.4"` `"0.5"` `"0.5.1"` `"0.5.5"` |
| **Verification level** | L1 |
| **If absent** | Verification MUST fail |
| **If unknown value** | Verification MUST fail with unsupported version error |

Identifies which version of the AIOSchema specification this manifest conforms to.
Verifiers MUST reject unknown versions with a clear error message identifying the
unsupported version string.

**Example:**
```json
"schema_version": "0.5.5"
```

---

### `creation_timestamp` [FP]

| Property | Value |
|---|---|
| **Type** | String |
| **Required** | MUST |
| **Format** | ISO 8601 UTC — `YYYY-MM-DDTHH:MM:SSZ` |
| **Pattern** | `^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$` |
| **Verification level** | L1 |
| **If absent** | Verification MUST fail |
| **If non-UTC (offset notation)** | Verification MUST fail |
| **If invalid format** | Verification MUST fail |

The timestamp at which the manifest was created. MUST be UTC — the trailing `Z` is
required and enforced. Offset notation (e.g. `+05:00`) is explicitly rejected.
Implementations MUST normalise to UTC before writing this field.

**Example:**
```json
"creation_timestamp": "2026-03-22T14:55:00Z"
```

---

### `hash_original` [FP]

| Property | Value |
|---|---|
| **Type** | String **or** Array\<String\> |
| **Required** | MUST |
| **Format** | `<alg>-<hex>` — algorithm token followed by hex digest |
| **Pattern (per entry)** | `^(sha256\|sha3-256)-[0-9a-f]{64}$\|^sha384-[0-9a-f]{96}$` |
| **Verification level** | L1 |
| **If absent** | Verification MUST fail |
| **If malformed** | Verification MUST fail |
| **If unsupported algorithm** | Skip with warning; fail only if no supported algorithm found |

A cryptographic hash (or array of hashes) of the original binary asset bytes.
The single-string form is the legacy format. The array form supports multiple
algorithms for durability.

**Single-hash example:**
```json
"hash_original": "sha256-e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
```

**Multi-hash example:**
```json
"hash_original": [
  "sha256-e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "sha384-38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
]
```

**Supported algorithms:**

| Token | Digest length (hex chars) | Status |
|---|---|---|
| `sha256` | 64 | REQUIRED |
| `sha3-256` | 64 | OPTIONAL |
| `sha384` | 96 | OPTIONAL |

Multi-hash verification: if **any** supported algorithm matches, hard match succeeds.
If all supported hashes are present but none match, hard match fails. If no supported
algorithm is found in the array, verification MUST fail.

---

### `creator_id` [FP]

| Property | Value |
|---|---|
| **Type** | String |
| **Required** | MUST |
| **Format** | UUID v7/v4 (anonymous mode) or `ed25519-fp-<32hex>` (attributed mode) |
| **Verification level** | L1 |
| **If absent** | Verification MUST fail |
| **If malformed** | Verification MUST fail |

Identifies the creator of the manifest. Two modes are supported:

| Mode | Format | Description |
|---|---|---|
| Anonymous | UUID v7 (SHOULD) or UUID v4 (MAY) | No identity disclosed. Auto-generated if not supplied. |
| Attributed | `ed25519-fp-<32hex>` | SHA-256 fingerprint of Ed25519 public key (first 128 bits = 32 hex chars). Persistent across all manifests signed with the same key. |

Verifiers infer the mode from the value: `ed25519-fp-` prefix → attributed; valid UUID → anonymous.

`creator_id` is a permanent identity anchor. It does not change when keys rotate — keys
are replaceable tools, `creator_id` is the identity. See `signature` for key usage.

**Anonymous example:**
```json
"creator_id": "019d0d52-1d17-7062-bbf8-3bbaf172122c"
```

**Attributed example:**
```json
"creator_id": "ed25519-fp-bac64206390ddefc552ade9038c1ae18"

```

---

### `core_fingerprint`

| Property | Value |
|---|---|
| **Type** | String |
| **Required** | MUST |
| **Format** | `sha256-<64hex>` (same pattern as hash_original) |
| **Pattern** | `^(sha256\|sha3-256)-[0-9a-f]{64}$\|^sha384-[0-9a-f]{96}$` |
| **Verification level** | L1 |
| **If absent** | Verification MUST fail |
| **If mismatch on recomputation** | Verification MUST fail |

A tamper-evident seal over the five Core Block fields. Computed as the SHA-256 hash of
the canonical JSON serialization of exactly these fields in alphabetical order:

```
CORE_HASH_FIELDS = [
  "asset_id", "schema_version", "creation_timestamp",
  "hash_original", "creator_id"
]
```

**Bootstrap rule:** `core_fingerprint` MUST NOT be included in its own computation.

**Canonicalization (reference — Python):**
```python
canonical = json.dumps(
    {k: core_block[k] for k in CORE_HASH_FIELDS},
    sort_keys=True, separators=(',', ':')
).encode('utf-8')
core_fingerprint = "sha256-" + hashlib.sha256(canonical).hexdigest()
```

**Example:**
```json
"core_fingerprint": "sha256-55e6ccdec47fea01c48da35bc5083025812083cbdbc1706a9be0d6edaf7fa5d3"
```

---

### `signature`

| Property | Value |
|---|---|
| **Type** | String or null |
| **Required** | SHOULD (null if no signing key available) |
| **Format** | `ed25519-<128hex>` |
| **Pattern** | `^ed25519-[0-9a-f]{128}$` |
| **Verification level** | L2 |
| **If null or absent** | Verification continues — absence is NOT a failure at L1 |
| **If present and non-null** | Verifier MUST verify; FAIL if invalid |
| **If present but no public key supplied** | Verifier MUST fail with clear error |

An Ed25519 signature over the canonical Core Block bytes. Signs only the core fields —
not extensions. Use `manifest_signature` when extensions also need integrity protection.

`signature` is tied to a specific key, not to `creator_id`. Key rotation does not
change `creator_id` — it produces a new `signature` with the new key. The identity
persists; the signing tool changes.

**Example:**
```json
"signature": "ed25519-a1b2c3d4...128hexchars...e5f6"
```

---

### `manifest_signature`

| Property | Value |
|---|---|
| **Type** | String or null |
| **Required** | SHOULD when sidecar integrity required (null otherwise) |
| **Format** | `ed25519-<128hex>` |
| **Pattern** | `^ed25519-[0-9a-f]{128}$` |
| **Verification level** | L2 |
| **If null or absent** | Verification continues — absence is NOT a failure at L1 |
| **If present and non-null** | Verifier MUST verify; FAIL if invalid |

A detached Ed25519 signature over the **canonical manifest bytes** — the entire manifest
including extensions, with `manifest_signature` itself set to null before signing
(bootstrap exclusion, prevents circular dependency).

Use `manifest_signature` when extensions carry material metadata (e.g. `soft_binding`,
`ai_model_used`) that also needs integrity protection. A sidecar with a valid
`manifest_signature` is self-verifying without access to the original asset.

**Canonical manifest bytes procedure:**
1. Deep-copy the manifest
2. Set `core.manifest_signature` to null
3. Serialize: `sort_keys=True`, `separators=(',',':')`, UTF-8 encoded
4. Sign the resulting bytes with Ed25519

**Example:**
```json
"manifest_signature": "ed25519-a1b2c3d4...128hexchars...e5f6"
```

---

### `anchor_reference`

| Property | Value |
|---|---|
| **Type** | String or null |
| **Required** | SHOULD at L3 (null or absent at L1/L2) |
| **Format** | `aios-anchor:<service-id>:<anchor-id>` |
| **Pattern** | `^aios-anchor:[a-z0-9_-]+:[a-zA-Z0-9_-]+$` |
| **Verification level** | L3 |
| **If null or absent** | Verification continues without anchor check |
| **If present, verify_anchor=true** | Verifier MUST call anchor_resolver; FAIL if mismatch |
| **If present, verify_anchor=false** | Emit warning; anchor_verified=false; continue |

A URI pointing to an external cryptographic timestamp anchor for this manifest.
The anchor independently records that this manifest existed at a specific point in time,
without any party being able to retroactively alter the record.

**URI structure:**
- `service-id` — registered anchor service identifier (e.g. `rfc3161`, `ots-bitcoin`)
- `anchor-id` — service-specific record identifier

**Example:**
```json
"anchor_reference": "aios-anchor:rfc3161:19e83aa5311cfb058c7555fc6b70103c"
```

---

### `previous_version_anchor`

| Property | Value |
|---|---|
| **Type** | String or null |
| **Required** | MAY (SHOULD for versioned documents) |
| **Format** | `aios-anchor:<service-id>:<anchor-id>` |
| **Pattern** | `^aios-anchor:[a-z0-9_-]+:[a-zA-Z0-9_-]+$` |
| **Verification level** | Informational — verifiers MUST NOT fail if absent or unresolvable |
| **If null or absent** | Verification continues normally |

Links this manifest to the anchor of its immediately preceding version, creating a
cryptographic chain of custody across versions. Used for versioned documents (e.g.
the AIOSchema specification itself), asset lineages, and any content that evolves
over time while maintaining provenance continuity.

Verifiers MUST NOT fail verification if this field is absent or if the anchor is
unresolvable — it is informational provenance, not an integrity check.

**Example:**
```json
"previous_version_anchor": "aios-anchor:ots-bitcoin:a1b2c3d4e5f6..."
```

---

## Extension Block Fields

The `extensions` block is optional. Extensions MUST NOT affect the `core_fingerprint`
computation. When `manifest_signature` is present, extensions ARE included in the
signature scope.

### Namespacing Rules

| Prefix | Usage |
|---|---|
| No prefix | Official registered extension fields (see §11 of the spec) |
| `x-<vendor>-` | Custom vendor or experimental fields |

Custom fields MUST NOT use names that conflict with any Core Block field or any
registered extension field name.

---

### Registered Extension Fields

The following fields are defined in §11 of the specification.

| Field | Type | Description | Maps to |
|---|---|---|---|
| `camera_model` | String | Device make and model | EXIF Make+Model / `xmp:CreatorTool` |
| `exposure_time` | String | Shutter speed e.g. `"1/120"` | EXIF ExposureTime |
| `iso` | Integer | ISO sensitivity value | EXIF ISOSpeedRatings |
| `software` | String | Software used to create or edit | EXIF Software / `xmp:CreatorTool` |
| `ai_model_used` | String or null | AI model identifier; null if not AI-generated | `aioschema:aiModelUsed` |
| `ai_model_version` | String or null | AI model version string | — |
| `license` | String | SPDX identifier e.g. `"CC-BY-4.0"` | `xmpRights:UsageTerms` |
| `soft_binding` | Object | pHash soft binding — see below | `aioschema:pHashFingerprint` |
| `compliance_level` | Integer | Self-declared conformance level (1, 2, or 3). Informational only. | — |
| `asset_name` | String | Original filename or human-readable asset name | — |
| `asset_type` | String | Asset type e.g. `"document"`, `"image"`, `"video"` | — |
| `description` | String | Free-text description of the asset | — |

---

### `soft_binding` Object

Used for perceptual hash soft binding on image and video assets. Required at Level 2
for image/video assets.

```json
"soft_binding": {
  "algorithm":      "pHash-v1",
  "fingerprint":    "f8e4c2a196b3d750",
  "threshold_info": 5
}
```

| Field | Type | Description |
|---|---|---|
| `algorithm` | String | Perceptual hash algorithm. Currently: `pHash-v1` |
| `fingerprint` | String | 16-character hex pHash digest of the asset |
| `threshold_info` | Integer | Informational only — the threshold used when generating. Verifiers MUST NOT read this value for policy decisions. |

**Critical:** verifiers MUST use their own `soft_binding_threshold` parameter (default: 5,
maximum: 10). The `threshold_info` in the manifest is documentation only and MUST be
ignored for verification policy.

---

## Verification Result Fields

A conforming verifier returns a result object with the following fields:

| Field | Type | Description |
|---|---|---|
| `success` | Boolean | True if verification passed at the requested level |
| `message` | String | Human-readable result summary |
| `match_type` | `"hard"` \| `"soft"` \| null | How the asset hash was matched |
| `signature_verified` | Boolean | True if `signature` was present and verified |
| `manifest_signature_verified` | Boolean | True if `manifest_signature` was present and verified |
| `anchor_checked` | Boolean | True if anchor verification was attempted |
| `anchor_verified` | Boolean | True if anchor verification succeeded |
| `warnings` | Array\<String\> | Non-fatal issues encountered during verification |

---

## Sidecar Naming Convention

```
<original-filename><original-extension>.aios.json
```

| Asset filename | Sidecar filename |
|---|---|
| `photo.jpg` | `photo.jpg.aios.json` |
| `video.mp4` | `video.mp4.aios.json` |
| `document.pdf` | `document.pdf.aios.json` |
| `report.md` | `report.md.aios.json` |

---

## Field Quick Reference

| Field | Block | Required | Level | In FP |
|---|---|---|---|---|
| `asset_id` | core | MUST | L1 | ✓ |
| `schema_version` | core | MUST | L1 | ✓ |
| `creation_timestamp` | core | MUST | L1 | ✓ |
| `hash_original` | core | MUST | L1 | ✓ |
| `creator_id` | core | MUST | L1 | ✓ |
| `core_fingerprint` | core | MUST | L1 | — |
| `signature` | core | SHOULD | L2 | — |
| `manifest_signature` | core | SHOULD | L2 | — |
| `anchor_reference` | core | SHOULD | L3 | — |
| `previous_version_anchor` | core | MAY | info | — |
| `soft_binding` | extensions | SHOULD (images) | L2 | — |
| `ai_model_used` | extensions | MAY | — | — |
| `license` | extensions | MAY | — | — |
| `compliance_level` | extensions | MAY | info | — |
| `asset_name` | extensions | MAY | — | — |
| `asset_type` | extensions | MAY | — | — |
| `description` | extensions | MAY | — | — |

**FP** = included in `core_fingerprint` computation

---

## Deprecated Fields

| Field | Deprecated in | Removed in | Notes |
|---|---|---|---|
| `hash_schema_block` | v0.5.5 | v0.6 | Accepted as alias for `core_fingerprint`. Use `core_fingerprint`. |

---

## Deferred Fields (Informational)

The following fields are planned for future versions. Implementations MUST NOT use
these names for custom fields — they are reserved.

| Field | Target version | Description |
|---|---|---|
| `creator_keyref` | v0.6 | Reference to the specific key used for `signature` — enables key rotation tracking without changing `creator_id` |
| `extensions_version` | v0.6 | Version string for the extensions block schema |
| `rights` | v0.6 | Structured rights and permissions field — AI usage declarations, licensing signals |

---

## Extension Registry (Coming in v0.5.6)

Official extension fields are registered in the AIOSchema Extension Registry,
maintained by the AIOSchema project. Custom vendor fields MUST use the `x-<vendor>-`
prefix to avoid namespace collisions with registered fields.

No custom field MAY use a name that conflicts with any Core Block field or any
registered extension field name, with or without a prefix.

---

*© 2026 Ovidiu Ancuta — AIOSchema™ and ◈™ are trademarks of Ovidiu Ancuta*
*Specification: CC-BY 4.0 — https://aioschema.org*
