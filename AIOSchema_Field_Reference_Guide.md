<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- Copyright 2026 Ovidiu Ancuta -->
<!-- AIOSchema Field Reference Guide v0.5.6 | AIOSchema spec v0.5.6 | https://aioschema.org -->

# AIOSchema Field Reference Guide
## Version 0.5.6

**Document ID:** as-doc-ref-field-v0.5.6
**Status:** Final
**Authored:** May 2026
**Published:** June 2026
**Author:** Ovidiu Ancuta
**Authority:** https://aioschema.org
**License:** CC-BY 4.0

This document is a field-by-field reference for AIOSchema v0.5.6 manifests.
It is a companion to the specification, not a replacement. For normative requirements,
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
These are the mathematically sealed fields; changing any one of them invalidates
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

A universally unique identifier for this asset manifest. UUID v7 is preferred: it is
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
| **Accepted values** | `"0.1"` `"0.2"` `"0.3"` `"0.3.1"` `"0.4"` `"0.5"` `"0.5.1"` `"0.5.5"` `"0.5.6"` |
| **Verification level** | L1 |
| **If absent** | Verification MUST fail |
| **If unknown value** | Verification MUST fail with unsupported version error |

Identifies which version of the AIOSchema specification this manifest conforms to.
Verifiers MUST reject unknown versions with a clear error message identifying the
unsupported version string.

**Example:**
```json
"schema_version": "0.5.6"
```

---

### `creation_timestamp` [FP]

| Property | Value |
|---|---|
| **Type** | String |
| **Required** | MUST |
| **Format** | ISO 8601 UTC: `YYYY-MM-DDTHH:MM:SSZ` |
| **Pattern** | `^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$` |
| **Verification level** | L1 |
| **If absent** | Verification MUST fail |
| **If non-UTC (offset notation)** | Verification MUST fail |
| **If invalid format** | Verification MUST fail |

The timestamp at which the manifest was created. MUST be UTC; the trailing `Z` is
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
| **Format** | `<alg>-<hex>` : algorithm token, hex digest |
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

`creator_id` is a permanent identity anchor. It does not change when keys rotate; keys
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

**Canonicalization (Python reference):**
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
| **If null or absent** | Verification continues; absence is NOT a failure at L1 |
| **If present and non-null** | Verifier MUST verify; FAIL if invalid |
| **If present but no public key supplied** | Verifier MUST fail with clear error |

An Ed25519 signature over the canonical Core Block bytes. Signs only the core fields,
not extensions. Use `manifest_signature` when extensions also need integrity protection.

`signature` is tied to a specific key, not to `creator_id`. Key rotation does not
change `creator_id`; it produces a new `signature` with the new key. The identity
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
| **If null or absent** | Verification continues; absence is NOT a failure at L1 |
| **If present and non-null** | Verifier MUST verify; FAIL if invalid |

A detached Ed25519 signature over the **canonical manifest bytes**: the entire manifest
including extensions, with `manifest_signature` itself set to null before signing
(bootstrap exclusion, prevents circular dependency).

Use `manifest_signature` when extensions carry material metadata (e.g. `soft_binding`,
`ai_model_used`, `ai_declaration`, `compliance_eu_art50`) that also needs integrity
protection. A sidecar with a valid `manifest_signature` is self-verifying without
access to the original asset.

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

Verifiers MUST treat a null value and an absent field as equivalent: both indicate no
anchor is present. Step 13 of the verification process applies only when
`anchor_reference` is a non-null string.

**URI structure:**
- `service-id`: registered anchor service identifier (e.g. `rfc3161`, `ots-bitcoin`)
- `anchor-id`: service-specific record identifier

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
| **Verification level** | Informational: verifiers MUST NOT fail if absent or unresolvable |
| **If null or absent** | Verification continues normally |

Links this manifest to the anchor of its immediately preceding version, creating a
cryptographic chain of custody across versions. Used for versioned documents (e.g.
the AIOSchema specification itself), asset lineages, and any content that evolves
over time while maintaining provenance continuity.

Verifiers MUST NOT fail verification if this field is absent or if the anchor is
unresolvable; it is informational provenance, not an integrity check.

**Example:**
```json
"previous_version_anchor": "aios-anchor:ots-bitcoin:a1b2c3d4e5f6..."
```

---

## Extension Block Fields

The `extensions` block is optional: a manifest without it is fully valid. When present,
each field within it follows its own requirement level (MAY, SHOULD, or MUST depending
on context). Extensions MUST NOT affect the `core_fingerprint` computation. When
`manifest_signature` is present, all extensions ARE included in the signature scope.

### Namespacing Rules

| Prefix | Usage |
|---|---|
| No prefix | Official registered extension fields (see §11 of the spec) |
| `x-<vendor>-` | Vendor or experimental fields; prefix MUST be registered via the Extension Registry |

Custom fields MUST NOT use names that conflict with any Core Block field or any
registered extension field name.

Unregistered vendor prefixes MUST NOT be used in conforming manifests. Register vendor
prefixes at `https://aioschema.org/registry/`.

### Extension Size Limit

The total serialized size of the `extensions` object MUST NOT exceed 4KB (4,096 bytes).
The Core Block is excluded from this calculation.

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
| `ai_model_version` | String or null | AI model version string | - |
| `license` | String | SPDX identifier e.g. `"CC-BY-4.0"` | `xmpRights:UsageTerms` |
| `soft_binding` | Object | pHash soft binding: see below | `aioschema:pHashFingerprint` |
| `compliance_level` | Integer | Self-declared conformance level (1, 2, or 3). Informational. Not to be confused with `compliance_eu_art50`. | - |
| `asset_name` | String | Original filename or human-readable asset name | - |
| `asset_type` | String | Asset type e.g. `"document"`, `"image"`, `"video"` | - |
| `description` | String (max 256 chars) | Human-readable note about the asset's provenance context. MUST NOT be used for machine-parseable metadata, rights declarations, or version history. | - |
| `ai_declaration` | Object | Structured AI disclosure: see §ai_declaration below | |
| `compliance_eu_art50` | Object | EU AI Act Art. 50(4) editorial exemption record: see §compliance_eu_art50 below | |
| `public_key` | String | Base64-encoded Ed25519 public key for self-contained verification: see §public_key below | |

---

### `soft_binding` Object

Used for perceptual hash soft binding on image and video assets. MUST be present at
Level 2 for image and video assets. For other asset types it is optional.

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
| `threshold_info` | Integer | Informational only; the threshold used when generating. Verifiers MUST NOT read this value for policy decisions. |

**Critical:** verifiers MUST use their own `soft_binding_threshold` parameter (default: 5,
maximum: 10). The `threshold_info` in the manifest is documentation only and MUST be
ignored for verification policy.

---

### `ai_declaration` Object

Structured boolean fields documenting AI involvement in content creation or modification.
When `disclosure_required` is true, all fields MUST accurately reflect the actual nature
of AI involvement.

| Field | Type | Requirement | Description |
|---|---|---|---|
| `disclosure_required` | Boolean | MUST | True if AI contributed to this content |
| `ai_generated` | Boolean | MUST | Content is fully AI-generated |
| `ai_manipulated` | Boolean | MUST | Existing content was substantially altered by AI |
| `human_reviewed` | Boolean | MUST | A human reviewed AI-generated content before publication |
| `standard_editing` | Boolean | OPTIONAL | Only standard editing applied (cropping, colour correction, noise removal). When true, `disclosure_required` MUST be false |
| `creative_work` | Boolean | OPTIONAL | Artistic, satirical, or fictional work |

**Constraint:** When `standard_editing` is true, `disclosure_required` MUST be false.

When `human_reviewed` is true, `compliance_eu_art50` SHOULD be present.

**Example:**
```json
"ai_declaration": {
  "disclosure_required": true,
  "ai_generated": true,
  "ai_manipulated": false,
  "human_reviewed": true,
  "standard_editing": false,
  "creative_work": false
}
```

---

### `compliance_eu_art50`

| Property | Value |
|---|---|
| **Type** | Object |
| **Required** | MAY (MUST when claiming EU AI Act Art. 50(4) editorial exemption) |
| **Verification level** | Warning on incomplete exemption fields |

Records that a qualifying editorial review occurred and its nature.

All fields are OPTIONAL in the JSON Schema. The fields marked MUST below MUST be
present when the publisher claims the editorial exemption. A manifest that includes
`compliance_eu_art50` without the required fields remains a fully valid AIOSchema
manifest; it does not assert the editorial exemption.

| Field | Type | Required for exemption | Description |
|---|---|---|---|
| `editorial_responsibility` | String | MUST | Organisation name or role title of the person holding editorial responsibility under EU AI Act Art. 50(4). Not a personal name. |
| `review_type` | String (enum) | MUST | Nature of review performed. |
| `reviewer_id` | String (`ed25519-fp-<32hex>`) | OPTIONAL | Cryptographic non-identifying anchor (Ed25519 public key fingerprint). Does not expose personal identity. |

`review_type` MUST be one of:
- `substantive`: deliberate examination of content substance by a person with relevant competence and professional judgement.
- `editorial-control`: editorial control exercised by a responsible person.

Both values satisfy the EU AI Act Art. 50(4) editorial exemption.

**Verifier behaviour:** Verifiers SHOULD emit a warning (not a failure) when
`compliance_eu_art50` is present but `review_type` is absent:
> `"compliance_eu_art50.review_type absent: set to \"substantive\" or \"editorial-control\""`

**Example:**
```json
"compliance_eu_art50": {
  "editorial_responsibility": "Editorial Team, Example Media Ltd",
  "review_type": "substantive"
}
```

---

### `public_key`

| Property | Value |
|---|---|
| **Type** | String |
| **Required** | MAY (enables self-contained verification) |
| **Format** | Base64-encoded raw 32-byte Ed25519 public key |
| **Verification level** | L2 (when `signature` or `manifest_signature` present) |

Embeds the Ed25519 public key directly in the manifest, enabling offline verification
without network access or an external key registry.

**Fingerprint cross-check (Normative):**

A verifier MUST validate the embedded key against `creator_id` before using it:

1. Decode the Base64 value to raw bytes.
2. Compute `SHA-256(raw_bytes)` and take the first 16 bytes (32 hex characters).
3. Construct the expected `creator_id`: `ed25519-fp-<32hex>`.
4. Compare against the manifest `creator_id` using timing-safe equality.
5. If they do not match: FAIL with `public_key_fingerprint_match=false`.
6. If they match: proceed with signature verification.

When both `extensions.public_key` and a key from Creator Key Discovery are available,
the verifier SHOULD prefer the discovered key and MUST verify both keys are identical.
A mismatch MUST produce a warning and SHOULD cause verification to fail.

**Example:**
```json
"public_key": "MCowBQYDK2VwAyEAj4VZRK5VJThKGx8LYXeF8YvjNWKpWnLqM3rXeV4Q9sM="
```

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
| `public_key_fingerprint_match` | Boolean or null | `true` if `extensions.public_key` fingerprint matched `creator_id`; `false` if mismatch; `null` if `extensions.public_key` absent |
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
| `core_fingerprint` | core | MUST | L1 | - |
| `signature` | core | SHOULD | L2 | - |
| `manifest_signature` | core | SHOULD | L2 | - |
| `anchor_reference` | core | SHOULD | L3 | - |
| `previous_version_anchor` | core | MAY | info | - |
| `soft_binding` | extensions | MUST (image/video at L2) | L2 | - |
| `ai_model_used` | extensions | MAY | - | - |
| `license` | extensions | MAY | - | - |
| `compliance_level` | extensions | MAY | info | - |
| `asset_name` | extensions | MAY | - | - |
| `asset_type` | extensions | MAY | - | - |
| `description` | extensions | MAY | - | - |
| `ai_declaration` | extensions | MAY | - | - |
| `compliance_eu_art50` | extensions | MAY | - | - |
| `public_key` | extensions | MAY | L2 | - |

**FP** = included in `core_fingerprint` computation

`signature` and `manifest_signature` are SHOULD at Level 2: they MUST be present when
a signing key is available. A manifest without them is still valid at Level 1.

`soft_binding` MUST be present at Level 2 for image and video assets. For other asset
types it is optional.

`ai_declaration` is MAY for general use. When a publisher asserts EU AI Act Art. 50
compliance, it MUST be present and MUST accurately reflect AI involvement.

`compliance_eu_art50` is MAY for general use. When a publisher claims the EU AI Act
Art. 50(4) editorial exemption, it MUST be present with `editorial_responsibility` and
`review_type` populated.

`public_key` is MAY. When present, the verifier MUST perform the fingerprint
cross-check against `creator_id` before using it for signature verification.

---

## Deprecated Fields

| Field | Deprecated in | Removed in | Notes |
|---|---|---|---|
| `hash_schema_block` | v0.5.5 | v0.6 | Accepted as alias for `core_fingerprint`. Use `core_fingerprint`. |

---

## Deferred Fields (Informational)

The following fields are planned for future versions. Implementations MUST NOT use
these names for custom fields; they are reserved.

| Field | Target version | Description |
|---|---|---|
| `creator_keyref` | v0.6 | Reference to the specific key used for `signature`; enables key rotation tracking without changing `creator_id` |
| `extensions_version` | v0.6 | Version string for the extensions block schema |
| `rights` | v0.6 | Structured rights and permissions field: AI usage declarations, licensing signals |

---

## Extension Registry

Official extension fields are registered in the AIOSchema Extension Registry at
`https://aioschema.org/registries/extensions/`. Vendor prefix registration is available
at `https://aioschema.org/registry/`.

No custom field MAY use a name that conflicts with any Core Block field or any
registered extension field name, with or without a prefix.

---

## Changelog

All versions of this document are backward compatible with v0.5.5 manifests. A
v0.5.5 verifier will correctly process any v0.5.5 manifest. A v0.5.6 verifier MUST
accept all `schema_version` values from `"0.1"` through `"0.5.6"`.

| Version | Date | Changes |
|---|---|---|
| v0.5.6 | 2026-06-05 | Added `ai_declaration` extension field (structured AI involvement disclosure). Added `compliance_eu_art50` extension field (EU AI Act Art. 50(4) editorial exemption record): two fields required when claiming exemption: `editorial_responsibility` and `review_type`; `reviewer_id` OPTIONAL. Added `public_key` extension field (self-contained verification via embedded Ed25519 public key) with normative fingerprint cross-check. Added `public_key_fingerprint_match` to VerificationResult. Added extension size limit: 4KB maximum on serialized `extensions` object. Added Extension Registry and vendor prefix registration requirement. Updated `description` field: 256-char maximum, provenance context only. `schema_version` accepted values extended to include `"0.5.6"`. |
| v0.5.5 | 2026-03-17 | Initial release of this document. `hash_schema_block` deprecated as alias for `core_fingerprint`; accepted by v0.5.5 and later verifiers; scheduled for removal in v0.6. |

---

*© 2026 Ovidiu Ancuta. AIOSchema™ and ◈™ are trademarks of Ovidiu Ancuta.*
*Specification: [CC-BY 4.0](https://creativecommons.org/licenses/by/4.0/) · Reference Implementations: [Apache 2.0](https://www.apache.org/licenses/LICENSE-2.0) · [https://aioschema.org](https://aioschema.org)*

<!-- end AIOSchema Field Reference Guide v0.5.6 | AIOSchema spec v0.5.6 | https://aioschema.org -->
