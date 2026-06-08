<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- Copyright 2026 Ovidiu Ancuta -->
<!-- AIOS-SPEC-0001-v0.5.6 | AIOSchema Specification v0.5.6 | https://aioschema.org -->

# AIOSchema Specification v0.5.6

**Document ID:** AIOS-SPEC-0001-v0.5.6
**Status:** Technical Review
**Authored:** June 8, 2026
**Published:** June 8, 2026
**Author:** Ovidiu Ancuta
**Authority:** https://aioschema.org
**License:** CC-BY 4.0
**Trademarks:** AIOSchema™ and ◈™ are trademarks of Ovidiu Ancuta
**Replaces:** AIOS-SPEC-0001-v0.5.5
**Superseded by:** (none)
**Target:** v1.0 stable (Q4 2026)

> **On dates:** *Authored* is when this version was created and anchored — recorded
> immutably in the founding anchor. *Published* is when it became publicly
> available on aioschema.org.

---

## Abstract

AIOSchema is an open standard built on a lightweight, extensible architecture for establishing, maintaining, and preserving the integrity, authenticity, and provenance of digital and physical assets. It defines a minimal, verifiable manifest format that establishes what an asset is, who created it, and when it existed, independently of any platform, storage system, or proprietary tool.

This document specifies AIOSchema version 0.5.6. It defines the Core Block structure, hash algorithm registry, verification procedure, anchoring mechanism, and interoperability mappings for C2PA, EXIF/XMP, schema.org, and W3C PROV. Six independent reference implementations (Python, TypeScript, Node.js, Go, Rust, and .NET) have been verified against a common cross-implementation test suite.

AIOSchema is technology-neutral and applies to both digital and physical assets. Physical assets are represented through a digital manifest: a photograph, scan, or structured description of the physical object is hashed and anchored, creating a verifiable provenance record that travels with the asset across its lifecycle.

AIOSchema is designed to be read in under an hour and implemented in a day.

---

## Design Philosophy

AIOSchema was created to solve a fundamental problem: digital and physical assets need a universal, durable, and verifiable provenance layer that works everywhere and depends on no single system, platform, or technology.

The design philosophy behind AIOSchema rests on four pillars:

- A stable, minimal structure
- Modular, replaceable algorithms
- Universal interoperability
- Long-term durability and verifiability

### Stable Core, Modular Algorithms

AIOSchema separates the shape of the standard from the algorithms used inside it. The Core Block is intentionally minimal and stable: it defines only the fields required for deterministic identity and verification. Everything else (hashing, signing, soft binding, anchoring) is treated as a module, not a fixed dependency.

This ensures that no single cryptographic primitive can compromise the whole standard, algorithms can be replaced without redesigning the manifest, and implementations remain simple and predictable. AIOSchema v0.5.x uses Ed25519 and SHA-256 as practical defaults, not permanent requirements. Algorithm registries (§17) govern available hash, signature, and anchor mechanisms, with formal deprecation paths.

### Universality and Interoperability

A provenance standard is only useful if it works everywhere. AIOSchema is container-agnostic, platform-agnostic, ecosystem-agnostic, and metadata-agnostic. It integrates cleanly with XMP, EXIF, schema.org, W3C PROV, and C2PA, or can be used as a standalone solution.

### Durability and Survivability

Digital content is constantly transformed: recompressed, resized, transcoded, stripped of metadata. Physical assets change hands, are photographed, scanned, and re-documented. AIOSchema survives these transformations through multi-hash support, detached signatures, sidecar and XMP hybrid embedding, soft binding via perceptual hashing, and anchor chaining. The manifest travels independently of the asset. Durability is not an afterthought: it is a core design requirement.

### Verifiable Without Specialized Tools

A developer can implement a verifier in a day. Verification requires no proprietary tools or libraries. The manifest is plain JSON. Canonicalization rules are deterministic. The anchoring mechanism is public and independently verifiable. No single system controls verification. This is essential for trust.

### Anchoring: Pluggable, Public, and Independent

AIOSchema uses a simple, universal anchor URI scheme: `aios-anchor:<service-id>:<anchor-id>`. This accommodates RFC 3161 trusted timestamp authorities, blockchain-based timestamping, hybrid services, and any future mechanism that produces a public, immutable, independently verifiable timestamp. AIOSchema mandates only that anchors be publicly verifiable, independent of the author, immutable, and timestamped. No specific service is mandated.

### Transparency and Provenance of the Standard Itself

AIOSchema uses its own mechanisms to establish the provenance of the specification. Each version is hashed, signed, anchored, and linked to its predecessor via `previous_version_anchor`. This creates a cryptographic chain of custody for the standard itself. The standard practices what it preaches.

### Evolution Without Fragmentation

No breaking changes within a minor version increment. Clear versioning semantics. Backward compatibility for all v0.x manifests. Forward compatibility through algorithm agility. The goal is a standard that grows without fracturing the ecosystem.

---

## 1. Introduction

AIOSchema is an extensible metadata framework designed to establish, maintain, and preserve the integrity, authenticity, and provenance of digital and physical assets. It defines a minimal set of verifiable core fields, supports optional extension fields, and enables tamper-evident anchoring through compatible secure mechanisms.

AIOSchema is technology-neutral and designed to operate across:

- Digital images and video files
- Documents
- AI-generated media
- Physical-to-digital scans
- Platform-specific content pipelines

AIOSchema is not intended to replace C2PA. It is a lighter, technology-agnostic standard that operates independently. Implementers may embed AIOSchema core fields as custom assertions inside C2PA manifests, or use AIOSchema standalone. See §7.1 for full interoperability detail.

---

## 2. Normative Language

The key words **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT**, **RECOMMENDED**,
**NOT RECOMMENDED**, and **MAY** are to be interpreted as described in RFC 2119.

**RECOMMENDED** is equivalent to **SHOULD**. **NOT RECOMMENDED** is equivalent to **SHOULD NOT**.

The conformance level name "Level 2: Recommended" (§5.2) is a label for a conformance tier, not a standalone RFC 2119 keyword. It means that level is the recommended baseline for production implementations. All normative requirements within that level are expressed using **MUST**, **SHOULD**, or **MAY** as appropriate.

---

## 3. Design Principles

| Principle | Description |
|-----------|-------------|
| **Minimal Core** | The Core Block contains only the fields required for deterministic identity and verification. These fields are architecturally frozen: any modification would produce a different standard, not a new version of AIOSchema. This immutability is what separates the data layer from the technology layer and guarantees long-term verifiability. |
| **Interoperability First** | Designed to adapt to existing compatible systems including C2PA, EXIF/XMP, schema.org, and W3C PROV. |
| **Privacy by Design** | No personal data in the Core Block. Identifiers are non-identifying (UUID v4/v7 or public-key fingerprint). |
| **Technology-Neutral** | No mandatory blockchain, storage system, watermarking, or metadata container. |
| **Durability** | Designed to survive recompression, resizing, format conversion, and platform uploads. See §8. |
| **Open Governance** | Will transition to a public foundation. See §13. |
| **Lightweight** | A developer should be able to read the spec in under an hour and implement it in a day. Every Core Block addition must justify its complexity cost. |

---

## 4. AIOSchema Structure

A manifest MUST be a JSON object conforming to Appendix A:

```json
{
  "core": { ... },
  "extensions": { ... }
}
```

---

## 5. Core Block (Required)

### 5.1 Core Fields

| Field | Type | Requirement | Description |
|---|---|---|---|
| `asset_id` | String | MUST | UUID v7 (SHOULD) or UUID v4 (MAY). |
| `schema_version` | String | MUST | AIOSchema version (e.g. `"0.5.6"`). |
| `creation_timestamp` | String | MUST | ISO 8601 UTC, must end with `"Z"`. |
| `hash_original` | String **or** Array\<String\> | MUST | Prefixed hash(es) of the binary asset. Format: `<alg>-<hex>`. String form is the legacy single-hash form accepted for backward compatibility. Array form advertises multiple hashes; verifiers accept the manifest if any advertised algorithm matches and is supported. The array MUST contain at least one entry and MUST NOT contain duplicate algorithm tokens. See §5.5. |
| `core_fingerprint` | String | MUST | Prefixed hash of the canonical core fields. See §5.6. |
| `creator_id` | String | MUST | UUID v7/v4 (anonymous) or `ed25519-fp-<32hex>` (attributed). See §5.7. |
| `signature` | String or null | SHOULD | Ed25519 signature over canonical core bytes. Format: `ed25519-<128hex>`. Null or absent on unsigned manifests. |
| `manifest_signature` | String or null | SHOULD | Detached Ed25519 signature over canonical manifest bytes. Null or absent on unsigned manifests. When present and non-null the verifier MUST verify it. See §5.8. |
| `anchor_reference` | String or null | SHOULD | Anchor URI: `aios-anchor:<service-id>:<anchor-id>`. Null or absent on unanchored manifests. Verifiers MUST treat a null value and an absent field as equivalent: both indicate no anchor is present. Step 13 of §10 applies only when `anchor_reference` is a non-null string. |
| `previous_version_anchor` | String or null | MAY | Anchor URI of the immediately preceding version of this specification or asset lineage. Creates a cryptographic chain of custody across versions. Format: `aios-anchor:<service-id>:<anchor-id>`. SHOULD be present in any manifest that represents a versioned document. Verifiers MUST NOT fail verification if this field is absent or unresolvable: it is informational provenance, not an integrity check. The founding provenance record for this specification is published at `https://aioschema.org/provenance/`. |

### 5.2 Conformance Levels (Normative)

| Level | Requirements |
|---|---|
| **Level 1: Minimal** | All required fields present. `hash_original` correct. `core_fingerprint` correct. Sidecar written per §8.2. Core Block preserved on export. All test vectors passed. |
| **Level 2: Recommended** | Level 1 plus: `signature` present when key available. `manifest_signature` present when sidecar integrity required. pHash soft binding for image/video assets. Hybrid XMP + sidecar embedding. Extension fields mapped to EXIF/XMP per Appendix C. |
| **Level 3: Anchor-Verified** | Level 2 plus: `anchor_reference` present. Anchor verification performed via `anchor_resolver`. `anchor_verified=true` in verification result. |

Self-declaration is informational. Implementations MUST pass the test vectors for the level they claim (§5.4).

### 5.3 Hash Algorithm Registry (Normative)

| Algorithm Token | Hex Digest Length | Status |
|---|---|---|
| `sha256` | 64 | REQUIRED |
| `sha3-256` | 64 | OPTIONAL |
| `sha384` | 96 | OPTIONAL |

Implementations MUST support `sha256`. Verifiers encountering an unknown token MUST return a verification failure with a clear error identifying the unsupported algorithm.

Algorithms have fixed digest lengths; the regex enforces exact length per algorithm:

```
^(sha256|sha3-256)-[0-9a-f]{64}$|^sha384-[0-9a-f]{96}$
```

### 5.3.1 Algorithm Registration Contract

The formal algorithm registration contract is defined in §17.1.1.

### 5.4 Test Vector Requirements (Normative)

Conforming implementations MUST pass all test vectors at:
`https://aioschema.org/test-vectors/v0.5.6/`

| ID | Description |
|---|---|
| TV-01 | Valid generate + verify round-trip (hard match) |
| TV-02 | Tampered `hash_original` must fail |
| TV-03 | Tampered `core_fingerprint` must fail |
| TV-04 | Soft match within pHash threshold |
| TV-05 | Soft match outside threshold must fail |
| TV-06 | Signature present and valid |
| TV-07 | Signature with wrong public key must fail |
| TV-08 | Unsigned manifest (null signature) passes |
| TV-09 | Missing required fields must fail |
| TV-10 | Invalid timestamp format rejected |
| TV-11 | Non-UTC timestamp rejected |
| TV-12 | Unknown `schema_version` rejected |
| TV-13 | Multi-hash manifest (SHA-256 + SHA-384): verification succeeds with either algorithm |
| TV-14 | `manifest_signature` present and valid: verification succeeds, `manifest_signature_verified=true` |
| TV-15 | `manifest_signature` present, extensions tampered: verification fails |
| TV-16 | SHA-384 single-hash manifest: verified correctly |
| TV-17 | Anchor-verified flow with correct anchor record: `anchor_verified=true` |
| TV-18 | Anchor present but `verify_anchor=False`: passes with warning |
| TV-19 | `extensions.public_key` present; fingerprint matches `creator_id`; `signature` and `manifest_signature` both verify. `public_key_fingerprint_match=true` |
| TV-20 | `extensions.public_key` fingerprint does NOT match `creator_id`: verification fails |
| TV-21 | Valid `ai_declaration` (`disclosure_required=true`, `standard_editing=false`): verification succeeds |
| TV-22 | `ai_declaration` constraint violation (`standard_editing=true` AND `disclosure_required=true`): verification fails |
| TV-23 | `extensions` JSON exactly at 4,096-byte limit: verification succeeds |
| TV-24 | `extensions` JSON exceeding 4,096-byte limit: verification fails |

### 5.5 `hash_original`: Multi-Hash Procedure (Normative)

**Generating a multi-hash manifest:**

1. Compute a hash using each desired algorithm over the original binary asset bytes.
2. Format each as `<alg>-<hex>`.
3. Store as a JSON array: `["sha256-<hex>", "sha384-<hex>"]`.

MUST include at least one `sha256` hash. Additional algorithms MAY be added.

**Verifying a multi-hash manifest:**

1. For each hash in the array (or for the single string), parse the algorithm token.
2. If the algorithm is unsupported: skip it, record a warning.
3. If the algorithm is supported: recompute and compare using timing-safe equality.
4. If **any** supported hash matches: hard match succeeds.
5. If all supported hashes are present but none match: hard match fails.
6. If **no** supported algorithm was found in the array: return failure (cannot verify).

`hash_original` accepts both string and array forms for backward compatibility with v0.5.5 and earlier manifests. Implementations in Go, Rust, .NET, and similar languages SHOULD use a custom deserializer or union type to handle both forms rather than mandating array-only emission, which would break existing conforming manifests. See the reference implementations for the canonical deserialization pattern for each language.

### 5.6 `core_fingerprint` Canonicalization (Normative)

Compute over exactly these fields (alphabetical order via `sort_keys=True`):

```
CORE_HASH_FIELDS = [
  "asset_id", "schema_version", "creation_timestamp",
  "hash_original", "creator_id"
]
```

`core_fingerprint` MUST NOT be included in its own computation.

**Reference implementation (Python):**

```python
canonical = json.dumps(
  {k: core_block[k] for k in CORE_HASH_FIELDS},
  sort_keys=True, separators=(',', ':')
).encode('utf-8')

core_fingerprint = "sha256-" + hashlib.sha256(canonical).hexdigest()
```

### 5.7 `creator_id` Modes (Normative)

| Mode | Format | Description |
|---|---|---|
| Anonymous | UUID v7 (SHOULD) or UUID v4 (MAY) | No identity disclosed. |
| Attributed | `ed25519-fp-<32hex>` | SHA-256 fingerprint of Ed25519 public key (first 128 bits). |

Verifiers infer mode from the value: `ed25519-fp-` prefix indicates attributed mode; a valid UUID indicates anonymous mode.

### 5.8 `manifest_signature`: Canonical Manifest Bytes (Normative)

`manifest_signature` is an Ed25519 signature over the **canonical manifest bytes**, defined as the UTF-8 encoding of the compact JSON serialization of the entire manifest with:

1. The `manifest_signature` field set to `null` (bootstrap exclusion: prevents circular dependency).
2. Keys sorted alphabetically at all levels (`sort_keys=True`).
3. No whitespace between tokens (`separators=(',', ':')`).

**Reference implementation (Python):**

```python
def canonical_manifest_bytes(manifest: dict) -> bytes:
  m = copy.deepcopy(manifest)
  m["core"]["manifest_signature"] = None
  return json.dumps(m, sort_keys=True, separators=(',', ':')).encode('utf-8')
```

`manifest_signature` signs the core block and extensions together. This provides integrity protection for sidecar files where extensions carry material metadata (e.g. `soft_binding`, `ai_model_used`, `ai_declaration`, `compliance`).

---

## 6. Extension Block (Optional)

Extensions MAY include EXIF/XMP-derived fields, AI-generation metadata, licensing, platform-specific metadata, and user-defined fields.

Extensions MUST NOT affect the `core_fingerprint` computation.

### 6.1 Extension Namespacing

Official extension fields are maintained by the AIOSchema project under the namespace `https://aioschema.org/extensions/`. Official extensions are listed in the Extension Registry (§17.5) and documented at `https://aioschema.org/extensions/`.

Vendor and experimental extensions MUST use a registered `x-<vendor>-` prefix. Each vendor prefix is registered once through the Extension Registry process published at `https://aioschema.org/registry/`. Fields under a registered prefix are the vendor's responsibility and MUST NOT conflict with any Core Block field or registered extension field name, with or without a prefix.

Unregistered vendor prefixes MUST NOT be used in conforming manifests.

Custom extensions MUST NOT increase the total size of the `extensions` object beyond the limit specified in §6.3.

### 6.2 Soft Binding Extension Field

```json
"soft_binding": {
  "algorithm": "pHash-v1",
  "fingerprint": "<16-char hex>",
  "threshold_info": 5
}
```

`threshold_info` is documentation only. Verifiers MUST use the `soft_binding_threshold` parameter (default 5) and MUST NOT read the threshold from the manifest.

### 6.3 Extension Size Limit

The total size of the serialized `extensions` object in a conforming manifest MUST NOT exceed 4KB (4,096 bytes). The Core Block (§5) is excluded from this calculation.

This limit ensures manifests remain suitable for QR code embedding, supply chain scanning, and distribution at scale. Payloads approaching this limit indicate misuse of the extensions block as a data store, which is not its intended purpose.

---

## 7. Interoperability and Mapping

### 7.1 C2PA Interoperability (Normative)

AIOSchema defines a C2PA custom assertion format for embedding AIOSchema provenance data inside C2PA manifests.

| Property | Value |
|---|---|
| Assertion label | `aioschema.core/v1` |
| Assertion data | Complete Core Block JSON, serialized as canonical compact UTF-8 JSON (sort_keys=True, no whitespace) per §5.6 |

A conforming AIOSchema implementer MAY embed a manifest's Core Block inside a C2PA manifest using this assertion format. A conforming AIOSchema verifier MAY extract and verify an AIOSchema Core Block found in a C2PA manifest assertion with this label.

AIOSchema does not mandate C2PA adoption. C2PA compatibility is an optional interoperability layer. AIOSchema manifests are fully valid and verifiable without any C2PA dependency.

AIOSchema and C2PA are complementary standards with distinct scopes. AIOSchema provenance data may be carried inside a C2PA manifest using the assertion format defined above; AIOSchema also operates as a standalone provenance layer without C2PA. No C2PA field name, structure, or identifier is incorporated into the AIOSchema Core Block or extension schema. This preserves AIOSchema's self-contained verification model and avoids coupling the standard's evolution to an external specification's release cycle.

If C2PA modifies its assertion handling in ways that affect this embedding, the C2PA implementation bears responsibility for maintaining conformance with this defined format. AIOSchema documents known C2PA version compatibility notes at `https://aioschema.org/compat/c2pa`.

The assertion label `aioschema.core/v1` uses dot notation per C2PA custom assertion naming conventions, not AIOSchema snake_case field naming. The `/v1` suffix denotes the major structural version of this assertion format and advances only when AIOSchema introduces breaking structural changes at a major version increment.

### 7.2 EXIF/XMP Mapping (Normative)

AIOSchema embeds its Core Block into XMP using the custom namespace `https://aioschema.org/xmp/v1/` with prefix `aioschema`, under the key `aioschema:manifest`. This embedding applies to file formats that support XMP: JPEG, PNG, PDF, and MP4. The XMP namespace URI uses a stable `v1` major-version designator rather than the schema version string. This ensures XMP readers and metadata tooling do not require updating on minor version increments. The namespace URI advances only at a major version increment with breaking structural changes. See Appendix C for the complete field mapping table.

### 7.3 schema.org Mapping (Normative)

AIOSchema fields map to schema.org vocabulary properties to enable discovery and indexing by schema.org-aware systems. Implementers embedding AIOSchema manifests in HTML SHOULD include the corresponding schema.org properties in their structured data. The mappings below are normative for conforming schema.org interoperability.

| AIOSchema Field | schema.org Property |
|---|---|
| `creator_id` | `schema:creator` |
| `creation_timestamp` | `schema:dateCreated` |
| `extensions.license` | `schema:license` |
| `extensions.ai_model_used` | `schema:isBasedOn` |

### 7.4 W3C PROV Mapping (Normative)

AIOSchema fields map to W3C PROV concepts to enable provenance interoperability with PROV-aware systems. Implementers publishing provenance records in PROV-O or PROV-N SHOULD use the mappings below. The mappings are normative for conforming W3C PROV interoperability.

| AIOSchema Field | PROV Concept | PROV Property |
|---|---|---|
| `asset_id` | `prov:Entity` | entity identifier |
| `creator_id` | `prov:Agent` | `prov:wasAttributedTo` |
| `creation_timestamp` | `prov:Generation` | `prov:generatedAtTime` |
| `hash_original` | `prov:Entity` | `prov:value` |
| `signature` | `prov:Influence` | `prov:qualifiedAttribution` |
| `manifest_signature` | `prov:Influence` | `prov:qualifiedDerivation` |

---

## 8. Durability and Survivability (Normative)

### 8.1 Embedded XMP (Level 2 MUST)

For JPEG, PNG, PDF, and MP4: embed the Core Block in XMP under namespace `https://aioschema.org/xmp/v1/` using key `aioschema:manifest`. The XMP namespace URI uses a stable `v1` major-version designator and does not change on minor version increments.

### 8.2 Sidecar JSON (Level 1 MUST)

**Naming convention:** `<original-filename><original-extension>.aios.json`

Examples: `photo.jpg` becomes `photo.jpg.aios.json`; `video.mp4` becomes `video.mp4.aios.json`.

The sidecar MUST contain the complete manifest (core + extensions) as UTF-8 JSON.

AIOSchema supports any file type as an asset. The hash is computed over the raw binary bytes of the file without transformation or format-specific pre-processing. The file type is identified by the sidecar filename through the naming convention above; no MIME type declaration or file parsing is required for manifest generation.

When `manifest_signature` is present the sidecar is self-verifying: its contents can be authenticated without access to the original asset file.

### 8.3 Soft Binding: pHash (Level 2 MUST for images/video)

Algorithm unchanged from v0.4. The verifier-side policy threshold is configurable via `soft_binding_threshold` parameter (default: 5, maximum: 10).

### 8.4 Hybrid Mode (Level 2 SHOULD)

Hybrid mode combines XMP embedding, sidecar JSON, and optional anchoring to maximise durability across platforms. For formats that support XMP (JPEG, PNG, PDF, MP4), the Core Block SHOULD be embedded in XMP per §8.1 and a sidecar MUST be written per §8.2. For formats that do not support XMP (plain text, arbitrary binary, custom formats), sidecar-only is the correct approach. When anchoring is present, the `anchor_reference` in the sidecar provides an independent temporal witness that survives platform metadata stripping. See Appendix D for platform-specific survivability data.

### 8.5 Post-Platform Recovery Procedure (Normative)

1. Locate sidecar at `<asset-filename>.aios.json`.
2. If `manifest_signature` present: verify sidecar integrity before proceeding.
3. Attempt `hash_original` hard match.
4. If hard fail: attempt pHash soft match using verifier-policy threshold.
5. If soft match: flag as `match_type="soft"` with warning.
6. If both fail: return FAIL.
7. Proceed to `core_fingerprint` and signature verification.

---

## 9. Anchoring

The anchoring mechanism, URI scheme, anchor resolver contract, and service discovery protocol defined in this section are normative. Whether a given manifest carries an `anchor_reference` is determined by its conformance level: Level 3 requires anchoring; Levels 1 and 2 do not. The `anchor_reference` field requirement is specified in §5.1 and §5.2.

### 9.1 Anchor URI Scheme (Normative)

```
aios-anchor:<service-id>:<anchor-id>
```

### 9.2 `anchor_resolver` Contract (Normative)

Anchor verification requires an `anchor_resolver`, a callable or function in the implementing language, with the following language-neutral contract:

**Input:** `anchor_ref`: the `aios-anchor:` URI string from the manifest.

**Output:** An anchor record object containing at minimum:

| Field | Type | Description |
|---|---|---|
| `asset_id` | String | Asset identifier; must match manifest `asset_id` |
| `core_fingerprint` | String | Core fingerprint; must match manifest `core_fingerprint` |
| `timestamp` | String | ISO 8601 UTC timestamp of when the anchor was created |
| `signature` | String or null | Ed25519 signature value from the manifest at anchor time, if stored by the service |

**Failure cases:**
- If the anchor record cannot be retrieved: return null/None/undefined
- If the anchor service returns an error: raise or throw `AnchorVerificationError`

**Verification succeeds** if the returned `asset_id` and `core_fingerprint` both match the manifest values using timing-safe comparison. When `signature` is present in the anchor record, verifiers SHOULD additionally compare it against the manifest's current `signature` field to detect re-signing attacks. A mismatch MUST produce a warning.

**Reference implementations** provide typed `anchor_resolver` interfaces in Python, TypeScript, Node.js, Go, Rust, and .NET at `https://aioschema.org/implementations/`.

### 9.3 Anchor Service Discovery (Normative)

Anchor services publish a discovery document at a well-known URL under their own domain:

```
https://<service-domain>/.well-known/aioschema-anchor.json
```

For example, a service operating at `tsa.example.com` publishes its discovery document at `https://tsa.example.com/.well-known/aioschema-anchor.json`. The discovery document MUST include the service name and supported anchor schemes. It SHOULD include a public verification endpoint URL. The anchor resolver contract (§9.2) governs how verifiers interact with the service.

### 9.4 What to Anchor (Normative)

Anchors MUST store: `asset_id`, `core_fingerprint`, `timestamp`.

Anchors SHOULD store: `signature`. Storing the `signature` value at anchor time enables verifiers to cross-check that the signing key at anchor time matches the current manifest's signature field, detecting re-signing attacks. This check is performed as described in §9.2. Anchor services that do not store `signature` provide temporal integrity verification only; they do not provide signing-key continuity verification.

### 9.5 Creator Key Discovery (Normative)

Creator Key Discovery is the mechanism by which a verifier resolves the Ed25519 public key for a manifest whose `creator_id` is in attributed mode (`ed25519-fp-<32hex>`) but whose `extensions.public_key` field is absent or not trusted.

**Resolution order (Normative):**

A verifier MUST attempt key resolution in the following order and use the first result that passes the fingerprint cross-check (§11.3):

1. **Embedded key:** if `extensions.public_key` is present and non-null, perform the fingerprint cross-check (§11.3). If it passes, use this key. If it fails, emit a warning and proceed to step 2.
2. **Well-known URL:** fetch the creator's key document at the well-known URL published by the creator under their own domain. The URL follows the pattern `https://<creator-domain>/.well-known/aioschema-keys/<creator_id_value>.json`, where `<creator_id_value>` is the full `ed25519-fp-<32hex>` string. Creators publish and maintain their own key documents; key documents are not hosted by aioschema.org. Parse the `public_key` field from the response and perform the fingerprint cross-check.
3. **Application-provided key:** the verifier MAY accept a public key provided by the calling application (for example, from a local keystore or a key retrieved through an out-of-band trust mechanism). The fingerprint cross-check (§11.3) MUST still be performed before use.

**If no key can be resolved:** the verifier MUST NOT proceed with signature verification. It MUST return `signature_verified=false` and emit a warning: `"public_key unavailable: signature not verified"`. This is not a verification failure for unsigned manifests; steps 11 and 12 of §10 apply only when `signature` and `manifest_signature` are non-null.

**Key document format:**

| Field | Type | Requirement | Description |
|---|---|---|---|
| `creator_id` | String | MUST | The full `ed25519-fp-<32hex>` value |
| `public_key` | String | MUST | Base64-encoded raw 32-byte Ed25519 public key |
| `published` | String | SHOULD | ISO 8601 UTC timestamp of first publication |
| `revoked` | Boolean | SHOULD | `true` if this key has been revoked |

If `revoked` is `true`, the verifier MUST NOT use the key and MUST emit a warning: `"creator key revoked: signature not verified"`.

Well-known URL key documents rely on DNS and HTTPS transport security and are not themselves cryptographically authenticated by this specification. For network-independent verification, use the embedded `extensions.public_key` path (§11.3), which requires no external fetch and is self-contained within the manifest.

---

## 10. Verification Process (Normative)

A conforming verifier MUST execute the following steps in order:

1. **Extract** metadata from XMP or sidecar (`.aios.json`).
2. **Validate** all required core fields present (§5.1).
3. **Validate** `schema_version` is supported; reject with clear error if unknown.
4. **Validate** `hash_original` format (single string or each array element) per §5.3 regex.
5. **Validate** `core_fingerprint` format per §5.3 regex.
6. **Validate** `creation_timestamp` is UTC ISO 8601 with trailing `"Z"`.
7. **Recompute** `hash_original`: for each algorithm in the manifest, recompute and compare (timing-safe). Hard match succeeds if any supported algorithm matches. See §5.5.
8. **If no hard match:** attempt soft binding per §8.5.
9. **If both fail:** return FAIL (asset tampered or replaced).
10. **Recompute** `core_fingerprint` per §5.6 canonicalization; compare timing-safe. FAIL if mismatch.
11. **If `signature` non-null:** validate format; require `public_key`; verify Ed25519 over canonical core bytes. FAIL if invalid.
12. **If `manifest_signature` non-null:** validate format; require `public_key`; verify Ed25519 over canonical manifest bytes per §5.8. FAIL if invalid. L2/L3 verifiers SHOULD additionally warn when extension keys do not match a known registered prefix (§17.5) or the `x-<vendor>-` pattern (§6.1). This is a warning, not a failure.
13. **If `anchor_reference` non-null:**
    - If `verify_anchor=True`: call `anchor_resolver`; compare `asset_id` and `core_fingerprint` (timing-safe); set `anchor_verified=true` on match.
    - If `verify_anchor=false` or no fetcher: emit warning; `anchor_verified=false`.
14. **Return** `VerificationResult` with:
    - `success` (bool)
    - `message` (str)
    - `match_type` (`"hard"` | `"soft"` | `None`)
    - `signature_verified` (bool)
    - `manifest_signature_verified` (bool)
    - `anchor_checked` (bool)
    - `anchor_verified` (bool)
    - `warnings` (list\[str\])

All hash comparisons MUST use timing-safe equality (`hmac.compare_digest`).

---

## 11. Recommended Extension Fields

| Field | Type | Description |
|---|---|---|
| `camera_model` | String | Device model |
| `exposure_time` | String | Shutter speed (e.g. `"1/120"`) |
| `iso` | Integer | ISO sensitivity |
| `software` | String | Software used to create/edit |
| `ai_model_used` | String or null | AI model identifier; null if not AI-generated |
| `ai_model_version` | String or null | AI model version |
| `license` | String | SPDX identifier (e.g. `"CC-BY-4.0"`) |
| `soft_binding` | Object | pHash soft binding (§6.2) |
| `compliance_level` | Integer | Self-declared conformance level (1, 2, or 3). Informational. Not to be confused with the `compliance` extension namespace (§11.2), which carries jurisdiction-specific regulatory records. |
| `description` | String (max 256 chars) | Human-readable note about the asset's provenance context (e.g. "Photo taken at Berlin summit, edited in Lightroom"). MUST NOT be used for machine-parseable metadata, rights declarations, or version history. |
| `ai_declaration` | Object | Structured AI disclosure (§11.1) |
| `compliance` | Object | Jurisdiction-specific regulatory compliance records (§11.2) |
| `public_key` | String | Base64-encoded Ed25519 public key for self-contained verification. See §11.3. |

### 11.1 AI Declaration Extension

The `ai_declaration` extension provides structured AI disclosure. It is the recommended approach for any context requiring machine-readable, verifiable documentation of AI involvement in content creation or manipulation. For Article 50 compliance, `ai_declaration` MUST be present and MUST accurately reflect the nature of AI involvement. See §11.2 for the jurisdiction-specific compliance record that documents editorial accountability on top of this disclosure layer.

The `rights` field for machine-readable AI usage declarations is planned for v0.6.

| Field | Type | Requirement | Description |
|---|---|---|---|
| `ai_declaration.disclosure_required` | Boolean | MUST | True if AI contributed to this content |
| `ai_declaration.ai_generated` | Boolean | MUST | Content is fully AI-generated |
| `ai_declaration.ai_manipulated` | Boolean | MUST | Existing content was substantially altered by AI |
| `ai_declaration.human_reviewed` | Boolean | MUST | A human reviewed AI-generated content before publication |
| `ai_declaration.standard_editing` | Boolean | OPTIONAL | Only standard editing was used (cropping, colour correction, noise removal). Exempt from disclosure per Article 50.2 |
| `ai_declaration.creative_work` | Boolean | OPTIONAL | Artistic, satirical, or fictional work. Reduced disclosure obligations per Article 50.4 |

When `ai_declaration.human_reviewed` is true, `compliance.eu_art50` (§11.2) SHOULD be present. To assert the editorial exemption under Article 50(4), `reviewer_name`, `reviewer_role`, `reviewer_contact`, `editorial_responsibility`, `review_timestamp`, and `review_type` MUST all be present in `compliance.eu_art50`.

When `ai_declaration.standard_editing` is true, `disclosure_required` MUST be false. Standard editing does not trigger AI disclosure obligations under Article 50.

When `ai_declaration.creative_work` is true, the visual provenance indicator SHOULD be rendered in a reduced format that does not hamper display or enjoyment of the work.

### 11.2 Compliance Extension Namespace

The `compliance` extension is a structured namespace for jurisdiction-specific regulatory compliance records. Each sub-key identifies a specific legislative framework. New sub-keys are added as official extensions through the AIOSchema Extension Registry process (§17.5) when legislation requires structured compliance documentation.

`compliance` is an object. Each key within it identifies a jurisdiction-specific record:

```json
"compliance": {
  "eu_art50": { ... }
}
```

Future entries follow the same pattern. Examples of planned sub-keys as relevant legislation matures:

| Sub-key | Legislation |
|---|---|
| `eu_art50` | EU AI Act Article 50, editorial exemption record |
| `ca_sb1047` | California SB 1047, AI safety obligations (if enacted) |
| `can_aida` | Canada Artificial Intelligence and Data Act |

#### 11.2.1 `compliance.eu_art50` (Normative)

`compliance.eu_art50` documents the editorial review record required to assert the editorial exemption under Article 50(4) of the EU AI Act, as specified in the Commission Guidelines on Article 50 transparency obligations (May 2026) and Code of Practice Measure 4.3.

All fields are OPTIONAL in the JSON Schema. Fields marked MUST below MUST be present when the publisher claims the editorial exemption. Manifests that include `compliance.eu_art50` without the required exemption fields remain fully valid AIOSchema manifests; they do not assert the editorial exemption.

| Field | Type | Required for exemption | Legal basis |
|---|---|---|---|
| `reviewer_id` | String (`ed25519-fp-<32hex>`) | RECOMMENDED | Cryptographic anchor binding reviewer identity to Ed25519 keypair |
| `reviewer_name` | String | MUST | Code of Practice Measure 4.3: responsible person identified by name |
| `reviewer_role` | String | MUST | Code of Practice Measure 4.3: responsible person identified by role |
| `reviewer_contact` | String (email or URI) | MUST | Code of Practice Measure 4.3: responsible person identified by contact details |
| `editorial_responsibility` | String | MUST | Art. 50(4): natural or legal person holding editorial responsibility |
| `review_timestamp` | String (ISO 8601 UTC) | MUST | Code of Practice: date of approval retained in internal logs |
| `review_type` | String (enum) | MUST | Commission Guidelines May 2026: nature of review |

`review_type` MUST be one of:

- `substantive`: deliberate examination of content substance by a person with relevant competence and professional judgement. Satisfies the editorial exemption.
- `editorial-control`: editorial control exercised by a responsible person. Alternative limb of Art. 50(4). Satisfies the editorial exemption.

Superficial checks (spell-checking, grammar correction, cursory approval without substantive engagement) do NOT satisfy the exemption per the May 2026 Commission Guidelines on Article 50 transparency obligations.

**Verifier behaviour:** Verifiers SHOULD emit a warning when `compliance.eu_art50` is present but any of `reviewer_name`, `reviewer_role`, `reviewer_contact`, or `review_type` are absent:

> "Incomplete editorial exemption documentation: may not satisfy Code of Practice Measure 4.3 (EU AI Act Article 50(4))"

This is a warning, not a verification failure. The manifest signature integrity is unaffected by the completeness of exemption documentation.

**Level 2 example (signed, no anchor):**

All signature and fingerprint values are illustrative placeholders. Real Ed25519 signatures are exactly 128 hex characters. Real SHA-256 fingerprints are exactly 64 hex characters.

```html
<head>
  <script type="application/ld+json">
  {
    "@context": "https://aioschema.org/v1",
    "@type": "https://aioschema.org/v1/Manifest",
    "core": {
      "asset_id": "01914de8-6a10-7083-a24a-1a73f2e9b000",
      "schema_version": "0.5.6",
      "creation_timestamp": "2026-05-07T14:30:00Z",
      "hash_original": [
        "sha256-4a3b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b"
      ],
      "core_fingerprint": "sha256-c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9",
      "creator_id": "ed25519-fp-7fcc5530c17565c99ea02d846ab0b5eb",
      "signature": "ed25519-<128-hex-chars>",
      "manifest_signature": "ed25519-<128-hex-chars>",
      "anchor_reference": null
    },
    "extensions": {
      "compliance_level": 2,
      "ai_declaration": {
        "disclosure_required": true,
        "ai_generated": true,
        "ai_manipulated": false,
        "human_reviewed": true,
        "standard_editing": false,
        "creative_work": false
      },
      "compliance": {
        "eu_art50": {
          "reviewer_id": "ed25519-fp-3ab4c5d6e7f8901234567890abcdef12",
          "reviewer_name": "Jane Smith",
          "reviewer_role": "Senior Editor",
          "reviewer_contact": "editorial@organisation.com",
          "editorial_responsibility": "Organisation Legal Name or Natural Person Name",
          "review_timestamp": "2026-05-07T15:00:00Z",
          "review_type": "substantive"
        }
      }
    }
  }
  </script>
</head>
```

**Level 3 example (signed, anchored):**

```html
<head>
  <script type="application/ld+json">
  {
    "@context": "https://aioschema.org/v1",
    "@type": "https://aioschema.org/v1/Manifest",
    "core": {
      "asset_id": "01914de8-6a10-7083-a24a-1a73f2e9b001",
      "schema_version": "0.5.6",
      "creation_timestamp": "2026-05-07T14:30:00Z",
      "hash_original": [
        "sha256-4a3b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b"
      ],
      "core_fingerprint": "sha256-c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9",
      "creator_id": "ed25519-fp-7fcc5530c17565c99ea02d846ab0b5eb",
      "signature": "ed25519-<128-hex-chars>",
      "manifest_signature": "ed25519-<128-hex-chars>",
      "anchor_reference": "aios-anchor:rfc3161-sectigo:abc123def456"
    },
    "extensions": {
      "compliance_level": 3,
      "ai_declaration": {
        "disclosure_required": true,
        "ai_generated": true,
        "ai_manipulated": false,
        "human_reviewed": true,
        "standard_editing": false,
        "creative_work": false
      },
      "compliance": {
        "eu_art50": {
          "reviewer_id": "ed25519-fp-3ab4c5d6e7f8901234567890abcdef12",
          "reviewer_name": "Jane Smith",
          "reviewer_role": "Senior Editor",
          "reviewer_contact": "editorial@organisation.com",
          "editorial_responsibility": "Organisation Legal Name or Natural Person Name",
          "review_timestamp": "2026-05-07T15:00:00Z",
          "review_type": "substantive"
        }
      }
    }
  }
  </script>
</head>
```

The same manifest SHOULD also be written as a sidecar file (`/path/to/page.html.aios.json`) at deploy time. The JSON-LD block provides in-page verification; the sidecar provides asset-level verification independently of the HTML document.

### 11.3 `public_key` Extension Field (Normative)

The `public_key` extension field enables self-contained verification: everything needed to verify a signed manifest travels with the manifest itself, with no network dependency.

```json
"extensions": {
  "public_key": "MCowBQYDK2VwAyEAj4VZRK5VJThKGx8LYXeF8YvjNWKpWnLqM3rXeV4Q9sM="
}
```

The value is the Base64-encoded raw 32-byte Ed25519 public key.

**Fingerprint cross-check (Normative):**

A verifier MUST validate the embedded public key against `creator_id` before using it for signature verification:

1. Decode the Base64 `public_key` value to raw bytes.
2. Compute `SHA-256(raw_bytes)` and take the first 16 bytes (32 hex characters).
3. Construct the expected `creator_id`: `ed25519-fp-<32hex>`.
4. Compare against the manifest's `creator_id` using timing-safe equality.
5. If they do not match: FAIL. The embedded public key does not belong to the declared creator. Do not proceed with signature verification.
6. If they match: use the decoded public key for signature verification (§10, steps 11 to 12).

An attacker who substitutes both the manifest content and the embedded public key cannot pass this check without also forging the `creator_id`, which would invalidate the `core_fingerprint`. This cross-check is what makes `extensions.public_key` as trustworthy as a key fetched from an external source.

When both `extensions.public_key` and a Creator Key Discovery result (§9.5) are available, the verifier SHOULD prefer the discovered key and MUST verify that both keys are identical. A mismatch between the embedded key and the discovered key MUST produce a warning and SHOULD cause verification to fail.

The public key is public by design. Publishing it in the manifest increases verifiability: more copies of the public key in more places makes it harder to deny or revoke authorship.

---

## 12. Security and Privacy

### 12.1 Security

AIOSchema's security model rests on three architectural principles that are mathematically enforced by the design, not by policy.

**The Core Block hash chain is tamper-evident by design.**
The `core_fingerprint` is computed over the five frozen Core Block fields: `asset_id`, `schema_version`, `creation_timestamp`, `hash_original`, and `creator_id`. Any modification to any of these fields, however small, produces a different fingerprint. Any modification to the fingerprint itself is immediately detectable on verification. There is no valid manifest in which the core fields have been tampered with and the `core_fingerprint` still passes. This principle holds indefinitely, independent of any anchor, signature, or external service.

**Asset substitution is detectable by design.**
`hash_original` is computed over the binary content of the asset. Any substitution of the asset, even a single bit change, produces a different hash. Multi-hash manifests strengthen this further: an attacker would need to simultaneously produce a collision across every algorithm in the array. This principle holds as long as at least one supported algorithm in the manifest remains collision-resistant.

**Prior existence is independently verifiable through anchoring.**
Once a manifest's `core_fingerprint` is anchored, the anchor timestamp establishes that the exact asset and core metadata existed before that point in time, independently of any clock, system, or authority controlled by the author. Copying a manifest and re-anchoring it produces a later timestamp, not an earlier one. Provenance cannot be fabricated retroactively: you cannot anchor to the past.

### 12.2 Privacy

AIOSchema enforces privacy at the Core Block level through architectural design.

**Anonymous mode** (`creator_id` as UUID v7 or v4): no identity is disclosed anywhere in the Core Block. The manifest is fully verifiable (hash integrity, fingerprint, anchor) without revealing anything about the creator. This is the default mode.

**Attributed mode** (`creator_id` as `ed25519-fp-<32hex>`): the creator has explicitly chosen to link the manifest to their public key fingerprint. This choice is made at creation time. Once anchored, the attribution is permanent and irrevocable: it cannot be removed from the provenance chain.

**Extension field risk:** Extension fields are outside the Core Block and outside the `core_fingerprint` computation. Implementers MUST be aware that extensions can carry personally identifying information. The `manifest_signature` field, when present, covers extensions, but it does not prevent disclosure. Implementers SHOULD audit extension fields before publication when anonymous mode is required.

### 12.3 Resistance

**Manifest forgery is detectable by design.** A copied or modified manifest will fail `core_fingerprint` verification. A manifest with a valid fingerprint but a substituted asset will fail `hash_original` verification. There is no path to a passing verification result on a forged manifest without a collision attack on the hash algorithm.

**False attribution is detectable by design.** An attacker cannot add a valid `signature` or `manifest_signature` to a manifest without the creator's private key. Unsigned manifests are valid but carry no attribution claim: verifiers MUST treat unsigned manifests accordingly.

**Replay attacks are detectable by design.** Anchoring ties the manifest to a specific point in time. A copied manifest re-anchored later produces a later timestamp. The original anchor, if present, always establishes prior existence.

**Threshold manipulation is prevented by design.** The `soft_binding.threshold_info` field in the manifest is informational only. Verifiers MUST use their own configured threshold policy and MUST NOT read the threshold from the manifest. This prevents an attacker from manipulating soft binding results by modifying the manifest.

### 12.4 Implementation Requirements

Implementations MUST:
- Use Ed25519 for all signatures (`signature`, `manifest_signature`)
- Use cryptographically secure RNG for UUID generation
- Use timing-safe comparison for all hash and signature comparisons
- Validate hash format before performing any comparison
- Validate `anchor_resolver` return values before comparing (never trust unchecked input)

Implementations MUST NOT:
- Trust `soft_binding.threshold_info` from the manifest
- Accept signature verification without caller-supplied public key
- Store private keys in the manifest or sidecar

---

## 13. Governance Model

AIOSchema is currently in its founder-controlled pre-governance phase. The specification is authored and maintained by its founder, with full editorial control.

An independent AIOSchema Foundation will be established to provide operational stewardship, maintain the mechanism registries, and support implementers. The founder will retain a permanent voting role in that organization, with all charter details defined at the time of its creation.

### 13.1 IPR and Patent Non-Assertion Policy

AIOSchema is committed to remaining implementable on a royalty-free basis.

**Specification:** The specification text is licensed under [CC-BY 4.0](https://creativecommons.org/licenses/by/4.0/). Reference implementations are licensed under Apache 2.0.

**Patent non-assertion:** The founder grants all implementers a perpetual, worldwide, royalty-free, non-exclusive, non-transferable license to any patent claims necessarily infringed by a conforming implementation of this specification. This commitment applies to all versions of AIOSchema published under the AIOSchema project.

**Registered mechanisms:** The Royalty-Free IPR commitment extends to all algorithms and mechanisms registered in the AIOSchema registries (§17). Registry licensees are bound by the same RF commitment for any contributions they make to the registries.

The formal IPR policy, including the patent non-assertion covenant, is published at `https://aioschema.org/ipr/`. Upon establishment of the AIOSchema Foundation, IPR stewardship transfers to the Foundation.

---

## 14. Backward Compatibility and Stability Policy (Normative)

v0.5.6 verifiers MUST accept `schema_version` values `"0.1"` through `"0.5.6"` to preserve the founding provenance chain integrity. Processing semantics are appropriate to the declared version.

`hash_original` as a string (v0.4 and earlier) MUST be accepted by v0.5.x verifiers.

`core_fingerprint` is the v0.5.5 rename of `hash_schema_block`. Verifiers MUST accept both field names and treat them as equivalent. `hash_schema_block` is deprecated as of v0.5.5 and will be removed in v0.6.

**Stability policy:** PATCH increments are editorial only. MINOR increments add features without breaking changes. MAJOR increments may introduce breaking changes and require a new conformance baseline.

---

## 15. Future Directions

v0.6 is planned to add DID-based `creator_id` mode, UUID v8 support, a reference anchor service, the `rights` field for machine-readable AI usage declarations, and `anchor_reference` array support. Feedback and implementation reports are welcome via `https://aioschema.org/contribute`.

---

## 16. Example Manifests (Informative)

All signature and hash values below are illustrative placeholders. Real Ed25519 signatures are exactly 128 hex characters. Real SHA-256 hashes are exactly 64 hex characters.

**Level 1: minimal, unsigned, no anchor:**

```json
{
  "core": {
    "asset_id": "019c7cb0-6e40-7f21-873b-9a9cf13e461a",
    "schema_version": "0.5.6",
    "creation_timestamp": "2026-05-10T12:00:00Z",
    "hash_original": "sha256-abc123def456abc123def456abc123def456abc123def456abc123def456abc1",
    "core_fingerprint": "sha256-def456abc123def456abc123def456abc123def456abc123def456abc123def4",
    "creator_id": "019c7cb0-6e40-7f21-873b-9a9cf13e4600",
    "signature": null,
    "manifest_signature": null,
    "anchor_reference": null
  },
  "extensions": {
    "compliance_level": 1,
    "description": "Example Level 1 manifest"
  }
}
```

**Level 2: multi-hash, signed, with soft binding and AI declaration:**

```json
{
  "core": {
    "asset_id": "019c7cb0-6e40-7f21-873b-9a9cf13e461b",
    "schema_version": "0.5.6",
    "creation_timestamp": "2026-05-10T12:00:00Z",
    "hash_original": [
      "sha256-abc123def456abc123def456abc123def456abc123def456abc123def456abc1",
      "sha384-def456abc123def456abc123def456abc123def456abc123def456abc123def456abc123def456abc123def456abc123"
    ],
    "core_fingerprint": "sha256-def456abc123def456abc123def456abc123def456abc123def456abc123def4",
    "creator_id": "ed25519-fp-7fcc5530c17565c99ea02d846ab0b5eb",
    "signature": "ed25519-<128-hex-chars>",
    "manifest_signature": "ed25519-<128-hex-chars>",
    "anchor_reference": null
  },
  "extensions": {
    "camera_model": "Example Camera Model",
    "license": "CC-BY-4.0",
    "ai_model_used": null,
    "compliance_level": 2,
    "soft_binding": {
      "algorithm": "pHash-v1",
      "fingerprint": "8f3c2a1b4e5d6f7a",
      "threshold_info": 5
    },
    "ai_declaration": {
      "disclosure_required": false,
      "ai_generated": false,
      "ai_manipulated": false,
      "human_reviewed": false
    }
  }
}
```

**Level 3: signed, anchored, with full AI and compliance record:**

```json
{
  "core": {
    "asset_id": "019c7cb0-6e40-7f21-873b-9a9cf13e461c",
    "schema_version": "0.5.6",
    "creation_timestamp": "2026-05-10T12:00:00Z",
    "hash_original": [
      "sha256-abc123def456abc123def456abc123def456abc123def456abc123def456abc1",
      "sha384-def456abc123def456abc123def456abc123def456abc123def456abc123def456abc123def456abc123def456abc123"
    ],
    "core_fingerprint": "sha256-def456abc123def456abc123def456abc123def456abc123def456abc123def4",
    "creator_id": "ed25519-fp-7fcc5530c17565c99ea02d846ab0b5eb",
    "signature": "ed25519-<128-hex-chars>",
    "manifest_signature": "ed25519-<128-hex-chars>",
    "anchor_reference": "aios-anchor:rfc3161-sectigo:abc123def456"
  },
  "extensions": {
    "compliance_level": 3,
    "ai_model_used": "example-model-v1",
    "license": "CC-BY-4.0",
    "ai_declaration": {
      "disclosure_required": true,
      "ai_generated": true,
      "ai_manipulated": false,
      "human_reviewed": true,
      "standard_editing": false,
      "creative_work": false
    },
    "compliance": {
      "eu_art50": {
        "reviewer_id": "ed25519-fp-3ab4c5d6e7f8901234567890abcdef12",
        "reviewer_name": "Jane Smith",
        "reviewer_role": "Senior Editor",
        "reviewer_contact": "editorial@organisation.com",
        "editorial_responsibility": "Organisation Legal Name or Natural Person Name",
        "review_timestamp": "2026-05-10T13:00:00Z",
        "review_type": "substantive"
      }
    }
  }
}
```

---

## 17. Mechanism Registries (Normative)

AIOSchema uses registries to manage pluggable mechanisms: hash algorithms, signature algorithms, anchor services, and extension prefixes. Registries are the formal mechanism by which the standard evolves without breaking compatibility.

### 17.1 Hash Algorithm Registry

| Token | Digest Length | Status | Since |
|---|---|---|---|
| `sha256` | 64 hex chars | REQUIRED | v0.1 |
| `sha3-256` | 64 hex chars | OPTIONAL | v0.4 |
| `sha384` | 96 hex chars | OPTIONAL | v0.5 |

### 17.1.1 Algorithm Registration Contract (Normative)

A conforming hash algorithm module MUST satisfy the following language-neutral contract:

| Property | Requirement |
|---|---|
| **Token** | A unique string identifier (e.g. `sha256`, `sha3-256`). MUST be lowercase, alphanumeric with hyphens only. |
| **Digest length** | Fixed number of hex characters in the output digest. MUST be declared. |
| **compute(bytes) → string** | Accepts raw bytes of the asset. Returns a prefixed hex digest string: `<token>-<hex>`. |
| **verify(bytes, digest) → bool** | Recomputes the digest and compares using timing-safe equality. Returns true on match. |
| **regex** | A validation pattern that enforces exact token and digest length. |

New algorithms are registered in §17.1. An algorithm not in the registry MUST NOT be used in conforming implementations without a registry entry.

Deprecated algorithms remain in the registry with status DEPRECATED. Verifiers MUST continue to accept deprecated algorithms for backward compatibility. Generators SHOULD NOT produce new manifests using deprecated algorithms.

### 17.2 Signature Algorithm Registry

| Token | Key Format | Status | Since |
|---|---|---|---|
| `ed25519` | 32-byte public key | REQUIRED | v0.1 |

### 17.3 Anchor Service Registry

The anchor service registry is a living document published at `https://aioschema.org/registries/anchor-services/`.

A conforming anchor service MUST satisfy the requirements in §9. Any service satisfying those requirements MAY be used regardless of registry status. The registry provides a curated list of known-conforming services for implementer convenience. It is not a gatekeeping mechanism.

### 17.4 Registry Governance

During the founder-controlled phase, the founder maintains all registries, including the Extension Registry (§17.5). New mechanism entries are accepted via the public process at `https://aioschema.org/registry/propose`. Extension prefix registration follows the process described at `https://aioschema.org/registry/`.

Upon establishment of the AIOSchema Foundation, registry maintenance transfers to the Foundation. The Royalty-Free IPR commitment applies to all registered mechanisms.

### 17.5 Extension Registry (Normative)

The Extension Registry records all registered extension names: both official extensions maintained by the AIOSchema project and vendor extensions using the `x-<vendor>-` prefix.

The Extension Registry is published at `https://aioschema.org/registries/extensions/`.

#### 17.5.1 Official Extensions

Official extensions are maintained by the AIOSchema project under the namespace `https://aioschema.org/extensions/`. They do not carry an `x-` prefix and are part of the open standard.

| Field | Status | Since | Description |
|---|---|---|---|
| `camera_model` | OPTIONAL | v0.1 | Device model |
| `exposure_time` | OPTIONAL | v0.1 | Shutter speed |
| `iso` | OPTIONAL | v0.1 | ISO sensitivity |
| `software` | OPTIONAL | v0.1 | Software used to create/edit |
| `ai_model_used` | OPTIONAL | v0.1 | AI model identifier |
| `ai_model_version` | OPTIONAL | v0.5 | AI model version |
| `license` | OPTIONAL | v0.1 | SPDX identifier |
| `soft_binding` | OPTIONAL | v0.3 | Perceptual hash (§6.2) |
| `compliance_level` | OPTIONAL | v0.3.1 | Self-declared conformance level (1/2/3) |
| `description` | OPTIONAL | v0.5.6 | Human-readable provenance context note (max 256 chars) |
| `ai_declaration` | OPTIONAL | v0.5.6 | Structured AI disclosure (§11.1) |
| `compliance` | OPTIONAL | v0.5.6 | Jurisdiction-specific regulatory compliance records (§11.2) |
| `public_key` | OPTIONAL | v0.5.6 | Base64-encoded Ed25519 public key for self-contained verification (§11.3) |

`ai_declaration` is OPTIONAL for general use. For manifests where the publisher asserts Article 50 compliance, `ai_declaration` MUST be present and MUST accurately reflect the nature of AI involvement.

`compliance` is OPTIONAL for general use. For manifests where the publisher asserts the Article 50(4) editorial exemption, `compliance.eu_art50` MUST be present with all required exemption fields populated per §11.2.1.

#### 17.5.2 Vendor Extensions

Vendor extensions use a registered `x-<vendor>-` prefix. Each prefix is registered once per vendor. Fields under a registered prefix are the vendor's responsibility and MUST be documented before use in conforming manifests.

| Prefix | Maintainer | Status | Since | Registered Fields |
|---|---|---|---|---|
| `x-aioschemahub` | AIOSchemaHub.com | ACTIVE | v0.5.6 | `x-aioschemahub-page-assets` |

Vendor prefix registration requirements:

- The prefix MUST be unique: no two vendors may register the same prefix.
- The prefix MUST NOT conflict with any Core Block field or registered extension name.
- Fields under the prefix MUST be documented before use in conforming manifests.
- The combined extension payload MUST fit within the size limit (§6.3).
- The prefix MUST be registered before it appears in conforming manifests.

Commercial use of a registered vendor prefix requires a registry license. Registration fees, terms, and the registration process are published at `https://aioschema.org/registry/`.

#### 17.5.3 Governance

Registry governance follows §17.4. The founder maintains all registries during the founder-controlled phase. Upon establishment of the AIOSchema Foundation, Extension Registry maintenance transfers to the Foundation.

### 17.6 Vendor and Industry Extensions

Implementers building domain-specific applications on AIOSchema: product passports, firmware provenance, logistics, pharma, and other verticals, SHOULD use namespaced vendor extensions with their organisation identifier:

```
x-{org-identifier}-{field-name}
```

Examples:

- `x-gs1-gtin` : GS1 Global Trade Item Number
- `x-eudamed-device-id` : EU medical device identifier
- `x-nmvs-serial` : EU pharma serialisation (NMVS)

Vendor extensions are not validated by AIOSchema verifiers. Verifiers MUST ignore unknown extension keys (tolerant reader principle). All vendor extensions MUST be registered per §17.5.2 before use in conforming manifests.

---

## 18. Security Considerations

The security, privacy, and abuse resistance properties of AIOSchema are addressed architecturally in §12. The Core Block fields are frozen and tamper-evident by design: any modification is detectable through `core_fingerprint` verification. Anonymous mode provides zero-disclosure provenance by default. Provenance cannot be fabricated retroactively: anchoring ties a manifest to a specific point in time that cannot be altered. Implementers MUST follow the requirements in §12.4.

Security vulnerabilities discovered in AIOSchema implementations or the specification itself MUST be reported to security@aioschema.org. The AIOSchema project commits to acknowledging reports within 24 hours and issuing a resolution or public advisory within 7 days. Vulnerabilities may also be reported via the GitHub repository issue tracker at `https://github.com/aioschema/aioschema/issues` using the `security` label.

---

## Appendix A: JSON Schema (Normative)

Published at `https://aioschema.org/schemas/v0.5.6/manifest.json`.

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://aioschema.org/schemas/v0.5.6/manifest.json",
  "title": "AIOSchema Manifest v0.5.6",
  "type": "object",
  "required": ["core"],
  "properties": {
    "core": {
      "type": "object",
      "required": [
        "asset_id", "schema_version", "creation_timestamp",
        "hash_original", "core_fingerprint", "creator_id"
      ],
      "properties": {
        "asset_id": { "type": "string" },
        "schema_version": {
          "type": "string",
          "enum": ["0.1","0.2","0.3","0.3.1","0.4","0.5","0.5.1","0.5.5","0.5.6"]
        },
        "creation_timestamp": {
          "type": "string",
          "pattern": "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$"
        },
        "hash_original": {
          "anyOf": [
            {
              "type": "string",
              "pattern": "^(sha256|sha3-256)-[0-9a-f]{64}$|^sha384-[0-9a-f]{96}$"
            },
            {
              "type": "array",
              "items": {
                "type": "string",
                "pattern": "^(sha256|sha3-256)-[0-9a-f]{64}$|^sha384-[0-9a-f]{96}$"
              },
              "minItems": 1,
              "uniqueItems": true
            }
          ]
        },
        "core_fingerprint": {
          "type": "string",
          "pattern": "^(sha256|sha3-256)-[0-9a-f]{64}$|^sha384-[0-9a-f]{96}$"
        },
        "creator_id": { "type": "string" },
        "signature": {
          "type": ["string", "null"],
          "if": { "type": "string" },
          "then": { "pattern": "^ed25519-[0-9a-f]{128}$" }
        },
        "manifest_signature": {
          "type": ["string", "null"],
          "if": { "type": "string" },
          "then": { "pattern": "^ed25519-[0-9a-f]{128}$" }
        },
        "anchor_reference": {
          "type": ["string", "null"],
          "if": { "type": "string" },
          "then": { "pattern": "^aios-anchor:[a-z0-9_-]+:[a-zA-Z0-9_-]+$" }
        },
        "previous_version_anchor": {
          "type": ["string", "null"],
          "if": { "type": "string" },
          "then": { "pattern": "^aios-anchor:[a-z0-9_-]+:[a-zA-Z0-9_-]+$" },
          "description": "Anchor URI of the immediately preceding version. Creates a cryptographic version chain. See §9."
        }
      },
      "additionalProperties": false
    },
    "extensions": {
      "type": "object",
      "properties": {
        "camera_model": { "type": "string" },
        "exposure_time": { "type": "string" },
        "iso": { "type": "integer" },
        "software": { "type": "string" },
        "ai_model_used": { "type": ["string", "null"] },
        "ai_model_version": { "type": ["string", "null"] },
        "license": { "type": "string" },
        "soft_binding": {
          "type": "object",
          "properties": {
            "algorithm": { "type": "string" },
            "fingerprint": { "type": "string" },
            "threshold_info": { "type": "integer" }
          },
          "required": ["algorithm", "fingerprint"]
        },
        "compliance_level": { "type": "integer", "minimum": 1, "maximum": 3 },
        "description": {
          "type": "string",
          "maxLength": 256,
          "description": "Human-readable provenance context note"
        },
        "public_key": {
          "type": "string",
          "contentEncoding": "base64",
          "description": "Base64-encoded raw 32-byte Ed25519 public key. Verifier MUST perform fingerprint cross-check against creator_id before use. See §11.3."
        },
        "ai_declaration": {
          "type": "object",
          "properties": {
            "disclosure_required": { "type": "boolean" },
            "ai_generated": { "type": "boolean" },
            "ai_manipulated": { "type": "boolean" },
            "human_reviewed": { "type": "boolean" },
            "standard_editing": { "type": "boolean" },
            "creative_work": { "type": "boolean" }
          },
          "required": [
            "disclosure_required", "ai_generated",
            "ai_manipulated", "human_reviewed"
          ]
        },
        "compliance": {
          "type": "object",
          "properties": {
            "eu_art50": {
              "type": "object",
              "properties": {
                "reviewer_id": { "type": "string", "pattern": "^ed25519-fp-[0-9a-f]{32}$" },
                "reviewer_name": { "type": "string" },
                "reviewer_role": { "type": "string" },
                "reviewer_contact": { "type": "string" },
                "editorial_responsibility": { "type": "string" },
                "review_timestamp": {
                  "type": "string",
                  "pattern": "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$"
                },
                "review_type": {
                  "type": "string",
                  "enum": ["substantive", "editorial-control"]
                }
              }
            }
          },
          "additionalProperties": true
        }
      },
      "additionalProperties": true
    }
  }
}
```

`additionalProperties: true` on `extensions` allows vendor `x-<vendor>-` fields to pass through without schema-level constraint. Their conformance is enforced by the Extension Registry (§17.5), not by the JSON Schema. `additionalProperties: true` on `compliance` allows future jurisdiction sub-keys to be added without a schema update.

---

## Appendix B: Version History

> **Date columns:** *Authored* is when the version was created and anchored (immutable). *Published* is when it became publicly available on aioschema.org. These are distinct by design. See §9 and the header note above.

| Version | Authored | Published | Summary |
|---|---|---|---|
| v0.1 | Jan 2026 | Archived | Initial draft; minimal core; basic extensions |
| v0.2 | Feb 2026 | Archived | Interoperability, durability, governance, regulatory alignment |
| v0.3 | Feb 2026 | Archived | RFC 2119 language, backward compat, security, C2PA note |
| v0.3.1 | Feb 2026 | Archived | Conformance levels, JSON Schema, timeline, editorial refinements |
| v0.4 | Feb 2026 | Archived | Multi-hash, detached manifest signature, SHA-384, configurable soft-binding threshold, Level 3, anchor resolver contract |
| v0.5 | Feb 2026 | Archived | `hash_original` as array (§5.5); `manifest_signature` (§5.8); SHA-384 (§5.3); configurable soft-binding threshold (§8.3); Level 3 conformance tier; `anchor_resolver` contract (§9.2) |
| v0.5.1 | Feb 2026 | Archived | `previous_version_anchor` field; governance rewritten as founder-controlled pre-governance phase with binding RF IPR commitment; Founding Provenance added |
| **v0.5.5** | March 17, 2026 | Archived | `core_fingerprint` rename; `anchor_resolver` rename; C2PA label stabilised; Design Philosophy added; language-neutral contracts; Mechanism Registries; reference implementations in Python, TypeScript, Node.js, Go, and Rust |
| **v0.5.6** | May 28, 2026 | Final | Extension Registry (§17.5); extension namespacing with licensed vendor registration (§6.1); extension size limit 4KB (§6.3); `ai_declaration` official extension with structured AI disclosure (§11.1); `compliance` official extension namespace for jurisdiction-specific regulatory records (§11.2); `compliance.eu_art50` editorial exemption record for EU AI Act Article 50(4) (§11.2.1); HTML JSON-LD examples for Level 2 and Level 3 (§11.2.1); C2PA integration direction clarified (§7.1); JSON Schema updated with `compliance` namespace (Appendix A); registry governance consolidated (§17.4); `public_key` extension field with normative fingerprint cross-check (§11.3); `manifest_signature` covers core + extensions (§5.8); multi-hash `hash_original` as array (§5.5); .NET implementation; test vectors TV-01 through TV-24 (TV-19 through TV-24 added in this version) |

---

## Appendix C: EXIF/XMP Mapping Table (Normative)

Custom XMP namespace: `https://aioschema.org/xmp/v1/` with prefix `aioschema`.

The namespace uses a stable `v1` major-version designator. It does not change on minor version increments. See §8.1.

| AIOSchema Field | EXIF Tag | XMP Property | Notes |
|---|---|---|---|
| `creation_timestamp` | DateTimeOriginal (0x9003) | `xmp:CreateDate` | UTC |
| `camera_model` | Make + Model (0x010F, 0x0110) | `xmp:CreatorTool` | Concatenate |
| `exposure_time` | ExposureTime (0x829A) | `exif:ExposureTime` | Rational |
| `iso` | ISOSpeedRatings (0x8827) | `exif:ISOSpeedRatings` | Integer |
| `software` | Software (0x0131) | `xmp:CreatorTool` | String |
| `license` | (none) | `xmpRights:UsageTerms` | SPDX |
| `description` | ImageDescription (0x010E) | `dc:description` | Dublin Core |
| `ai_model_used` | (none) | `aioschema:aiModelUsed` | Custom |
| `asset_id` (core) | (none) | `aioschema:assetId` | Custom |
| `schema_version` (core) | (none) | `aioschema:schemaVersion` | Custom |
| `core_fingerprint` (core) | (none) | `aioschema:coreFingerprint` | Custom |
| `manifest_signature` (core) | (none) | `aioschema:manifestSignature` | Custom |
| `soft_binding.fingerprint` | (none) | `aioschema:pHashFingerprint` | Custom |

---

## Appendix D: Platform Survivability (Informative)

| Platform | XMP Preserved | Sidecar Supported | EXIF Preserved | Notes |
|---|---|---|---|---|
| Instagram | No | No | Stripped | Sidecar + manifest_signature recommended |
| Threads | No | No | Stripped | Sidecar + manifest_signature recommended |
| X (Twitter) | No | No | Stripped | Sidecar + manifest_signature recommended |
| TikTok | No | No | Stripped | Sidecar + manifest_signature recommended |
| YouTube | Partial | No | Partial | Some XMP survives via description metadata |
| WhatsApp | No | No | Stripped | Sidecar + manifest_signature recommended |
| Telegram | Partial | Yes | Partial | Files sent as documents preserve sidecar; images sent as photos are recompressed and stripped |
| LinkedIn | Partial | No | Partial | Creator mode preserves some fields |
| Dropbox | Yes | Yes | Yes | Recommended for archival |
| Google Drive | Yes | Yes | Yes | Recommended for archival |
| iCloud Drive | Yes | Yes | Yes | Recommended for archival |

---

## Appendix E: Self-Certification Checklist (Normative)

**Level 1**
- [ ] All required Core Block fields present
- [ ] `hash_original` computed with supported algorithm, correct format
- [ ] `core_fingerprint` computed via canonicalization (§5.6)
- [ ] `creation_timestamp` UTC with trailing "Z"
- [ ] Sidecar written as `<filename>.<ext>.aios.json`
- [ ] Core Block preserved unchanged during export
- [ ] All v0.5.6 test vectors (TV-01 through TV-24) pass
- [ ] Verifier accepts `hash_schema_block` as deprecated alias for `core_fingerprint`

**Level 2**: Level 1 plus:
- [ ] `signature` present when signing key available
- [ ] `manifest_signature` present when sidecar integrity required
- [ ] pHash soft binding for image/video assets
- [ ] Hybrid XMP + sidecar embedding
- [ ] Extension fields mapped to EXIF/XMP per Appendix C
- [ ] Verifier uses policy threshold, not `threshold_info` from manifest

**Level 3**: Level 2 plus:
- [ ] `anchor_reference` present
- [ ] Anchor verification performed via conforming `anchor_resolver`
- [ ] `anchor_verified=true` in verification result

**Specification Versions**: additional items for versioned specification documents:
- [ ] Founding anchor created before first publication
- [ ] `previous_version_anchor` present in all versions after genesis
- [ ] Specification bundle manifest published at canonical URL
- [ ] Version chain verifiable end-to-end from genesis

---

## Appendix F: URL Registry and Conformance Pages

The following URLs are normatively referenced in this specification. All MUST resolve before this version is published.

| URL | Status | Spec Reference | Purpose |
|---|---|---|---|
| `/implementations/` | Live | §5.4, §9.2, §15 | Reference implementations landing |
| `/schemas/v0.5.6/manifest.json` | Required | §5.4, §14, App A | Normative JSON Schema |
| `/test-vectors/v0.5.6/` | Required | §5.4 | Conformance test vectors |
| `/registries/extensions/` | Required | §17.5 | Extension Registry |
| `/registry/` | Required | §6.1, §17.5 | Registry governance and licensing |
| `/provenance/` | Required | §5.1 | Founding anchor record and version chain |
| `/compat/c2pa/` | Required | §7.1 | C2PA compatibility notes |
| `/registry/propose/` | Required | §17.4 | Public registry proposal process |
| `/registries/anchor-services/` | Required | §17.3 | Anchor service registry |
| `/extensions/` | Required | §6.1 | Official extension field documentation |
| `/xmp/v1/` | Required | §8.1, App C | XMP namespace URI |
| `/contribute/` | Recommended | §15 | Public contribution intake |
| `/ipr/` | Required | §13.1 | IPR policy and patent non-assertion |
| `/security/` | Required | §18 | Security vulnerability reporting |

**Legacy redirect required:** `/schemas/v0.5/` MUST redirect to `/schemas/v0.5.5/` for backward compatibility with implementations that cached the earlier URL.

---

© 2026 Ovidiu Ancuta · AIOSchema™ and ◈™ are trademarks of Ovidiu Ancuta
Specification: [CC-BY 4.0](https://creativecommons.org/licenses/by/4.0/) · Reference Implementations: Apache 2.0
<!-- end AIOS-SPEC-0001-v0.5.6 | AIOSchema Specification v0.5.6 | https://aioschema.org -->
