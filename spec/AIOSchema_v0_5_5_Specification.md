# AIOSchema Specification v0.5.5
## Public Review Draft

**Status:** Public Review Draft — Not Yet Published
**Maintained by:** AIOSchema Working Group — Founder-Controlled Pre-Governance Phase
**Website:** https://aioschema.org
**License:** Creative Commons Attribution 4.0 International (CC-BY 4.0)
**Replaces:** v0.5.1
**Authored:** February 2026
**Published:** TBD
**Target:** v1.0 stable (Q4 2026)

> **On dates:** *Authored* is when this version was created and anchored — recorded
> immutably in the founding anchor (§18). *Published* is when it became publicly
> available on aioschema.org. These are intentionally distinct: the anchor timestamp
> establishes prior art independently of the publication decision.

---

## Design Philosophy

AIOSchema is deliberately lightweight. A developer should be able to read this specification
in under an hour and produce a working implementation in a day. Every feature added to the
Core Block must justify its complexity cost. v0.5 adds four things that pass that test:
multi-hash support, detached manifest signatures, SHA-384, and a configurable soft-binding
threshold. v0.5.1 adds `previous_version_anchor` — the field that chains each version of
the standard to its predecessor, creating a cryptographic provenance record for the
specification itself. Everything else stays out of the core.

---

## Change Log (v0.5.1 → v0.5.5)

*v0.5.5 is the publication-ready release. It completes the specification language,
adds language-neutral contracts, renames two fields for clarity, and delivers the
TypeScript reference implementation.*

| # | Area | Change | Status |
|---|------|--------|--------|
| 1 | Core Block | `hash_schema_block` renamed to `core_fingerprint` — clearer, no JSON Schema terminology collision | **Renamed** |
| 2 | §9 | `anchor_fetcher` renamed to `anchor_resolver` — language-neutral, consistent snake_case | **Renamed** |
| 3 | §7.1 | C2PA assertion label stabilised to `aioschema.core/v1` — no longer versioned per release | **Changed** |
| 4 | §0 | Design Philosophy inserted as opening section | **Added** |
| 5 | §9.2 | `anchor_resolver` contract rewritten as language-neutral — removes Python-specific syntax | **Revised** |
| 6 | §5.3 | Algorithm registration contract added — formal interface for pluggable algorithms | **Added** |
| 7 | §19 | Mechanism Registries — formal home for algorithm and anchor service registries | **Added** |
| 8 | §15 | Backward compat: `hash_schema_block` accepted as deprecated alias for `core_fingerprint` | **Updated** |
| 9 | §17 | Example manifest updated to `schema_version: "0.5.5"` | **Fixed** |
| 10 | §7.1 | C2PA section rewritten — MAY not MUST, standalone validity stated, note on label format | **Revised** |
| 11 | Implementations | TypeScript reference implementation and test suite | **Added** |

**All v0.5.1 features, test vectors, and normative requirements are unchanged.**
`core_fingerprint` and `hash_schema_block` are accepted as equivalent by all v0.5.5
verifiers. `hash_schema_block` will be removed in v0.6.

**Deferred to v0.6:** DID `creator_id` mode, `creator_keyref` field, UUID v8,
`extensions_version`, reference anchor service.

## Change Log (v0.5 → v0.5.1)

*v0.5.1 is a targeted update. No features added, no breaking changes. Two focused changes only:*

| # | Area | Change | Status |
|---|------|--------|--------|
| 1 | Core Block | `previous_version_anchor` — optional field linking each spec version to its predecessor anchor | **Added** |
| 2 | §14 | Governance model rewritten — founder-controlled pre-governance phase formally defined | **Revised** |
| 3 | §18 | New section: Founding Provenance — self-anchoring procedure for the specification itself | **Added** |
| 4 | JSON Schema | Updated to include optional `previous_version_anchor` field | **Updated** |
| 5 | Appendix B | Version history updated | **Updated** |
| 6 | Appendix F | Level 3 checklist updated with founding provenance item | **Updated** |

**All v0.5 features, test vectors, and normative requirements are unchanged.**

**Deferred to v0.6:** DID `creator_id` mode, `creator_keyref` field, UUID v8,
`extensions_version`. These features require additional design work to remain
consistent with the lightweight architecture.

---

## Change Log (v0.4 → v0.5)

| # | Area | Change | Status |
|---|------|--------|--------|
| 1 | Core Block | `hash_original` may be a single string **or** an array of prefixed hashes | **Added** |
| 2 | Core Block | `manifest_signature` — detached Ed25519 signature over entire manifest | **Added** |
| 3 | Core Block | SHA-384 added to hash algorithm registry (optional) | **Added** |
| 4 | Verification | Soft-binding threshold now verifier-configurable (was global constant) | **Added** |
| 5 | Verification | `manifest_signature` verification step added to §10 | **Added** |
| 6 | Verification | `anchor_resolver` hook contract formally defined | **Added** |
| 7 | Conformance | Level 3 — Anchor-Verified — added as optional tier | **Added** |
| 8 | JSON Schema | Updated for multi-hash, `manifest_signature`, SHA-384 | **Updated** |
| 9 | Test Vectors | New vectors TV-13 through TV-18 | **Added** |
| 10 | Spec | Canonical manifest bytes procedure defined (fixes §10 step 11 gap) | **Fixed** |
| 11 | Spec | SHA-384 regex corrected (per-algorithm exact length) | **Fixed** |
| 12 | Spec | §5.1/§5.2 field duplication resolved | **Fixed** |

---

## 0. Design Philosophy

AIOSchema was created to solve a fundamental problem: digital content needs a universal,
durable, and verifiable provenance layer that works everywhere and depends on no single
system, platform, or technology.

The design philosophy behind AIOSchema rests on four pillars:

- A stable, minimal structure
- Modular, replaceable algorithms
- Universal interoperability
- Long-term durability and verifiability

### 0.1 Stable Core, Modular Algorithms

AIOSchema separates the shape of the standard from the algorithms used inside it.
The Core Block is intentionally minimal and stable — it defines only the fields required
for deterministic identity and verification. Everything else — hashing, signing, soft
binding, anchoring — is treated as a module, not a fixed dependency.

This ensures that no single cryptographic primitive can compromise the whole standard,
algorithms can be replaced without redesigning the manifest, and implementations remain
simple and predictable. AIOSchema v0.5.x uses Ed25519, SHA-256, and pHash as practical
defaults, not permanent requirements. Future versions introduce formal algorithm
registries and deprecation paths (§19).

### 0.2 Universality and Interoperability

A provenance standard is only useful if it works everywhere. AIOSchema is container-agnostic,
platform-agnostic, ecosystem-agnostic, and metadata-agnostic. It integrates cleanly with
XMP, EXIF, schema.org, W3C PROV, and C2PA. It is not a replacement for these systems —
it is a bridge.

### 0.3 Durability and Survivability

Digital content is constantly transformed — recompressed, resized, transcoded, stripped
of metadata. AIOSchema survives these transformations through multi-hash support, detached
signatures, sidecar and XMP hybrid embedding, soft binding via perceptual hashing, and
anchor chaining. Durability is not an afterthought — it is a core design requirement.

### 0.4 Verifiable Without Specialized Tools

A developer can implement a verifier in a day. Verification requires no proprietary tools
or libraries. The manifest is plain JSON. Canonicalization rules are deterministic. The
anchoring mechanism is public and independently verifiable. No single system controls
verification. This is essential for trust.

### 0.5 Anchoring: Pluggable, Public, and Independent

AIOSchema uses a simple, universal anchor URI scheme: `aios-anchor:<service-id>:<anchor-id>`.
This accommodates RFC 3161 trusted timestamp authorities, blockchain-based timestamping,
hybrid services, and any future mechanism that produces a public, immutable, independently
verifiable timestamp. AIOSchema mandates only that anchors be publicly verifiable,
independent of the author, immutable, and timestamped. No specific service is mandated.

### 0.6 Transparency and Provenance of the Standard Itself

AIOSchema uses its own mechanisms to establish the provenance of the specification. Each
version is hashed, signed, anchored, and linked to its predecessor via
`previous_version_anchor`. This creates a cryptographic chain of custody for the standard
itself. The standard practices what it preaches.

### 0.7 Evolution Without Fragmentation

No breaking changes within a minor version increment. Clear versioning semantics. Backward
compatibility for all v0.x manifests. Forward compatibility through algorithm agility.
The goal is a standard that grows without fracturing the ecosystem.

### 0.8 Two Independent Implementations Before Publication

No version of this specification is considered complete until two independent implementations
in different languages verify each other's test vectors. This is not overhead — it is the
mechanism that catches specification ambiguity before it reaches implementers. AIOSchema
v0.5.5 is validated by Python and TypeScript reference implementations.

---

## 1. Introduction

AIOSchema is an open, universal metadata framework for establishing authenticity, provenance,
and transparency across digital and AI-generated content. It defines a minimal, verifiable
Core Block, an extensible Extension Block, and optional durable anchoring.

v0.5.5 is the publication-ready release of AIOSchema. It completes the specification with
language-neutral contracts for anchor resolution and algorithm registration, renames
`hash_schema_block` to the clearer `core_fingerprint`, stabilises the C2PA interoperability
label, and adds the Design Philosophy as §0. All v0.5 features are preserved unchanged.
The fundamental design is unchanged.

**Relationship to C2PA:** AIOSchema is not a replacement for C2PA. It is a lightweight
provenance entry point. Implementers are encouraged to embed AIOSchema core fields as a
custom assertion inside C2PA manifests (`aioschema.core/v1`), or use AIOSchema standalone
where C2PA is impractical.

---

## 2. Normative Language

The key words **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT**, and **MAY** are to be
interpreted as described in RFC 2119.

---

## 3. Design Principles

| Principle | Description |
|-----------|-------------|
| **Minimal Core** | Core Block contains only fields required for deterministic identity and verification. |
| **Interoperability First** | Must interoperate cleanly with C2PA, EXIF/XMP, schema.org, and W3C PROV. |
| **Privacy by Design** | No personal data in the Core Block. Identifiers are non-identifying (UUID v4/v7 or public-key fingerprint). |
| **Technology-Neutral** | No mandatory blockchain, storage system, watermarking, or metadata container. |
| **Durability** | Must survive recompression, resizing, format conversion, and platform uploads. See §8. |
| **Open Governance** | Must transition to neutral multi-stakeholder governance under the timeline in §14. |
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
| `schema_version` | String | MUST | AIOSchema version (e.g. `"0.5"`). |
| `creation_timestamp` | String | MUST | ISO 8601 UTC, must end with `"Z"`. |
| `hash_original` | String **or** Array\<String\> | MUST | Prefixed hash(es) of the binary asset. Format: `<alg>-<hex>`. See §5.5. |
| `core_fingerprint` | String | MUST | Prefixed hash of the canonical core fields. See §5.6. |
| `creator_id` | String | MUST | UUID v7/v4 (anonymous) or `ed25519-fp-<32hex>` (attributed). See §5.7. |
| `signature` | String or null | SHOULD | Ed25519 signature over canonical core bytes. Format: `ed25519-<128hex>`. |
| `manifest_signature` | String or null | SHOULD | Detached Ed25519 signature over canonical manifest bytes. See §5.8. |
| `anchor_reference` | String or null | SHOULD | Anchor URI: `aios-anchor:<service-id>:<anchor-id>`. |
| `previous_version_anchor` | String or null | MAY | Anchor URI of the **immediately preceding version** of this specification or asset lineage. Creates a cryptographic chain of custody across versions. Format: `aios-anchor:<service-id>:<anchor-id>`. See §18. |

**Notes:**
- `hash_original` as a **string** is the legacy single-hash form. `hash_original` as an
  **array** advertises multiple hashes (e.g. SHA-256 and SHA-384). Verifiers accept the
  manifest if **any** advertised algorithm matches and is supported. The array MUST contain
  at least one entry and MUST NOT contain duplicate algorithm tokens.
- `manifest_signature` is null or absent on unsigned manifests. When present and non-null
  the verifier MUST verify it.
- `previous_version_anchor` is used to chain successive versions of a specification,
  document, or asset lineage. It is optional in all asset manifests but SHOULD be
  present in any manifest that represents a versioned document (e.g. a specification).
  Verifiers MUST NOT fail verification if this field is absent or unresolvable — it is
  informational provenance, not an integrity check.

### 5.2 Conformance Levels (Normative)

| Level | Requirements |
|---|---|
| **Level 1 — Minimal** | All required fields present. `hash_original` correct. `core_fingerprint` correct. Sidecar written per §8.2. Core Block preserved on export. All test vectors passed. |
| **Level 2 — Recommended** | Level 1 plus: `signature` present when key available. `manifest_signature` present when sidecar integrity required. pHash soft binding for image/video assets. Hybrid XMP + sidecar embedding. Extension fields mapped to EXIF/XMP per Appendix D. |
| **Level 3 — Anchor-Verified** | Level 2 plus: `anchor_reference` present. Anchor verification performed via `anchor_resolver`. `anchor_verified=True` in verification result. |

Self-declaration is informational. Implementations MUST pass the test vectors for the level they claim (§5.4).

### 5.3 Hash Algorithm Registry (Normative)

| Algorithm Token | Hex Digest Length | Status |
|---|---|---|
| `sha256` | 64 | REQUIRED |
| `sha3-256` | 64 | OPTIONAL |
| `sha384` | 96 | OPTIONAL |

Implementations MUST support `sha256`. Verifiers encountering an unknown token MUST return
a verification failure with a clear error identifying the unsupported algorithm.

**Validation pattern** — algorithms have fixed digest lengths; the regex enforces exact
length per algorithm:

```
^(sha256|sha3-256)-[0-9a-f]{64}$|^sha384-[0-9a-f]{96}$
```

### 5.3.1 Algorithm Registration Contract (Normative)

A conforming hash algorithm module MUST satisfy the following language-neutral contract:

| Property | Requirement |
|---|---|
| **Token** | A unique string identifier (e.g. `sha256`, `sha3-256`). MUST be lowercase, alphanumeric with hyphens only. |
| **Digest length** | Fixed number of hex characters in the output digest. MUST be declared. |
| **compute(bytes) → string** | Accepts raw bytes of the asset. Returns a prefixed hex digest string: `<token>-<hex>`. |
| **verify(bytes, digest) → bool** | Recomputes the digest and compares using timing-safe equality. Returns true on match. |
| **regex** | A validation pattern that enforces exact token and digest length. |

**Registration:** New algorithms are registered in §19.1. An algorithm not in the registry
MUST NOT be used in conforming implementations without a registry entry.

**Deprecation:** Deprecated algorithms remain in the registry with status DEPRECATED.
Verifiers MUST continue to accept deprecated algorithms for backward compatibility.
Generators SHOULD NOT produce new manifests using deprecated algorithms.

### 5.4 Test Vector Requirements (Normative)

Conforming implementations MUST pass all test vectors at:
`https://aioschema.org/test-vectors/v0.5.1/`

**New vectors in v0.5** (all v0.4 vectors remain required):

| ID | Description |
|---|---|
| TV-13 | Multi-hash manifest (SHA-256 + SHA-384) — verification succeeds with either algorithm. |
| TV-14 | `manifest_signature` present and valid — verification succeeds, `manifest_signature_verified=True`. |
| TV-15 | `manifest_signature` present, extensions tampered — verification fails. |
| TV-16 | SHA-384 single-hash manifest — verified correctly. |
| TV-17 | Anchor-verified flow — correct anchor record → `anchor_verified=True`. |
| TV-18 | Anchor present but `verify_anchor=False` — passes with warning. |

### 5.5 `hash_original` — Multi-Hash Procedure (Normative)

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
6. If **no** supported algorithm was found in the array: return failure — cannot verify.

### 5.6 `core_fingerprint` Canonicalization (Normative)

Unchanged from v0.4. Compute over exactly these fields (alphabetical order via `sort_keys=True`):

```
CORE_HASH_FIELDS = [
    "asset_id", "schema_version", "creation_timestamp",
    "hash_original", "creator_id"
]
```

**Bootstrap rule:** `core_fingerprint` MUST NOT be included in its own computation.

**Reference implementation (Python):**

```python
canonical = json.dumps(
    {k: core_block[k] for k in CORE_HASH_FIELDS},
    sort_keys=True, separators=(',', ':')
).encode('utf-8')

core_fingerprint = "sha256-" + hashlib.sha256(canonical).hexdigest()
```

### 5.7 `creator_id` Modes (Normative)

Unchanged from v0.4.

| Mode | Format | Description |
|---|---|---|
| Anonymous | UUID v7 (SHOULD) or UUID v4 (MAY) | No identity disclosed. |
| Attributed | `ed25519-fp-<32hex>` | SHA-256 fingerprint of Ed25519 public key (first 128 bits). |

Verifiers infer mode from the value: `ed25519-fp-` prefix → attributed; valid UUID → anonymous.

### 5.8 `manifest_signature` — Canonical Manifest Bytes (Normative)

`manifest_signature` is an Ed25519 signature over the **canonical manifest bytes**, defined
as the UTF-8 encoding of the compact JSON serialization of the entire manifest with:

1. The `manifest_signature` field set to `null` (bootstrap exclusion — prevents circular dependency).
2. Keys sorted alphabetically at all levels (`sort_keys=True`).
3. No whitespace between tokens (`separators=(',', ':')`).

**Reference implementation (Python):**

```python
def canonical_manifest_bytes(manifest: dict) -> bytes:
    # Work on a copy with manifest_signature zeroed out
    m = copy.deepcopy(manifest)
    m["core"]["manifest_signature"] = null  # bootstrap exclusion
    return json.dumps(m, sort_keys=True, separators=(',', ':')).encode('utf-8')
```

`manifest_signature` signs the core block **and** extensions together. This provides
integrity protection for sidecar files where extensions carry material metadata (e.g.
`soft_binding`, `ai_model_used`).

---

## 6. Extension Block (Optional)

Extensions MAY include EXIF/XMP-derived fields, AI-generation metadata, licensing,
platform-specific metadata, and user-defined fields.

Extensions MUST NOT affect the `core_fingerprint` computation.

### 6.1 Extension Namespacing

Official extensions: `https://aioschema.org/extensions/`
Vendor/experimental: MUST use prefix `x-<vendor>-<field>`.

### 6.2 Soft Binding Extension Field

```json
"soft_binding": {
  "algorithm": "pHash-v1",
  "fingerprint": "<16-char hex>",
  "threshold_info": 5
}
```

`threshold_info` is documentation only. Verifiers MUST use the `soft_binding_threshold`
parameter (default 5) and MUST NOT read the threshold from the manifest.

---

## 7. Interoperability and Mapping

### 7.1 C2PA Interoperability (Normative)

AIOSchema defines a C2PA custom assertion format for embedding AIOSchema provenance
data inside C2PA manifests.

| Property | Value |
|---|---|
| Assertion label | `aioschema.core/v1` |
| Assertion data | Complete Core Block JSON, serialized as canonical compact UTF-8 JSON (sort_keys=True, no whitespace) per §5.6 |

A conforming AIOSchema implementer MAY embed a manifest's Core Block inside a C2PA
manifest using this assertion format.

A conforming AIOSchema verifier MAY extract and verify an AIOSchema Core Block found
in a C2PA manifest assertion with this label.

AIOSchema does not mandate C2PA adoption. C2PA compatibility is an optional
interoperability layer. AIOSchema manifests are fully valid and verifiable without
any C2PA dependency.

If C2PA modifies its assertion handling in ways that affect this embedding, the C2PA
implementation bears responsibility for maintaining conformance with this defined
format. AIOSchema will document known C2PA version compatibility notes at
`https://aioschema.org/compat/c2pa`.

**Note:** The assertion label `aioschema.core/v1` uses dot notation per C2PA custom
assertion naming conventions, not AIOSchema snake_case field naming. The `/v1` suffix
denotes the major structural version of this assertion format. It advances only when
AIOSchema introduces breaking structural changes at a major version increment.

### 7.2 EXIF/XMP Mapping (Normative)

See Appendix D for the complete mapping table.

### 7.3 schema.org Mapping

| AIOSchema Field | schema.org Property |
|---|---|
| `creator_id` | `schema:creator` |
| `creation_timestamp` | `schema:dateCreated` |
| `extensions.license` | `schema:license` |
| `extensions.ai_model_used` | `schema:isBasedOn` |

### 7.4 W3C PROV Mapping (Normative)

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

For JPEG, PNG, PDF, MP4: embed Core Block in XMP under namespace
`https://aioschema.org/xmp/v0.5.1/` using key `aioschema:manifest`.

### 8.2 Sidecar JSON (Level 1 MUST)

**Naming convention:** `<original-filename><original-extension>.aios.json`

Examples: `photo.jpg` → `photo.jpg.aios.json`, `video.mp4` → `video.mp4.aios.json`

The sidecar MUST contain the complete manifest (core + extensions) as UTF-8 JSON.

When `manifest_signature` is present the sidecar is self-verifying — its contents can be
authenticated without access to the original asset file.

### 8.3 Soft Binding — pHash (Level 2 MUST for images/video)

Algorithm unchanged from v0.4 (§8.3). The verifier-side policy threshold is now
configurable via `soft_binding_threshold` parameter (default: 5, maximum: 10).

### 8.4 Hybrid Mode (Level 2 SHOULD)

Combine XMP + sidecar + optional anchoring.

### 8.5 Post-Platform Recovery Procedure (Normative)

1. Locate sidecar at `<asset-filename>.aios.json`.
2. If `manifest_signature` present: verify sidecar integrity before proceeding.
3. Attempt `hash_original` hard match.
4. If hard fail: attempt pHash soft match using verifier-policy threshold.
5. If soft match: flag as `match_type="soft"` with warning.
6. If both fail: return FAIL.
7. Proceed to `core_fingerprint` and signature verification.

---

## 9. Anchoring (Optional)

### 9.1 Anchor URI Scheme (Normative)

```
aios-anchor:<service-id>:<anchor-id>
```

### 9.2 `anchor_resolver` Contract (Normative)

Anchor verification requires an `anchor_resolver` — a callable or function in the
implementing language — with the following language-neutral contract:

**Input:** `anchor_ref` — the `aios-anchor:` URI string from the manifest.

**Output:** An anchor record object containing at minimum:

| Field | Type | Description |
|---|---|---|
| `asset_id` | String | Asset identifier — must match manifest `asset_id` |
| `core_fingerprint` | String | Core fingerprint — must match manifest `core_fingerprint` |
| `timestamp` | String | ISO 8601 UTC timestamp of when the anchor was created |

**Failure cases:**
- If the anchor record cannot be retrieved: return null/None/undefined
- If the anchor service returns an error: raise or throw `AnchorVerificationError`

**Verification succeeds** if the returned `asset_id` and `core_fingerprint` both match
the manifest values using timing-safe comparison.

**Reference implementations** provide typed `anchor_resolver` interfaces in Python and
TypeScript at `https://aioschema.org/implementations/`.

### 9.3 Anchor Service Discovery

Services publish a discovery document at:
`https://<service-domain>/.well-known/aioschema-anchor.json`

### 9.4 What to Anchor

Anchors MUST store: `asset_id`, `core_fingerprint`, `timestamp`. MAY store `signature`.

---

## 10. Verification Process (Normative)

A conforming verifier MUST execute the following steps in order:

1. **Extract** metadata from XMP or sidecar (`.aios.json`).
2. **Validate** all required core fields present (§5.1).
3. **Validate** `schema_version` is supported; reject with clear error if unknown.
4. **Validate** `hash_original` format (single string or each array element) per §5.3 regex.
5. **Validate** `core_fingerprint` format per §5.3 regex.
6. **Validate** `creation_timestamp` is UTC ISO 8601 with trailing `"Z"`.
7. **Recompute** `hash_original`: for each algorithm in the manifest, recompute and compare
   (timing-safe). Hard match succeeds if any supported algorithm matches. See §5.5.
8. **If no hard match:** attempt soft binding per §8.5.
9. **If both fail:** return FAIL — asset tampered or replaced.
10. **Recompute** `core_fingerprint` per §5.6 canonicalization; compare timing-safe. FAIL if mismatch.
11. **If `signature` non-null:** validate format; require `public_key`; verify Ed25519
    over canonical core bytes. FAIL if invalid.
12. **If `manifest_signature` non-null:** validate format; require `public_key`; verify
    Ed25519 over canonical manifest bytes per §5.8. FAIL if invalid.
13. **If `anchor_reference` non-null:**
    - If `verify_anchor=True`: call `anchor_resolver`; compare `asset_id` and
      `core_fingerprint` (timing-safe); set `anchor_verified=True` on match.
    - If `verify_anchor=False` or no fetcher: emit warning; `anchor_verified=False`.
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
| `compliance_level` | Integer | Self-declared level (1, 2, or 3). Informational. |

---

## 12. Security, Privacy and Abuse Resistance (Normative)

### 12.1 Normative Requirements

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

### 12.2 Known Risks

Mitigate: anchor spoofing, side-channel inference from extensions, forced/automated signing,
malicious metadata injection. Reference: C2PA Harms Modeling Framework.

---

## 13. Regulatory Alignment (Normative)

The regulatory compliance matrix from v0.4 §13.1 remains unchanged.
The Regulatory Readiness Profile MUST be published by June 30, 2026 (§13.2).
The list of what AIOSchema does not cover (§13.3) remains unchanged.

`manifest_signature` and multi-hash support strengthen the "machine-readable marking"
argument under EU AI Act Art. 50, but do not change the partial-compliance status.

---

## 14. Governance Model

### 14.1 Current Phase — Founder-Controlled

AIOSchema is currently in its **founder-controlled pre-governance phase**. The specification
is authored and maintained by its founder with full editorial control. This is a deliberate
choice, not an oversight.

The rationale is straightforward: a standard handed to a governance body before it is
complete risks being shaped by committee dynamics rather than technical merit. AIOSchema
will arrive at governance as a finished, tested, proven standard — not as a work-in-progress
requiring committee completion.

This phase continues until v1.0 is stable and adopted. There is no external deadline on
this transition. It happens when the standard is ready.

### 14.2 Founder Commitments (Binding)

During the founder-controlled phase, the following commitments are binding and publicly
recorded via the founding anchor (§18):

- **Open specification.** The full specification is and will remain publicly readable,
  freely implementable, and CC-BY 4.0 licensed. Any developer can read it in under an
  hour and implement it in a day. This will never change.

- **Royalty-Free IPR.** All normative specification text and reference implementations
  are covered by a Royalty-Free (RF) patent commitment. Implementers will never be
  charged royalties for implementing this standard. This commitment is irrevocable.

- **Open participation.** Any individual or organization may contribute to public review,
  submit issues, and propose changes via the public process at aioschema.org.

- **Transparent change history.** All normative changes are logged in the changelog and
  anchored as described in §18. The version history is cryptographically verifiable.

- **Backward compatibility.** The stability policy in §15 is binding. No breaking changes
  without a major version increment.

- **Permanent founder attribution.** The founder's authorship is recorded in the founding
  anchor and all subsequent anchors. This attribution is irrevocable regardless of
  governance transition.

### 14.3 Governance Transition — Post v1.0

When v1.0 is stable and has demonstrated real-world adoption, AIOSchema will transition
to neutral multi-stakeholder governance. The founder will:

- Select a host organization (candidate: Linux Foundation, W3C, or equivalent neutral body)
- Transfer editorial control of the normative specification
- Establish a working group with open membership and transparent voting
- Ensure the RF IPR policy is formally adopted by the receiving body
- Retain permanent founder status and ongoing participation rights

The transition timeline is driven by readiness, not by an arbitrary date. A standard
that transitions too early — before it is complete and credible — is more likely to be
diluted or abandoned than one that arrives at governance already proven.

### 14.4 What Governance Does Not Change

Regardless of when the governance transition occurs, the following are permanent and
non-negotiable:

- The specification remains CC-BY 4.0 and freely implementable
- The RF IPR commitment is irrevocable
- The founding anchor record is immutable
- The founder's authorship attribution is permanent
- The lightweight architecture principle (§3) governs all future versions

---

## 15. Backward Compatibility and Stability Policy (Normative)

v0.5 is fully backward compatible with v0.1–v0.4.

Verifiers MUST accept `schema_version` values `"0.1"` through `"0.5.5"` and process them
with the semantics appropriate to the declared version.

`hash_original` as a string (v0.4 and earlier) MUST be accepted by v0.5.x verifiers.

`core_fingerprint` is the v0.5.5 rename of `hash_schema_block`. Verifiers MUST accept both
field names and treat them as equivalent. `hash_schema_block` is deprecated as of v0.5.5
and will be removed in v0.6.

The stability policy (MAJOR/MINOR/PATCH) from v0.4 §15.2 remains unchanged.

---

## 16. Call for Implementation and Feedback

Timeline:

| Milestone | Target Date | Notes |
|---|---|---|
| v0.5.1 founding anchor created | Feb 2026 | Authored date — immutable anchor establishes prior art |
| v0.5.1 published on aioschema.org | TBD | Publication date — set when ready to release |
| v0.5.1 feedback period | TBD | Open-ended — feedback welcome at aioschema.org |
| v0.6 release candidate (scoped DID, test vectors) | TBD | After public review closes |
| Regulatory Readiness Profile published | Before Aug 2, 2026 | Hard external deadline (EU AI Act / SB 942) |
| Governance host selected | Q3 2026 | Pre-condition for v1.0 |
| v1.0 authored + founding anchor | TBD | When technically complete |
| v1.0 published + governance transition | Q4 2026 | Target — depends on governance readiness |

---

## 17. Example Manifest

**Level 2 — multi-hash, signed, with soft binding:**

```json
{
  "core": {
    "asset_id": "019c7cb0-6e40-7f21-873b-9a9cf13e461b",
    "schema_version": "0.5.5",
    "creation_timestamp": "2026-03-01T12:00:00Z",
    "hash_original": [
      "sha256-abc123def456abc123def456abc123def456abc123def456abc123def456abc1",
      "sha384-def456abc123def456abc123def456abc123def456abc123def456abc123def456abc123def456abc123def456abc12"
    ],
    "core_fingerprint": "sha256-def456abc123def456abc123def456abc123def456abc123def456abc123def4",
    "creator_id": "ed25519-fp-7fcc5530c17565c99ea02d846ab0b5eb",
    "signature": "ed25519-<128-hex-chars>",
    "manifest_signature": "ed25519-<128-hex-chars>",
    "anchor_reference": "aios-anchor:my-timestamp-service:abc123def456"
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
    }
  }
}
```

---

## 18. Founding Provenance (Normative for Specification Versions)

### 18.1 Purpose

AIOSchema is a standard about content provenance and trust. It is appropriate — and
intentional — that AIOSchema uses its own mechanisms to establish the provenance of the
standard itself. This section defines how.

### 18.2 The Founding Anchor

Before first publication of any version of this specification, the author MUST generate
an AIOSchema manifest of the specification bundle and anchor it using the procedure in
§18.4. The resulting anchor reference is the **founding anchor** — an immutable,
independently verifiable record of:

- What the specification contained at that moment
- Who created it (via `creator_id`)
- When it was created (via the anchor timestamp, independent of any clock the author controls)
- That it existed before any copies or derivatives

The founding anchor for AIOSchema v0.5.1 is recorded in the specification manifest at
`https://aioschema.org/provenance/v0.5.1/manifest.json`.

### 18.3 Version Chaining

Each subsequent version of the specification MUST include the anchor reference of its
immediate predecessor in the `previous_version_anchor` field of the specification manifest.
This creates a **cryptographic chain of custody**:

```
v0.5.1 manifest  →  previous_version_anchor: null  (genesis)
v0.6   manifest  →  previous_version_anchor: aios-anchor:<v0.5.1-anchor-id>
v1.0   manifest  →  previous_version_anchor: aios-anchor:<v0.6-anchor-id>
```

Because each anchor timestamp is independently verifiable and immutable, it is impossible
to insert a fake predecessor into the chain after the fact. Anyone can verify the complete
lineage of the standard from its genesis to the current version.

### 18.4 Specification Anchoring Procedure (Normative)

To anchor a specification version:

1. Assemble the **specification bundle** — a directory containing:
   - The specification document (`AIOSchema_vX.Y.Z_Specification.md`)
   - The reference implementation (`aioschema_vXY.py` or equivalent)
   - The test suite (`test_aioschema_vXY.py` or equivalent)

2. Generate an AIOSchema manifest of the bundle:
   - `hash_original`: multi-hash array over the concatenated canonical content of all
     bundle files (sorted by filename, concatenated in order)
   - `creator_id`: the founder's attributed creator ID (`ed25519-fp-<32hex>`)
   - `previous_version_anchor`: the anchor reference of the previous version, or null
     for the genesis version
   - `manifest_signature`: signed with the founder's private key

3. Submit the manifest's `core_fingerprint` to a public anchoring service.

4. Record the returned anchor reference in the specification manifest's `anchor_reference`
   field and publish at `https://aioschema.org/provenance/vX.Y.Z/manifest.json`.

### 18.5 Anchor Service Requirements

The anchoring service used for specification provenance MUST:

- Be publicly verifiable by any third party without authentication
- Produce timestamps that are independent of any clock or system controlled by the author
- Store records immutably (records cannot be deleted or modified after submission)

**Conforming anchor service categories:**

| Category | Standard / Mechanism | Notes |
|---|---|---|
| Trusted Timestamp Authority | RFC 3161 (IETF standard) | Legally recognized under EU eIDAS. Recommended for specification anchoring. |
| Blockchain-based timestamping | Any public, immutable distributed ledger | Service must provide public verification without authentication. |
| Hybrid services | RFC 3161 + blockchain | Provides redundancy across verification methods. |

The spec makes no recommendation for any specific vendor or service. Implementers choose
the service appropriate for their jurisdiction, reliability requirements, and tooling.
The anchor URI scheme (`aios-anchor:<service-id>:<anchor-id>`) accommodates any conforming
service via the `<service-id>` token.

### 18.6 What the Founding Anchor Proves

The founding anchor proves:

- **Existence:** The specification existed in this exact form before the anchor timestamp
- **Integrity:** Any modification to any file in the bundle would invalidate the hash
- **Authorship:** The creator_id and signature link the bundle to the founder's key
- **Sequence:** The version chain proves the order in which versions were created

It does not prove:
- That the content is correct or valuable (that is for implementers to judge)
- Legal ownership under any jurisdiction (that is a separate matter)
- That no prior work exists (it establishes precedence only from the anchor date forward)

### 18.7 Self-Verification Example

The following command verifies the AIOSchema v0.5.1 specification bundle against its
founding anchor using the reference implementation:

```bash
python3 aioschema_anchor.py verify \
  --bundle ./aioschema-v0.5.1-bundle/ \
  --manifest https://aioschema.org/provenance/v0.5.1/manifest.json
```

---


## 19. Mechanism Registries (Normative)

AIOSchema uses registries to manage pluggable mechanisms — hash algorithms, signature
algorithms, soft binding algorithms, and anchor services. Registries are the formal
mechanism by which the standard evolves without breaking compatibility.

### 19.1 Hash Algorithm Registry

| Token | Digest Length | Status | Since |
|---|---|---|---|
| `sha256` | 64 hex chars | REQUIRED | v0.1 |
| `sha3-256` | 64 hex chars | OPTIONAL | v0.4 |
| `sha384` | 96 hex chars | OPTIONAL | v0.5 |

### 19.2 Signature Algorithm Registry

| Token | Key Format | Status | Since |
|---|---|---|---|
| `ed25519` | 32-byte public key | REQUIRED | v0.1 |

### 19.3 Soft Binding Algorithm Registry

| Token | Fingerprint Format | Status | Since |
|---|---|---|---|
| `pHash-v1` | 16 hex chars | REQUIRED | v0.3 |

### 19.4 Anchor Service Registry

The anchor service registry is a living document published at
`https://aioschema.org/registries/anchor-services/`.

A conforming anchor service MUST satisfy the requirements in §9. Any service satisfying
those requirements MAY be used regardless of registry status. The registry provides
a curated list of known-conforming services for implementer convenience — it is not
a gatekeeping mechanism.

### 19.5 Registry Governance

During the founder-controlled phase (§14.1), the founder maintains all registries.
New entries are accepted via the public process at `https://aioschema.org/registry/propose`.

Upon governance transition (§14.3), registry maintenance transfers to the working group.
The RF IPR commitment (§14.2) applies to all registered mechanisms.

## Appendix A — JSON Schema (Normative)

Published at `https://aioschema.org/schemas/v0.5.1/manifest.json`.

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://aioschema.org/schemas/v0.5.1/manifest.json",
  "title": "AIOSchema Manifest v0.5.1",
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
          "enum": ["0.1","0.2","0.3","0.3.1","0.4","0.5","0.5.1","0.5.5"]
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
          "pattern": "^ed25519-[0-9a-f]{128}$"
        },
        "manifest_signature": {
          "type": ["string", "null"],
          "pattern": "^ed25519-[0-9a-f]{128}$"
        },
        "anchor_reference": {
          "type": ["string", "null"],
          "pattern": "^aios-anchor:[a-z0-9_-]+:[a-zA-Z0-9_-]+$"
        },
        "previous_version_anchor": {
          "type": ["string", "null"],
          "pattern": "^aios-anchor:[a-z0-9_-]+:[a-zA-Z0-9_-]+$",
          "description": "Anchor URI of the immediately preceding version. Creates a cryptographic version chain. See §18."
        }
      },
      "additionalProperties": false
    },
    "extensions": {
      "type": "object",
      "additionalProperties": true
    }
  }
}
```

---

## Appendix B — Version History

> **Date columns:** *Authored* is when the version was created and anchored (immutable).
> *Published* is when it became publicly available on aioschema.org.
> These are distinct by design — see §18 and the header note above.

| Version | Authored | Published | Summary |
|---|---|---|---|
| v0.1 | Jan 2026 | TBD | Initial draft; minimal core; basic extensions |
| v0.2 | Feb 2026 | TBD | Interoperability, durability, governance, regulatory alignment |
| v0.3 | Feb 2026 | TBD | RFC 2119 language, backward compat, security, C2PA note |
| v0.3.1 | Feb 2026 | TBD | Conformance levels, JSON Schema, timeline, editorial refinements |
| v0.4 | Feb 2026 | TBD | All 22 public-review issues; normative conformance, durability, governance, regulatory mapping |
| v0.5 | Feb 2026 | TBD | Multi-hash, detached manifest signature, SHA-384, configurable soft-binding threshold, Level 3, anchor_resolver contract |
| v0.5.1 | Feb 2026 | TBD | `previous_version_anchor` field; §14 governance rewritten as founder-controlled pre-governance phase with binding RF IPR commitment; §18 Founding Provenance added |
| **v0.5.5** | Feb 2026 | TBD | `core_fingerprint` rename; `anchor_resolver` rename; C2PA label stabilised to `aioschema.core/v1`; §0 Design Philosophy; §9 language-neutral anchor contract; §5.3 algorithm registration contract; §19 Mechanism Registries; TypeScript implementation |

---

## Appendix C — Ecosystem Context (Non-Normative)

C2PA 2.3 (Dec 2025) remains the dominant provenance standard. AIOSchema v0.5 serves as a
lightweight entry point. EU AI Act Art. 50 and California SB 942/AB 853 take effect Aug 2, 2026.

---

## Appendix D — EXIF/XMP Mapping Table (Normative)

Custom XMP namespace: `https://aioschema.org/xmp/v0.5.1/` with prefix `aioschema`.

| AIOSchema Field | EXIF Tag | XMP Property | Notes |
|---|---|---|---|
| `creation_timestamp` | DateTimeOriginal (0x9003) | `xmp:CreateDate` | UTC |
| `camera_model` | Make + Model (0x010F, 0x0110) | `xmp:CreatorTool` | Concatenate |
| `exposure_time` | ExposureTime (0x829A) | `exif:ExposureTime` | Rational |
| `iso` | ISOSpeedRatings (0x8827) | `exif:ISOSpeedRatings` | Integer |
| `software` | Software (0x0131) | `xmp:CreatorTool` | String |
| `license` | — | `xmpRights:UsageTerms` | SPDX |
| `ai_model_used` | — | `aioschema:aiModelUsed` | Custom |
| `asset_id` (core) | — | `aioschema:assetId` | Custom |
| `schema_version` (core) | — | `aioschema:schemaVersion` | Custom |
| `manifest_signature` (core) | — | `aioschema:manifestSignature` | Custom |
| `soft_binding.fingerprint` | — | `aioschema:pHashFingerprint` | Custom |

---

## Appendix E — Platform Survivability (Informative, Living Document)

| Platform | XMP Preserved | Sidecar Supported | EXIF Preserved | Notes |
|---|---|---|---|---|
| Instagram | No | No | Stripped | Sidecar + manifest_signature recommended |
| X (Twitter) | No | No | Stripped | Sidecar + manifest_signature recommended |
| TikTok | No | No | Stripped | Sidecar + manifest_signature recommended |
| YouTube | Partial | No | Partial | Some XMP survives via description metadata |
| WhatsApp | No | No | Stripped | Sidecar + manifest_signature recommended |
| LinkedIn | Partial | No | Partial | Creator mode preserves some fields |
| Dropbox | Yes | Yes | Yes | Recommended for archival |
| Google Drive | Yes | Yes | Yes | Recommended for archival |

---

## Appendix F — Self-Certification Checklist (Normative)

**Level 1**
- [ ] All required Core Block fields present
- [ ] `hash_original` computed with supported algorithm, correct format
- [ ] `core_fingerprint` computed via canonicalization (§5.6)
- [ ] `creation_timestamp` UTC with trailing "Z"
- [ ] Sidecar written as `<filename>.<ext>.aios.json`
- [ ] Core Block preserved unchanged during export
- [ ] All v0.5 test vectors (TV-01 through TV-18) pass

**Level 2** — Level 1 plus:
- [ ] `signature` present when signing key available
- [ ] `manifest_signature` present when sidecar integrity required
- [ ] pHash soft binding for image/video assets
- [ ] Hybrid XMP + sidecar embedding
- [ ] Extension fields mapped to EXIF/XMP per Appendix D
- [ ] Verifier uses policy threshold, not `threshold_info` from manifest

**Level 3** — Level 2 plus:
- [ ] `anchor_reference` present
- [ ] Anchor verification performed via conforming `anchor_resolver`
- [ ] `anchor_verified=True` in verification result

**Specification Versions** — additional items for versioned specification documents:
- [ ] Founding anchor created before first publication (§18.4)
- [ ] `previous_version_anchor` present in all versions after genesis
- [ ] Specification bundle manifest published at canonical URL
- [ ] Version chain verifiable end-to-end from genesis
