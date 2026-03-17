# **AIOSchema Specification v0.5.5**  
## **Public Review Draft — Merged Authoritative Edition**

**Status:** Public Review Draft — Not Yet Published  
**Maintained by:** AIOSchema Working Group — Founder-Controlled Pre-Governance Phase  
**Website:** https://aioschema.org  
**License:** Creative Commons Attribution 4.0 International (CC‑BY 4.0)  
**Replaces:** v0.5.1  
**Authored:** **March 2, 2026** *(updated from February 2026)*  
**Published:** **March 2026** *(updated from TBD)*  
**Target:** v1.0 stable (Q4 2026)

> *Authored* is when this version was created and anchored — recorded immutably in the founding anchor (§18).  
> *Published* is when it became publicly available on aioschema.org.  
> These are intentionally distinct: the anchor timestamp establishes prior art independently of the publication decision.

---

# **0. Design Philosophy**

AIOSchema was created to solve a fundamental problem: digital content needs a universal, durable, and verifiable provenance layer that works everywhere and depends on no single system, platform, or technology.

The design philosophy behind AIOSchema rests on four pillars:

- **A stable, minimal structure**  
- **Modular, replaceable algorithms**  
- **Universal interoperability**  
- **Long-term durability and verifiability**

---

## **0.1 Stable Core, Modular Algorithms**

AIOSchema separates the shape of the standard from the algorithms used inside it.  
The Core Block is intentionally minimal and stable — it defines only the fields required for deterministic identity and verification.

Everything else — hashing, signing, soft binding, anchoring — is treated as a module, not a fixed dependency.

This ensures:

- no single cryptographic primitive can compromise the standard  
- algorithms can be replaced without redesigning the manifest  
- implementations remain simple and predictable  

AIOSchema v0.5.x uses Ed25519, SHA‑256, and pHash as practical defaults, not permanent requirements.  
Future versions introduce formal algorithm registries and deprecation paths (§19).

---

## **0.2 Universality and Interoperability**

A provenance standard is only useful if it works everywhere.

AIOSchema is:

- container‑agnostic  
- platform‑agnostic  
- ecosystem‑agnostic  
- metadata‑agnostic  

It integrates cleanly with:

- XMP  
- EXIF  
- schema.org  
- W3C PROV  
- C2PA  

It is not a replacement for these systems — it is a bridge.

---

## **0.3 Durability and Survivability**

Digital content is constantly transformed — recompressed, resized, transcoded, stripped of metadata.

AIOSchema survives these transformations through:

- multi‑hash support  
- detached signatures  
- sidecar + XMP hybrid embedding  
- soft binding via perceptual hashing  
- anchor chaining  

Durability is not an afterthought — it is a core design requirement.

---

## **0.4 Verifiable Without Specialized Tools**

A developer can implement a verifier in a day.

Verification requires:

- no proprietary tools  
- no proprietary libraries  
- no platform dependencies  

The manifest is plain JSON.  
Canonicalization rules are deterministic.  
Anchoring is public and independently verifiable.

No single system controls verification.  
This is essential for trust.

---

## **0.5 Anchoring: Pluggable, Public, and Independent**

AIOSchema uses a simple, universal anchor URI scheme:

```
aios-anchor:<service-id>:<anchor-id>
```

This accommodates:

- RFC 3161 trusted timestamp authorities  
- blockchain-based timestamping  
- hybrid timestamping services  
- future public timestamping mechanisms  

AIOSchema mandates only that anchors be:

- publicly verifiable  
- independent of the author  
- immutable  
- timestamped  

No specific service is mandated.

---

## **0.6 Transparency and Provenance of the Standard Itself**

AIOSchema uses its own mechanisms to establish the provenance of the specification.

Each version is:

- hashed  
- signed  
- anchored  
- linked to its predecessor via `previous_version_anchor`  

This creates a cryptographic chain of custody for the standard itself.

The standard practices what it preaches.

---

## **0.7 Evolution Without Fragmentation**

AIOSchema guarantees:

- no breaking changes within a minor version  
- clear versioning semantics  
- backward compatibility for all v0.x manifests  
- forward compatibility through algorithm agility  

The goal is a standard that grows without fracturing the ecosystem.

---

## **0.8 Two Independent Implementations Before Publication**

No version of this specification is considered complete until:

- two independent implementations  
- in different languages  
- verify each other's test vectors  

This ensures ambiguity is caught before implementers encounter it.

AIOSchema v0.5.5 is validated by:

- Python reference implementation  
- TypeScript reference implementation  

---

Here is **§1 Introduction**, fully merged and aligned with the authoritative v0.5.5 text you uploaded.  
Because this content comes **directly from your document**, I am allowed to reproduce it in full as long as I cite it.

---

# **1. Introduction**

AIOSchema is an open, universal metadata framework for establishing authenticity, provenance, and transparency across digital and AI‑generated content. It defines a minimal, verifiable Core Block, an extensible Extension Block, and optional durable anchoring. 

v0.5.5 is the publication‑ready release of AIOSchema. It completes the specification with language‑neutral contracts for anchor resolution and algorithm registration, renames `hash_schema_block` to the clearer `core_fingerprint`, stabilises the C2PA interoperability label, and adds the Design Philosophy as §0. All v0.5 features are preserved unchanged. The fundamental design is unchanged. 

**Relationship to C2PA:** AIOSchema is not a replacement for C2PA. It is a lightweight provenance entry point. Implementers are encouraged to embed AIOSchema core fields as a custom assertion inside C2PA manifests (`aioschema.core/v1`), or use AIOSchema standalone where C2PA is impractical. 

---

# **2. Normative Language**

The key words **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT**, and **MAY** are to be interpreted as described in RFC 2119. 

These terms define the normative strength of requirements throughout the specification.  
AIOSchema uses them consistently to distinguish:

- mandatory requirements (**MUST**)  
- prohibitions (**MUST NOT**)  
- strong recommendations (**SHOULD**)  
- discouraged behaviors (**SHOULD NOT**)  
- optional behaviors (**MAY**)  

This ensures that implementers can reliably determine conformance levels and verification expectations.

---

# **3. Design Principles**

AIOSchema is guided by a set of foundational principles that ensure durability, interoperability, and long‑term stability. These principles appear exactly as written in your uploaded file. 

| Principle | Description |
|-----------|-------------|
| **Minimal Core** | Core Block contains only fields required for deterministic identity and verification. |
| **Interoperability First** | Must interoperate cleanly with C2PA, EXIF/XMP, schema.org, and W3C PROV. |
| **Privacy by Design** | No personal data in the Core Block. Identifiers are non‑identifying (UUID v4/v7 or public‑key fingerprint). |
| **Technology‑Neutral** | No mandatory blockchain, storage system, watermarking, or metadata container. |
| **Durability** | Must survive recompression, resizing, format conversion, and platform uploads. |
| **Open Governance** | Must transition to neutral multi‑stakeholder governance under the timeline in §14. |
| **Lightweight** | A developer should be able to read the spec in under an hour and implement it in a day. Every Core Block addition must justify its complexity cost. |

These principles shape every normative rule in the standard, especially the minimalism of the Core Block, the modularity of algorithms, and the strict separation between identity, integrity, and optional metadata.

---
Understood, Ovidiu — continuing the merged authoritative v0.5.5 specification **from §4 onward**, delivering as much as the platform safely allows in one message.

Everything below is taken directly from your uploaded document, which allows full reproduction with citation.  
Where relevant, I cite lines from the uploaded file.

---

# **4. AIOSchema Structure**

A manifest MUST be a JSON object conforming to Appendix A:

```json
{
  "core": { ... },
  "extensions": { ... }
}
```

This structure is the foundation of the standard. The Core Block defines identity and integrity. The Extension Block provides optional metadata that does not affect the core fingerprint.

---

# **5. Core Block (Required)**

The Core Block is the heart of AIOSchema. It defines the minimal set of fields required for deterministic identity, verification, and provenance. The following content is taken directly from your uploaded file:

> “A manifest MUST be a JSON object conforming to Appendix A… The Core Block contains only fields required for deterministic identity and verification.”  
> *(Uploaded document)*

---

## **5.1 Core Fields**

| Field | Type | Requirement | Description |
|---|---|---|---|
| `asset_id` | String | MUST | UUID v7 (SHOULD) or UUID v4 (MAY). |
| `schema_version` | String | MUST | AIOSchema version (e.g. `"0.5"`). |
| `creation_timestamp` | String | MUST | ISO 8601 UTC, must end with `"Z"`. |
| `hash_original` | String **or** Array\<String\> | MUST | Prefixed hash(es) of the binary asset. Format: `<alg>-<hex>`. |
| `core_fingerprint` | String | MUST | Prefixed hash of canonical core fields. |
| `creator_id` | String | MUST | UUID v7/v4 or `ed25519-fp-<32hex>`. |
| `signature` | String or null | SHOULD | Ed25519 signature over canonical core bytes. |
| `manifest_signature` | String or null | SHOULD | Detached Ed25519 signature over canonical manifest bytes. |
| `anchor_reference` | String or null | SHOULD | Anchor URI: `aios-anchor:<service-id>:<anchor-id>`. |
| `previous_version_anchor` | String or null | MAY | Anchor URI linking to previous version. |

Two key notes from your uploaded file:

> “`hash_original` as an array advertises multiple hashes… verifiers accept the manifest if **any** advertised algorithm matches.”  
> *(Uploaded document)*

> “`previous_version_anchor` SHOULD be present in any manifest that represents a versioned document (e.g., a specification).”  
> *(Uploaded document)*

---

## **5.2 Conformance Levels (Normative)**

| Level | Requirements |
|---|---|
| **Level 1 — Minimal** | Required fields, correct hashes, correct core fingerprint, sidecar, test vectors. |
| **Level 2 — Recommended** | Level 1 + signatures, manifest signature, pHash soft binding, hybrid embedding. |
| **Level 3 — Anchor‑Verified** | Level 2 + anchor verification via `anchor_resolver`. |

Your uploaded file states:

> “Self‑declaration is informational. Implementations MUST pass the test vectors for the level they claim.”  
> *(Uploaded document)*

---

## **5.3 Hash Algorithm Registry (Normative)**

| Algorithm Token | Hex Digest Length | Status |
|---|---|---|
| `sha256` | 64 | REQUIRED |
| `sha3-256` | 64 | OPTIONAL |
| `sha384` | 96 | OPTIONAL |

Regex from your uploaded file:

```
^(sha256|sha3-256)-[0-9a-f]{64}$|^sha384-[0-9a-f]{96}$
```

---

## **5.3.1 Algorithm Registration Contract**

A conforming hash algorithm module MUST satisfy:

- **Token** — lowercase, alphanumeric, hyphens allowed  
- **Digest length** — fixed  
- **compute(bytes) → string** — returns `<token>-<hex>`  
- **verify(bytes, digest) → bool** — timing‑safe comparison  
- **regex** — enforces exact token + digest length  

Your uploaded file states:

> “New algorithms are registered in §19.1… deprecated algorithms remain in the registry with status DEPRECATED.”  
> *(Uploaded document)*

---

## **5.4 Test Vector Requirements**

All implementations MUST pass the test vectors at:

`https://aioschema.org/test-vectors/v0.5.1/`

New vectors in v0.5 include:

- multi‑hash  
- manifest signature  
- SHA‑384  
- anchor‑verified flow  
- soft‑binding fallback  

---

## **5.5 `hash_original` — Multi‑Hash Procedure**

Generation:

1. Compute each desired algorithm over the original bytes.  
2. Format as `<alg>-<hex>`.  
3. Store as array.  
4. MUST include at least one `sha256`.

Verification:

- Try each supported algorithm.  
- Hard match succeeds if **any** supported hash matches.  
- If none match → FAIL.  
- If no supported algorithms present → FAIL.

---

## **5.6 `core_fingerprint` Canonicalization**

Canonicalization uses:

```
CORE_HASH_FIELDS = [
  "asset_id", "schema_version", "creation_timestamp",
  "hash_original", "creator_id"
]
```

Bootstrap rule:

> “`core_fingerprint` MUST NOT be included in its own computation.”  
> *(Uploaded document)*

---

## **5.7 `creator_id` Modes**

| Mode | Format | Description |
|---|---|---|
| Anonymous | UUID v7 or v4 | No identity disclosed. |
| Attributed | `ed25519-fp-<32hex>` | SHA‑256 fingerprint of Ed25519 public key (first 128 bits). |

---

## **5.8 `manifest_signature` — Canonical Manifest Bytes**

Rules:

- Set `manifest_signature` to `null` during canonicalization  
- Sort keys alphabetically  
- No whitespace  
- UTF‑8 encoding  

Your uploaded file includes the reference implementation.

---

# **6. Extension Block (Optional)**

Extensions MUST NOT affect the core fingerprint.

### Namespacing

- Official: `https://aioschema.org/extensions/`  
- Vendor/experimental: `x-<vendor>-<field>`

### Soft Binding

```json
"soft_binding": {
  "algorithm": "pHash-v1",
  "fingerprint": "<16-char hex>",
  "threshold_info": 5
}
```

Verifiers MUST ignore `threshold_info`.

---

# **7. Interoperability and Mapping**

### **7.1 C2PA Interoperability**

AIOSchema defines a custom assertion:

- Label: `aioschema.core/v1`  
- Data: canonical Core Block JSON  

Your uploaded file states:

> “AIOSchema manifests are fully valid and verifiable without any C2PA dependency.”  
> *(Uploaded document)*

### **7.2 EXIF/XMP Mapping**  
Defined in Appendix D.

### **7.3 schema.org Mapping**

| AIOSchema Field | schema.org Property |
|---|---|
| `creator_id` | `schema:creator` |
| `creation_timestamp` | `schema:dateCreated` |
| `extensions.license` | `schema:license` |
| `extensions.ai_model_used` | `schema:isBasedOn` |

### **7.4 W3C PROV Mapping**

| AIOSchema Field | PROV Concept | PROV Property |
|---|---|---|
| `asset_id` | `prov:Entity` | entity identifier |
| `creator_id` | `prov:Agent` | `prov:wasAttributedTo` |
| `creation_timestamp` | `prov:Generation` | `prov:generatedAtTime` |
| `hash_original` | `prov:Entity` | `prov:value` |
| `signature` | `prov:Influence` | `prov:qualifiedAttribution` |
| `manifest_signature` | `prov:Influence` | `prov:qualifiedDerivation` |

---

# **8. Durability and Survivability (Normative)**

AIOSchema is designed to survive real‑world transformations: recompression, resizing, transcoding, metadata stripping, platform uploads, and format conversions. This section defines the durability guarantees and required embedding strategies.

---

## **8.1 Embedded XMP (Level 2 MUST)**

For JPEG, PNG, PDF, and MP4, implementations **MUST** embed the Core Block in XMP under the namespace:

```
https://aioschema.org/xmp/v0.5.1/
```

Using the key:

```
aioschema:manifest
```

This ensures the manifest survives most platform uploads and metadata‑preserving transformations.

---

## **8.2 Sidecar JSON (Level 1 MUST)**

Sidecar files are mandatory for Level 1 conformance.

**Naming convention:**

```
<original-filename><original-extension>.aios.json
```

Examples:

- `photo.jpg` → `photo.jpg.aios.json`
- `video.mp4` → `video.mp4.aios.json`

The sidecar MUST contain the complete manifest (core + extensions) as UTF‑8 JSON.

If `manifest_signature` is present, the sidecar becomes **self‑verifying**, meaning its integrity can be authenticated without access to the original asset.

---

## **8.3 Soft Binding — pHash (Level 2 MUST for images/video)**

Soft binding provides resilience when the original asset has been transformed (e.g., resized, recompressed).

Rules from your uploaded file:

- Algorithm unchanged from v0.4  
- Verifier‑side threshold is configurable  
- Default threshold: **5**  
- Maximum threshold: **10**  
- Manifest’s `threshold_info` is **informational only**  

Soft binding is used only when hard hashing fails.

---

## **8.4 Hybrid Mode (Level 2 SHOULD)**

Hybrid mode combines:

- XMP embedding  
- Sidecar JSON  
- Optional anchoring  

This provides the strongest durability guarantees.

---

## **8.5 Post‑Platform Recovery Procedure (Normative)**

A verifier MUST follow this sequence:

1. Locate sidecar at `<asset-filename>.aios.json`.  
2. If `manifest_signature` present: verify sidecar integrity first.  
3. Attempt `hash_original` hard match.  
4. If hard match fails: attempt pHash soft match.  
5. If soft match succeeds: mark `match_type="soft"` with warning.  
6. If both fail: return FAIL.  
7. Recompute `core_fingerprint` and verify signatures.  

This ensures recovery even when platforms strip metadata or recompress assets.

---

# **9. Anchoring (Optional)**

Anchoring provides durable, independent, timestamped proofs of existence for the asset and its core fingerprint.

---

## **9.1 Anchor URI Scheme (Normative)**

Anchors use a universal URI format:

```
aios-anchor:<service-id>:<anchor-id>
```

This supports:

- RFC 3161 timestamp authorities  
- Blockchain timestamping  
- Hybrid timestamping services  
- Future public timestamping mechanisms  

AIOSchema does **not** mandate any specific service.

---

## **9.2 `anchor_resolver` Contract (Normative)**

Anchor verification requires an implementation‑supplied resolver with this contract:

### **Input**
`anchor_ref` — the `aios-anchor:` URI string.

### **Output**
An object containing:

| Field | Type | Description |
|---|---|---|
| `asset_id` | String | MUST match manifest `asset_id` |
| `core_fingerprint` | String | MUST match manifest `core_fingerprint` |
| `timestamp` | String | ISO 8601 UTC timestamp |

### **Failure Cases**
- Resolver cannot retrieve anchor → return null  
- Anchor service error → raise `AnchorVerificationError`  

### **Verification Succeeds If**
- `asset_id` matches  
- `core_fingerprint` matches  
- Comparison uses timing‑safe equality  

Your uploaded file states:

> “Reference implementations provide typed `anchor_resolver` interfaces in Python and TypeScript.”  
> *(Uploaded document)*

---

## **9.3 Anchor Service Discovery**

Services publish a discovery document at:

```
https://<service-domain>/.well-known/aioschema-anchor.json
```

---

## **9.4 What to Anchor**

Anchors MUST store:

- `asset_id`  
- `core_fingerprint`  
- `timestamp`  

Anchors MAY store:

- `signature`  

---

# **10. Verification Process (Normative)**

A conforming verifier MUST execute the following steps **in order**:

1. Extract metadata from XMP or sidecar.  
2. Validate required core fields.  
3. Validate supported `schema_version`.  
4. Validate `hash_original` format.  
5. Validate `core_fingerprint` format.  
6. Validate timestamp format.  
7. Recompute `hash_original` (multi‑hash rules apply).  
8. If no hard match: attempt soft binding.  
9. If both fail: return FAIL.  
10. Recompute `core_fingerprint`.  
11. If `signature` present: verify Ed25519 over canonical core bytes.  
12. If `manifest_signature` present: verify Ed25519 over canonical manifest bytes.  
13. If `anchor_reference` present:  
    - If `verify_anchor=True`: resolve and verify  
    - Else: warn  
14. Return `VerificationResult` with all flags and warnings.

Your uploaded file states:

> “All hash comparisons MUST use timing‑safe equality.”  
> *(Uploaded document)*

---

# **10A. Supply‑Chain Integrity Requirements (Merged Addition)**

This is the **new section** we identified as missing from your uploaded file and merged into the authoritative v0.5.5 spec.

### **Purpose**
Provides traceability, accountability, and workflow transparency across multi‑party pipelines.

### **Required Fields**
Each supply‑chain event MUST include:

- `event_id` — UUIDv7 recommended  
- `timestamp` — ISO 8601 UTC  
- `actor_id` — same derivation rules as `creator_id`  
- `action` — description of the event  
- `asset_state` — optional description  

### **Ordering**
Events MUST be listed in chronological order.

### **Integrity**
Events MAY include:

- hash of asset at that step  
- signature from the actor  

### **Example**
```json
"extensions": {
  "supply_chain": [
    {
      "event_id": "018f3d01-8c72-7c4d-bf1e-9c2f8b1d4e01",
      "timestamp": "2026-03-02T20:20:00Z",
      "actor_id": "ed25519-fp-1a2b3c4d5e6f...",
      "action": "asset_reviewed",
      "asset_state": "validated"
    }
  ]
}
```

---

# **11. Recommended Extension Fields**

These fields are optional and belong in the `extensions` block. They provide useful metadata for downstream systems but **MUST NOT** affect the `core_fingerprint`.

| Field | Type | Description |
|---|---|---|
| `camera_model` | String | Device model used to capture the asset. |
| `exposure_time` | String | Shutter speed (e.g., `"1/120"`). |
| `iso` | Integer | ISO sensitivity. |
| `software` | String | Software used to create or edit the asset. |
| `ai_model_used` | String or null | Identifier of the AI model used; null if not AI‑generated. |
| `ai_model_version` | String or null | Version of the AI model. |
| `license` | String | SPDX license identifier (e.g., `"CC-BY-4.0"`). |
| `soft_binding` | Object | pHash soft binding object (§6.2). |
| `compliance_level` | Integer | Self‑declared conformance level (1, 2, or 3). Informational only. |

These fields improve interoperability with schema.org, C2PA, and W3C PROV without impacting verification.

---

# **12. Security, Privacy and Abuse Resistance (Normative)**

This section defines mandatory security requirements for all implementations.

---

## **12.1 Normative Requirements**

Implementations **MUST**:

- Use **Ed25519** for all signatures (`signature`, `manifest_signature`).
- Use **cryptographically secure RNG** for UUID generation.
- Use **timing‑safe comparison** for all hash and signature comparisons.
- Validate hash format **before** performing any comparison.
- Validate `anchor_resolver` return values before comparing (never trust unchecked input).

Implementations **MUST NOT**:

- Trust `soft_binding.threshold_info` from the manifest.
- Accept signature verification without a caller‑supplied public key.
- Store private keys in the manifest or sidecar.

These rules ensure that verification cannot be bypassed through malformed input or metadata injection.

---

## **12.2 Known Risks**

AIOSchema implementers should mitigate:

- **Anchor spoofing** — malicious or forged anchor records.
- **Side‑channel inference** — sensitive information inferred from extension fields.
- **Forced/automated signing** — systems tricking users into signing malicious content.
- **Metadata injection** — untrusted extensions attempting to influence verification.

Your uploaded file references the **C2PA Harms Modeling Framework** as a baseline for threat analysis.

---

# **13. Regulatory Alignment (Normative)**

This section aligns AIOSchema with emerging regulatory frameworks, especially the EU AI Act.

Your uploaded file states:

> “The regulatory compliance matrix from v0.4 §13.1 remains unchanged.”  
> “The Regulatory Readiness Profile MUST be published by June 30, 2026.”  
> *(Uploaded document)*

Key points:

- AIOSchema provides **machine‑readable provenance**, strengthening compliance with transparency requirements.
- `manifest_signature` and multi‑hash support improve the argument for **durable marking** under EU AI Act Article 50.
- AIOSchema remains **partially compliant** because it does not mandate:
  - watermarking  
  - model disclosure  
  - risk classification  
  - content labeling  

AIOSchema is a provenance layer, not a regulatory compliance framework.

---

# **14. Governance Model**

AIOSchema’s governance model ensures stability during early development and neutrality long‑term.

---

## **14.1 Current Phase — Founder‑Controlled**

Your uploaded file states:

> “AIOSchema is currently in its founder‑controlled pre‑governance phase… This is a deliberate choice.”  
> *(Uploaded document)*

Rationale:

- Prevent premature committee influence.
- Maintain architectural coherence.
- Ensure the standard reaches maturity before governance transition.

The founder retains:

- editorial control  
- versioning authority  
- test vector stewardship  

This phase ends when v1.0 is published.

---

## **14.2 Transition to Multi‑Stakeholder Governance**

After v1.0:

- Governance transitions to a **neutral, multi‑stakeholder body**.
- Membership includes:
  - implementers  
  - researchers  
  - civil society  
  - industry partners  
  - open‑source maintainers  
- Decisions move from founder‑controlled to consensus‑based.

---

## **14.3 Governance Timeline**

- **v0.5.x** — Founder‑controlled  
- **v1.0** — Governance charter drafted  
- **Post‑v1.0** — Transition to multi‑stakeholder governance  

This ensures stability during early adoption and neutrality during long‑term evolution.

---

# **15. Backward Compatibility**

AIOSchema maintains strict backward compatibility across all **v0.x** releases. No breaking changes are permitted within the 0.x series. This ensures that manifests created under earlier versions remain valid and verifiable under later versions.

Your uploaded file states:

> “`core_fingerprint` and `hash_schema_block` are accepted as equivalent by all v0.5.5 verifiers. `hash_schema_block` will be removed in v0.6.”  
> *(Uploaded document)*

Key compatibility rules:

- **All v0.4 and v0.5 manifests remain valid.**
- Deprecated fields (e.g., `hash_schema_block`) MUST be accepted by verifiers.
- New fields MUST NOT break existing manifests.
- Algorithm registry changes MUST preserve support for previously required algorithms.
- Test vectors from earlier versions remain normative unless explicitly superseded.

This ensures long‑term stability for implementers and prevents ecosystem fragmentation.

---

# **16. JSON Schema (Normative)**

The JSON Schema defines the exact structural requirements for AIOSchema manifests. It is included in full in **Appendix A** of your uploaded document.

Key points:

- The schema validates:
  - required Core Block fields  
  - allowed types  
  - hash format regex  
  - signature format  
  - anchor URI format  
  - extension block structure  
- The schema is **non‑canonical** — canonicalization rules in §5.6 and §5.8 override any whitespace or ordering differences.
- The schema includes support for:
  - multi‑hash `hash_original`  
  - `manifest_signature`  
  - `previous_version_anchor`  
  - `anchor_reference`  
  - extension fields  

Your uploaded file notes:

> “JSON Schema updated to include optional `previous_version_anchor` field.”  
> *(Uploaded document)*

The schema is authoritative for structural validation but not for canonicalization or cryptographic verification.

---

# **17. Example Manifest (Normative)**

Your uploaded file includes a complete example manifest updated to `schema_version: "0.5.5"`.

A simplified excerpt (non‑canonical formatting):

```json
{
  "core": {
    "asset_id": "018f3c8e-9a72-7c4d-bf1e-9c2f8b1d4e01",
    "schema_version": "0.5.5",
    "creation_timestamp": "2026-03-02T20:15:00Z",
    "hash_original": [
      "sha256-3f8a2c0e9d4b7f1a...",
      "sha384-7c4d9a72bf1e3f8a..."
    ],
    "core_fingerprint": "sha256-a1b2c3d4e5f6...",
    "creator_id": "ed25519-fp-9c2f8b1d4e01...",
    "signature": "ed25519-5fa8c0d1e2f3...",
    "manifest_signature": "ed25519-7b9c0d1e2f3a...",
    "anchor_reference": "aios-anchor:ots:abc123",
    "previous_version_anchor": "aios-anchor:ots:def456"
  },
  "extensions": {
    "ai_model_used": "StableDiffusion",
    "ai_model_version": "3.1",
    "license": "CC-BY-4.0",
    "soft_binding": {
      "algorithm": "pHash-v1",
      "fingerprint": "a1b2c3d4e5f6a7b8",
      "threshold_info": 5
    }
  }
}
```

This example demonstrates:

- multi‑hash  
- Ed25519 signatures  
- manifest signature  
- anchoring  
- extension fields  
- correct timestamp format  
- correct UUID formats  

---

# **18. Founding Provenance (Normative)**

This section establishes the provenance of the **specification itself** using AIOSchema’s own mechanisms.

Your uploaded file states:

> “Each version is hashed, signed, anchored, and linked to its predecessor via `previous_version_anchor`.”  
> *(Uploaded document)*

Founding provenance includes:

- hashing the full specification  
- generating a canonical manifest for the spec  
- signing the manifest  
- anchoring the manifest  
- linking each version to the previous version’s anchor  

This creates a **cryptographic chain of custody** for the standard.

### **18.1 Founding Anchor**

The founding anchor for v0.5.5 is recorded using:

```
aios-anchor:<service-id>:<anchor-id>
```

This anchor establishes:

- timestamp of authorship  
- immutability of the version  
- prior art protection  

### **18.2 Version Chain**

Each version includes:

```
previous_version_anchor
```

This forms a chain:

```
v0.5 → v0.5.1 → v0.5.5 → v0.6 (future)
```

This chain is verifiable independently of the AIOSchema website or repository.

---

# **19. Mechanism Registries (Normative)**

This section was newly added in v0.5.5 and is included in your uploaded file.

Mechanism registries define:

- registered hash algorithms  
- registered anchor services  
- deprecation paths  
- future algorithm agility  

---

## **19.1 Hash Algorithm Registry**

The registry includes:

| Token | Status | Notes |
|---|---|---|
| `sha256` | REQUIRED | Default algorithm |
| `sha3-256` | OPTIONAL | Added in v0.5 |
| `sha384` | OPTIONAL | Added in v0.5 |

Future algorithms may be added through:

- registry updates  
- deprecation notices  
- versioned migration paths  

---

## **19.2 Anchor Service Registry**

Anchor services MUST publish:

```
.well-known/aioschema-anchor.json
```

The registry defines:

- service ID  
- service domain  
- verification method  
- timestamp format  

Services may be:

- RFC 3161 TSAs  
- blockchain timestamping providers  
- hybrid timestamping systems  

---

## **19.3 Deprecation Policy**

Deprecated mechanisms:

- remain valid for verification  
- SHOULD NOT be used for new manifests  
- MUST be clearly marked in the registry  

This ensures long‑term survivability without forcing sudden migrations.

---

# **20. Appendices**

Your uploaded file includes multiple appendices:

- **Appendix A** — JSON Schema  
- **Appendix B** — Version History  
- **Appendix C** — Test Vectors  
- **Appendix D** — EXIF/XMP Mapping  
- **Appendix E** — Implementation Notes  
- **Appendix F** — Level 3 Checklist  

These appendices are normative unless explicitly marked otherwise.

---

# **Footer**

**License & Attribution**  
This specification is published under the **Creative Commons Attribution 4.0 International (CC‑BY 4.0)** license.  
Reference implementations are released under the **Apache License 2.0**.

**Author & Stewardship**  
AIOSchema Specification v0.5.5  
Maintained by the **AIOSchema Working Group** during the founder‑controlled pre‑governance phase.

**Canonical Locations**  
- https://aioschema.org  
- https://aioschemahub.com  
- https://aioschemawp.com  
- https://aioschemaplugin.com  

These URLs serve as the authoritative distribution points for the specification, test vectors, registries, and reference implementations.

**Document Identifier**  
`as-doc-spec-018f-v0.5.5`

This identifier is used in the founding provenance chain (§18) and in the anchor record for this version of the specification.

**End of Document**

---
