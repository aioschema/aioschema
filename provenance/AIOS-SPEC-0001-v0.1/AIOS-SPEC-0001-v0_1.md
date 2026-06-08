---
aioschema:
  skip_generation: true
---

# **AIOSchema Standard Document: Core Specification v0.1**

**Document ID:** AIOS-SPEC-0001-v0.1
**Status:** Archived
**Date:** February 19, 2026
**Author:** Ovidiu Ancuta · Founder-Controlled Pre-Governance Phase
**Authority:** [https://aioschema.org](https://aioschema.org)
**License:** CC-BY 4.0: `https://creativecommons.org/licenses/by/4.0/` [(creativecommons.org in Bing)](https://www.bing.com/search?q="https%3A%2F%2Fcreativecommons.org%2Flicenses%2Fby%2F4.0%2F")
**Replaces:** None
**Superseded by:** AIOS-SPEC-0001-v0.3.1

---

## Abstract

AIOSchema v0.1 is the initial release of the AIOSchema metadata framework. It defines a minimal Core Block for establishing the integrity, authenticity, and provenance of digital assets using cryptographic hashing and optional anchoring. This version is archived; all new implementations **MUST** target v0.5.5.

---

## 1. Introduction

AIOSchema is an extensible metadata framework designed to establish, maintain, and preserve the integrity, authenticity, and provenance of digital and physical assets. It defines a minimal set of verifiable core fields, supports optional extension fields, and enables tamper-evident anchoring through compatible secure mechanisms.

AIOSchema is technology-neutral and designed to operate across:

- Digital images and video files
- Documents
- AI-generated media
- Physical-to-digital scans
- Platform-specific content pipelines

> **Note:** AIOSchema is not intended to replace C2PA. Instead, it provides a simpler, privacy-first entry point for provenance metadata. Implementers are encouraged to embed AIOSchema core fields as custom assertions inside C2PA manifests or use AIOSchema as a fallback when full C2PA integration is impractical.

---

## 2. Normative Language

The key words **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT**, and **MAY** in this document are to be interpreted as described in RFC 2119.

---

## 3. Design Principles

### 3.1 Minimal Core

Only fields essential for authenticity and verification are included in the Core Block. The goal is a structure simple enough for universal adoption.

### 3.2 Extensible by Design

All non-critical metadata belongs in the Extension Block, allowing flexibility without compromising integrity. Interoperability with C2PA, EXIF/XMP, schema.org, and W3C PROV was formalized in v0.3.1.

### 3.3 Privacy-Preserving

Core fields **MUST NOT** contain personal data. Identifiers **MUST** use UUID v4 or public-key fingerprints.

---

## 4. Core Block Definition

The Core Block defines the immutable identity of the asset.

| Field | Type | Requirement | Description |
|---|---|---|---|
| `asset_id` | String | **MUST** | Unique identifier for the asset (UUID v4) |
| `schema_version` | String | **MUST** | Version of the AIOSchema used (e.g. `"0.1"`) |
| `creation_timestamp` | ISO 8601 | **MUST** | UTC timestamp of record creation |
| `hash_original` | String | **MUST** | SHA-256 hash of the original binary asset |
| `hash_schema_block` | String | **MUST** | SHA-256 hash of the core block itself. Note: The canonicalization procedure (which fields are included and their serialization order) was not normatively specified in this version. The normative bootstrap procedure was defined in v0.4. |
| `creator_id` | String | **MUST** | Anonymous or public key identifier (UUID v4 or public-key fingerprint). Note: Two formal modes, anonymous and attributed, were defined in v0.4. |
| `signature` | String or null | **SHOULD** | Included when signing keys are available |
| `anchor_reference` | String or null | **SHOULD** | Included when anchoring is used |

---

## 5. Example Manifest

```json
{
  "core": {
    "asset_id": "ccc3f2df-ed2b-499d-adc5-71104192ed6b",
    "schema_version": "0.1",
    "creation_timestamp": "2026-02-19T04:30:00Z",
    "hash_original": "sha256-abc123...",
    "hash_schema_block": "sha256-def456...",
    "creator_id": "f8a1c0e4-2b3d-4d8c-9e1f-3c2b8a7d5e91",
    "signature": null,
    "anchor_reference": null
  }
}
```

---

## 6. Security Considerations

Implementations **MUST NOT** include personal data in the Core Block. Hash values **MUST** be computed over the original binary asset prior to any transformation.

> **Progression Note:** Full security, privacy, and abuse-resistance requirements, including prohibition of coerced signing, fraudulent anchors, and deceptive provenance claims, were formally specified in v0.3.1.

---

## 7. Version History

| Version | Date | Summary |
|---|---|---|
| v0.1 | Feb 19, 2026 | Initial release: `asset_id`, `hash_original`, `creation_timestamp`, `creator_id`, SHA-256 only |

> **Note:** `hash_schema_block` was introduced in v0.2. Its normative canonicalization procedure was defined in v0.4. It was renamed `core_fingerprint` in v0.5.5.

---

## License & Attribution

**Specification documents:** CC-BY 4.0: `https://creativecommons.org/licenses/by/4.0/` [(creativecommons.org in Bing)](https://www.bing.com/search?q="https%3A%2F%2Fcreativecommons.org%2Flicenses%2Fby%2F4.0%2F")
**Reference implementations:** Apache License 2.0: `https://www.apache.org/licenses/LICENSE-2.0` [(apache.org in Bing)](https://www.bing.com/search?q="https%3A%2F%2Fwww.apache.org%2Flicenses%2FLICENSE-2.0")
**Provenance Studio:** Proprietary Software © 2026 Ovidiu Ancuta. All rights reserved.

**Authority:** [https://aioschema.org](https://aioschema.org)

*End of Document: AIOS-SPEC-0001-v0.1*

---
