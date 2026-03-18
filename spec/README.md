# AIOSchema Specification

AIOSchema is an open standard for cryptographic content provenance and digital authenticity — for both digital and physical assets. It defines a minimal, verifiable manifest format that establishes what an asset is, who created it, and when it existed, independently of any platform, storage system, or proprietary tool.

**Version:** 0.5.5 — Technical Review
**Author:** Ovidiu Ancuta
**Authority:** https://aioschema.org
**License:** CC-BY 4.0

---

## Document

**`AIOSchema_v0_5_5_Specification.md`** is the normative specification. It covers:

- Core Block structure and field definitions
- Hash algorithm registry and validation rules
- Verification procedure (10-step normative process)
- Anchoring mechanism and anchor resolver contract
- Extension block and soft binding
- Interoperability mappings — C2PA, EXIF/XMP, schema.org, W3C PROV
- Security, privacy, and abuse resistance properties
- Governance model
- Mechanism registries

Designed to be read in under an hour and implemented in a day.

---

## Implementations

Five reference implementations are available in `../implementations/`, all cross-verified against a common deterministic test suite:

| Language | Folder | Tests |
|---|---|---|
| Python | `implementations/python/` | 108 |
| TypeScript | `implementations/typescript/` | 70 |
| Node.js | `implementations/nodejs/` | 80 |
| Go | `implementations/go/` | 27 |
| Rust | `implementations/rust/` | 30 |

---

## Conformance

Test vectors are in `../conformance/`. Any conforming implementation must pass all 18 test vectors (TV-01 through TV-18) and all 14 cross-implementation deterministic vectors (CV-01 through CV-14).

---

## Status

This is a Technical Review release. The specification is complete and implemented. Feedback and implementation reports are welcome at https://aioschema.org/contribute.

The founding provenance record for this specification is published at https://aioschema.org/provenance/.

---

## License

- **Specification:** CC-BY 4.0 — https://creativecommons.org/licenses/by/4.0/
- **Reference Implementations:** Apache License 2.0 — https://www.apache.org/licenses/LICENSE-2.0
