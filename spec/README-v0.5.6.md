<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- Copyright 2026 Ovidiu Ancuta -->
<!-- AIOSchema v0.5.6 | spec/README-v0.5.6.md | https://aioschema.org -->

# AIOSchema Specification

AIOSchema is an open standard for cryptographic content provenance and digital authenticity, for both digital and physical assets. It defines a minimal, verifiable manifest format that establishes what an asset is, who created it, and when it existed, independently of any platform, storage system, or proprietary tool.

**Version:** 0.5.6
**Author:** Ovidiu Ancuta
**Authority:** https://aioschema.org
**License:** CC-BY 4.0

---

## Document

**`AIOSchema-v0_5_6-Specification.md`** is the normative specification. It covers:

- Core Block structure and field definitions
- Hash algorithm registry and validation rules
- Verification procedure (14-step normative process)
- Anchoring mechanism and anchor resolver contract
- Extension block and soft binding
- Compliance extensions: `compliance_eu_art50` for EU AI Act Article 50 editorial exemption documentation
- Interoperability mappings: C2PA, EXIF/XMP, schema.org, W3C PROV
- Security, privacy, and abuse resistance properties
- Governance model
- Mechanism registries

Designed to be read in under an hour and implemented in a day.

---

## What Changed from v0.5.5

- `compliance_eu_art50` extension added under `extensions`: flat underscore key, two normative fields, `editorial_responsibility` (MUST) and `review_type` (MUST when claiming Article 50(4) exemption).
- All PII fields removed from the standard (GDPR Art. 5(1)(c) data minimisation).
- Verification procedure extended to 14 steps; step 14 adds `public_key_fingerprint_match` to the formal `VerificationResult` struct.
- `x-schemahub` reserved vendor prefix removed from the extension registry.
- Test vector suite extended to TV-25 (TV-01 through TV-25).
- Cross-implementation vector suite extended to CV-18 (CV-01 through CV-18).
- Six reference implementations (.NET added).

---

## Implementations

Six reference implementations are available in `../implementations/`, all cross-verified against a common deterministic test suite:

| Language | Folder | Tests |
|---|---|---|
| Node.js | `implementations/js/` | 43 |
| Python | `implementations/python/` | 115 |
| TypeScript | `implementations/typescript/` | 77 |
| Go | `implementations/go/` | 34 |
| Rust | `implementations/rust/` | 37 |
| .NET | `implementations/dotnet/` | 69 |

---

## Conformance

Test vectors are in `../conformance/`. Any conforming implementation must pass all 25 test vectors (TV-01 through TV-25) and all 18 cross-implementation deterministic vectors (CV-01 through CV-18).

See `../conformance/CONFORMANCE_VECTORS.md` for the full vector registry and per-implementation test function mapping.

---

## Status

This is a stable release. The specification is complete, anchored, and implemented across six languages. Feedback and implementation reports are welcome at https://aioschema.org/contribute.

The founding provenance record for this specification is published at https://aioschema.org/provenance/.

---

## License

- **Specification:** CC-BY 4.0 — https://creativecommons.org/licenses/by/4.0/
- **Reference Implementations:** Apache License 2.0 — https://www.apache.org/licenses/LICENSE-2.0

<!-- end AIOSchema v0.5.6 | spec/README-v0.5.6.md | https://aioschema.org -->
