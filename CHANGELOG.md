# Changelog

All notable changes to the AIOSchema specification and reference implementations.

---

## v0.5.5 — March 17, 2026

**The stable foundation release.** First and only published version. Five independent
reference implementations with a fully cross-verified conformance test suite.

### Specification

- Renamed `hash_schema_block` to `core_fingerprint` throughout — old name accepted as alias for backward compatibility
- Renamed `anchor_resolver` parameter to `anchorResolver` in implementation APIs
- Added §0 Design Philosophy: Language Neutrality, Universality, Minimalism, Verifiability, Openness
- Added C2PA comparison and positioning (complementary trust models, not competing)
- Added RFC 3161 timestamp authority support in §9 anchoring
- Added `manifest_signature` field — signs the entire manifest including extensions
- Added multi-hash support — `hash_original` may be a string or array of strings
- Formalized 12-step verification procedure in §10
- Formalized `AnchorResolver` callback contract in §9.2
- Added `previous_version_anchor` field for version chain support

### Reference implementations

- **Python** (`implementations/python/`) — 108 tests, all passing, 14/14 CV vectors
- **TypeScript** (`implementations/typescript/`) — 70 tests, all passing, 14/14 CV vectors
- **Node.js** (`implementations/js/`) — 80 tests, all passing, 14/14 CV vectors
- **Go** (`implementations/go/`) — 27 tests, all passing, 14/14 CV vectors
- **Rust** (`implementations/rust/`) — 30 tests, all passing, 14/14 CV vectors

### Conformance

- TV-01 through TV-19 formally defined and implemented across all suites
- CV-01 through CV-14 deterministic cross-implementation vectors in `conformance/cross_verify_vectors.json`
- Bootstrap rule verified in all five implementations: `core_fingerprint` absent from `CORE_HASH_FIELDS`

---

## v0.5.1 — February 2026 *(Founding provenance record — not published)*

- Added `previous_version_anchor` field for version chain support
- Soft binding threshold capped at `SOFT_BINDING_THRESHOLD_MAX`
- Minor field validation improvements

## v0.5 — February 2026 *(Founding provenance record — not published)*

- Added `manifest_signature` concept (preliminary)
- Added `anchor_reference` field
- Multi-hash `hash_original` array support (preliminary)

## v0.4 — February 2026 *(Founding provenance record — not published)*

- Added Ed25519 `signature` field
- Added `creator_id` with `ed25519-fp-` format
- UUID v7 `asset_id` required for new manifests

## v0.3.1 — February 2026 *(Founding provenance record — not published)*

- Patch: timestamp validation requires UTC `Z` suffix

## v0.3 — February 2026 *(Founding provenance record — not published)*

- Added `extensions` block
- Added soft binding via `extensions.soft_binding` pHash

## v0.2 — February 2026 *(Founding provenance record — not published)*

- Added `hash_schema_block` (now `core_fingerprint`)
- SHA-384 and SHA3-256 algorithm support

## v0.1 — February 2026 *(Founding provenance record — not published)*

- Initial release
- `asset_id`, `hash_original`, `creation_timestamp`, `creator_id`
- SHA-256 only

---

## Supported versions

v0.5.5 is the first and only published version of AIOSchema. Versions v0.1 through
v0.5.1 are founding provenance records — cryptographically anchored prior art establishing
the development lineage, but never publicly released.

v0.5.5 verifiers accept the following `schema_version` values to preserve the integrity
of the founding provenance chain. These values appear in the anchored founding record
manifests and must remain verifiable:

`0.1` `0.2` `0.3` `0.3.1` `0.4` `0.5` `0.5.1` `0.5.5`
