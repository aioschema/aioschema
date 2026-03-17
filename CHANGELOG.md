# Changelog

All notable changes to the AIOSchema specification and reference implementations.

---

## v0.5.5 — February 2026

**The stable foundation release.** First version with four independent reference
implementations and a cross-verified conformance test suite.

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

- **Python** (`aioschema_v055.py`) — 108 tests, all passing
- **TypeScript** (`implementations/typescript/`) — 70 tests, all passing
- **Go** (`implementations/go/`) — all unit tests and 14 CV vectors passing
- **Rust** (`implementations/rust/`) — all unit tests and 14 CV vectors passing

### Conformance

- TV-01 through TV-18 formally defined and implemented across all suites
- CV-01 through CV-14 deterministic cross-implementation vectors in `cross_verify_vectors.json`
- Bootstrap rule verified in all four implementations: `core_fingerprint` absent from `CORE_HASH_FIELDS`

---

## v0.5.1 — February 2026

- Soft binding threshold capped at `SOFT_BINDING_THRESHOLD_MAX`
- Minor field validation improvements

## v0.5 — February 2026

- Added `manifest_signature` concept (preliminary)
- Added `anchor_reference` field
- Multi-hash `hash_original` array support (preliminary)

## v0.4 — February 2026

- Added Ed25519 `signature` field
- Added `creator_id` with `ed25519-fp-` format
- UUID v7 `asset_id` required for new manifests

## v0.3.1 — February 2026

- Patch: timestamp validation requires UTC `Z` suffix

## v0.3 — February 2026

- Added `extensions` block
- Added soft binding via `extensions.soft_binding` pHash

## v0.2 — February 2026

- Added `hash_schema_block` (now `core_fingerprint`)
- SHA-384 and SHA3-256 algorithm support

## v0.1 — February 2026

- Initial release
- `asset_id`, `hash_original`, `creation_timestamp`, `creator_id`
- SHA-256 only

---

## Supported versions

The following schema versions are accepted by v0.5.5 verifiers:

`0.1` `0.2` `0.3` `0.3.1` `0.4` `0.5` `0.5.1` `0.5.5`
