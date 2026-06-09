<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 Ovidiu Ancuta -->
<!--
     AIOSchema monorepo root CHANGELOG
     https://aioschema.org
-->

# Changelog

All notable changes to the AIOSchema standard and reference implementations
are documented here. This file covers the monorepo root. Each implementation
has its own CHANGELOG or version history in its subdirectory.

---

## v0.5.6 (2026-06-06)

### Specification

- **`compliance_eu_art50` replaces `x-aioschema-eu_art50`**

  The vendor-prefixed key `x-aioschema-eu_art50` is replaced by
  `compliance_eu_art50` under the `extensions.compliance` namespace. The
  field carries exactly two normative sub-fields: `editorial_responsibility`
  (MUST) and `review_type` (MUST when claiming the EU AI Act Art. 50(4)
  exemption). Personal data fields (`reviewer_name`, `reviewer_role`,
  `reviewer_contact`) are not part of the standard; they remain in deployer
  internal records per GDPR Art. 5(1)(c).

- **TV-19 to TV-25 canonicalized**

  Seven new test vectors added to `test-vectors/v0.5.6/`:

  | Vector | Category | Outcome |
  |---|---|---|
  | TV-19 | public-key binding | `public_key` fingerprint matches `creator_id`; PASS |
  | TV-20 | public-key binding | `public_key` fingerprint mismatch; FAIL |
  | TV-21 | ai-declaration | valid `standard_editing=false` constraint; PASS |
  | TV-22 | ai-declaration | `standard_editing=true` conflict with §11.1; FAIL |
  | TV-23 | extension-size | extensions at 4096-byte limit; PASS |
  | TV-24 | extension-size | extensions at 4097 bytes, one over limit; FAIL |
  | TV-25 | compliance | `compliance_eu_art50` warning pattern; WARN |

- **CV-15 to CV-18 added**

  Four new cross-verification vectors bring the total to 18. All six
  implementations are required to pass all 18 vectors.

- **`manifest.json` schema updated**

  `conformance/cross_verify_vectors.json` updated: `schema_version` fields
  set to `"0.5.6"`, CV-05 and CV-06 expected values recomputed.

### Reference implementations

All six implementations updated to v0.5.6 conformance. SPDX Apache-2.0
headers and closing footers applied to every source and documentation file.
Inline per-file changelog blocks removed; history lives in CHANGELOG.md only.

| Implementation | Path | Key changes |
|---|---|---|
| JS/Node.js | `implementations/js/` | `compliance_eu_art50`; default TSA `rfc3161.ai.moda`; TV-25 wired |
| Go | `implementations/go/` | `compliance_eu_art50`; TV-25 (`TestTV25_ComplianceEuArt50`); README and LICENSE added |
| Rust | `implementations/rust/` | `compliance_eu_art50`; TV-25 (`tv25_compliance_eu_art50`); README and LICENSE added |
| TypeScript | `implementations/typescript/` | `compliance_eu_art50`; default TSA `rfc3161.ai.moda`; TV-25 wired; README and LICENSE added |
| Python | `implementations/python/` | `compliance_eu_art50`; default TSA `rfc3161.ai.moda`; TV-25 (`TestTV25ComplianceEuArt50`); README and LICENSE added |
| .NET (C#) | `implementations/dotnet/` | Zero-dependency; `SpecVersion` `"0.5.6"`; TV-25 (`RunTV25()`); README added |

### Tools

- CLI v0.5.14 (`tools/cli/`)

### Repo hygiene

- SPDX headers and closing footers on all source and documentation files
- JSON files: no header or footer (no comment syntax in JSON)
- `Cargo.lock`, `go.mod`: no header or footer
- `test_tv19_debug.ts` excluded from the repo (development scratch file)
- `_rustc_info.json` excluded via `.gitignore` (build artifact)
- `.gitignore` written at repo root covering all anguages

---

## v0.5.5 (2026-03-14)

Initial public anchored release. RFC 3161 anchor serial `03801FB4`,
timestamp `2026-03-14T04:08:39Z` (FreeTSA). Genesis OTS anchor: Bitcoin
block 939726.

- Five reference implementations: JS, Go, Rust, TypeScript, Python
- TV-01 to TV-18 test vector suite
- CV-01 to CV-14 cross-verification vectors

---

## Earlier versions

See git history for v0.4 and earlier.

<!-- end AIOSchema monorepo root CHANGELOG | https://aioschema.org -->
