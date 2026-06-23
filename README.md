<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- Copyright 2026 Ovidiu Ancuta -->
<!-- AIOSchema v0.5.6 | README.md | https://aioschema.org -->

# AIOSchema

**Cryptographic provenance for any digital asset and physical assets.**

AIOSchema is an open standard for generating, anchoring, and verifying the provenance of digital content and physical assets: a small JSON sidecar file (`.aios.json`) that cryptographically describes what a file is, when it existed, and who created it. Designed to be read in one hour and implemented in one day.

- - **Specification:** [aioschema.org](https://aioschema.org/?utm_source=github-readme)
- **CLI:** [aioschema.org/cli](https://aioschema.org/cli)
- **Current version:** v0.5.6

> **Why now?**  
> EU AI Act Article 50 (Aug 2026) and Digital Product Passport (2027+) require verifiable provenance. AIOSchema is the only open standard that is lightweight, modular, and already implemented across six languages — with a zero-dependency .NET implementation, EU AI Act Article 50 editorial exemption support built in, and a 25-vector conformance suite that any implementation can run in under a minute.

---

## What a manifest looks like

```json
{
  "core": {
    "asset_id": "019526c1-3b2a-7f4d-9e01-a1b2c3d4e5f6",
    "schema_version": "0.5.6",
    "creation_timestamp": "2026-05-10T12:00:00Z",
    "hash_original": "sha256-45880b5668c1271d3546dc2f8ec4d8bed1fbf9deb986b76da73b1ea459a6d492",
    "core_fingerprint": "sha256-9d03a34ebfd1e3614a7ae742d7533b4b05978538ed5e55c6339413d4eb07e5c8",
    "creator_id": "ed25519-fp-7fcc5530c17565c99ea02d846ab0b5eb",
    "signature": "ed25519-<128-hex>",
    "manifest_signature": "ed25519-<128-hex>",
    "anchor_reference": "aios-anchor:rfc3161:abc123"
  },
  "extensions": {
    "compliance_level": 3,
    "ai_declaration": {
      "disclosure_required": true,
      "ai_generated": true,
      "ai_manipulated": false,
      "human_reviewed": true
    },
    "compliance": {
      "eu_art50": {
        "editorial_responsibility": "Organisation Legal Name",
        "review_type": "substantive"
      }
    }
  }
}
```

One file alongside your asset. Verifiable forever, by anyone, with no central authority.

---

## Repository structure

```
aioschema/
├── spec/                        Specification documents
├── conformance/                 Test vectors (TV-01 to TV-25) and cross-verify suite (CV-01 to CV-18)
├── implementations/
│   ├── js/                      Node.js 18+
│   ├── python/                  Python 3.9+
│   ├── typescript/              TypeScript
│   ├── go/                      Go 1.21+
│   ├── rust/                    Rust 2021
│   └── dotnet/                  .NET 8, zero external dependencies
├── cli/                         @aioschema/cli command-line tool
├── provenance/                  Versioned provenance records for this specification
├── publications/                Position papers and white papers
└── API.md                       Language-neutral API contracts
```

---

## Quick start

**Python**
```bash
pip install cryptography pillow
python implementations/python/aioschema_v056.py
```

**Node.js (CLI)**
```bash
npm install -g @aioschema/cli
aioschema generate myfile.pdf
aioschema verify myfile.pdf myfile.pdf.aios.json
```

**Node.js (API)**
```js
const { generateManifest, verifyManifest } = require('@aioschema/js');
const manifest = generateManifest('myfile.pdf');
const result = await verifyManifest('myfile.pdf', manifest);
console.log(result.success, result.match_type);
```

**Go**
```bash
cd implementations/go
go test ./...
```

**Rust**
```bash
cd implementations/rust
cargo test
```

**.NET**
```bash
cd implementations/dotnet
dotnet test
```

---

## Conformance

Any implementation must pass all 25 test vectors (TV-01 through TV-25) and all 18 cross-implementation deterministic vectors (CV-01 through CV-18). See [`conformance/CONFORMANCE_VECTORS.md`](./conformance/CONFORMANCE_VECTORS.md).

Six implementations. All cross-verified. All minimal by design: no implementation pulls in a dependency it does not need. The .NET implementation uses zero external NuGet packages — Ed25519 signing, SHA-256, and UUID v7 are all pure managed .NET 8. For a provenance standard, the auditability of the implementation itself matters as much as the auditability of what it produces.

| Implementation | Unit tests | CV vectors |
|---|---|---|
| Python | 115 | 18/18 |
| TypeScript | 77 | 18/18 |
| Node.js | 43 | 18/18 |
| Go | 34 | 18/18 |
| Rust | 37 | 18/18 |
| .NET | 69 | 18/18 |

---

## License

- **Specification:** [CC-BY 4.0](https://creativecommons.org/licenses/by/4.0/) — implement freely with attribution.
- **Reference implementations:** [Apache 2.0](https://www.apache.org/licenses/LICENSE-2.0).

See [`LICENSE.md`](./LICENSE.md) for full terms.

<!-- end AIOSchema v0.5.6 | README.md | https://aioschema.org -->
