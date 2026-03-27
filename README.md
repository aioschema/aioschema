# AIOSchema

**Cryptographic provenance for any digital asset.**

AIOSchema is an open standard for generating, anchoring, and verifying the provenance of digital content and physical assets — a small JSON sidecar file (`.aios.json`) that cryptographically describes what a file is, when it existed, and who created it. Designed to be read in one hour and implemented in one day.

- **Specification:** [aioschema.org](https://aioschema.org)
- **Hub & Tools:** [aioschemahub.com](https://aioschemahub.com)
- **Current version:** v0.5.5 (Technical Preview)

> **Why now?**  
> EU AI Act Article 50 (Aug 2026) and Digital Product Passport (2027+) require verifiable provenance. AIOSchema is the only open standard that’s lightweight, modular, and already implemented across five languages.
---

## What a manifest looks like

```json
{
  "core": {
    "asset_id": "019526c1-3b2a-7f4d-9e01-a1b2c3d4e5f6",
    "schema_version": "0.5.5",
    "creation_timestamp": "2026-03-01T00:00:00Z",
    "hash_original": "sha256-e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "core_fingerprint": "sha256-...",
    "creator_id": "ed25519-fp-7fcc5530c17565c99ea02d846ab0b5eb"
  }
}
```

One file alongside your asset. Verifiable forever, by anyone, with no central authority.

---

## Repository structure

```
aioschema/
├── spec/                        Specification documents
├── implementations/
│   ├── API.md                   Language-neutral API contracts
│   ├── python/                  Reference implementation (Python 3.9+)
│   ├── typescript/              Reference implementation (TypeScript)
│   ├── js/                      Reference implementation (Node.js 18+)
│   ├── go/                      Reference implementation (Go 1.21+)
│   └── rust/                    Reference implementation (Rust 2021)
├── cli/                         Command-line tool
└── conformance/                 Cross-implementation test vectors
```

---

## Quick start

**Python**
```bash
pip install cryptography pillow
python implementations/python/aioschema_v055.py
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

---

## Conformance

Any implementation must pass all 18 test vectors (TV-01 through TV-18) and all 14 cross-implementation deterministic vectors (CV-01 through CV-14). See [`CONFORMANCE_VECTORS.md`](./CONFORMANCE_VECTORS.md) and [`conformance/`](./conformance/).

TV-19 (key rotation via `previous_version_anchor`) is implemented as an extension in the Node.js and TypeScript suites. It will be canonicalized in v0.5.6.

| Implementation | Unit tests | CV vectors |
|---|---|---|
| Python | 108 ✓ | 14/14 ✓ |
| TypeScript | 70 ✓ | 14/14 ✓ |
| Node.js | 80 ✓ | 14/14 ✓ |
| Go | 27 ✓ | 14/14 ✓ |
| Rust | 30 ✓ | 14/14 ✓ |

---

## License

- **Specification:** [CC-BY 4.0](https://creativecommons.org/licenses/by/4.0/) — implement freely with attribution.
- **Reference implementations:** [Apache 2.0](https://www.apache.org/licenses/LICENSE-2.0).

See [`LICENSE.md`](./LICENSE.md) for full terms.
