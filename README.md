# AIOSchema

**Cryptographic provenance for any digital asset.**

AIOSchema is an open standard for generating, anchoring, and verifying digital content provenance — a small JSON sidecar file (`.aios.json`) that cryptographically describes what a file is, when it existed, and who created it. Designed to be read in one hour and implemented in one day.

- **Specification:** [aioschema.org](https://aioschema.org)
- **Hub & Tools:** [aioschemahub.com](https://aioschemahub.com)
- **Current version:** v0.5.5 (Technical Preview)
- **Regulatory target:** EU AI Act Article 50 / California SB 942 — August 2, 2026

---

## What a manifest looks like

```json
{
  "core": {
    "asset_id": "019526c1-3b2a-7f4d-9e01-a1b2c3d4e5f6",
    "schema_version": "0.5.5",
    "creation_timestamp": "2026-03-01T00:00:00Z",
    "hash_original": "sha256-e3b0c44298fc1c149afbf4c8996fb98467ae41e4649b934ca495991b7852b855",
    "core_fingerprint": "sha256-...",
    "creator_id": "ed25519-fp-ebc64203390ddefc442ade9038e1ae18"
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
│   ├── python/                  Reference implementation (Python 3.9+)
│   ├── typescript/              Reference implementation (TypeScript / Node 18+)
│   ├── js/                      Reference implementation (Node.js, npm package)
│   ├── go/                      Reference implementation (Go 1.21+)
│   └── rust/                    Reference implementation (Rust 2021)
├── conformance/                 Cross-implementation test vectors (JSON)
```

---

## Quick start

**Python**
```bash
pip install cryptography pillow
python aioschema_v055.py generate myfile.pdf
python aioschema_v055.py verify myfile.pdf myfile.pdf.aios.json
```

**Node.js (CLI)**
```bash
npm install -g @aioschema/js
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

Any implementation must pass all 19 test vectors (TV-01 through TV-19) and all 14 cross-implementation deterministic vectors (CV-01 through CV-14). See [`CONFORMANCE_VECTORS.md`](./CONFORMANCE_VECTORS.md) and [`conformance/`](./conformance/).

Current status:

| Implementation | Unit tests | CV vectors |
|---|---|---|
| Python | 108 ✓ | 14/14 ✓ |
| TypeScript | 70 ✓ | 14/14 ✓ |
| Node.js | 80 ✓ | 14/14 ✓ |
| Go | 28 ✓ | 14/14 ✓ |
| Rust | 37 ✓ | 14/14 ✓ |

---

## License

- **Specification:** [CC-BY 4.0](https://creativecommons.org/licenses/by/4.0/) — implement freely with attribution.
- **Reference implementations:** [Apache 2.0](https://www.apache.org/licenses/LICENSE-2.0).

See [`LICENSE.md`](./LICENSE.md) for full terms.
