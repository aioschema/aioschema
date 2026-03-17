# AIOSchema Conformance Vectors

`cross_verify_vectors.json` contains 14 deterministic cross-implementation test vectors (CV-01 through CV-14). Any conforming AIOSchema implementation must produce byte-identical results for all 14 vectors.

---

## Running the CV suite

**Python**
```bash
cd implementations/python
python cross_verify_python.py
# Expected: 14/14 PASS ✓ ALL PASS
```

**TypeScript**
```bash
cd implementations/typescript
npx ts-node cross_verify_ts.ts
# Expected: 14/14 PASS ✓ ALL PASS
```

**Node.js**
```bash
cd implementations/js
node cross_verify_node.js
# Expected: 14/14 PASS ✓ ALL PASS
```

**Go**
```bash
cd implementations/go
go test ./... -run CrossVerify
# Expected: PASS
```

**Rust**
```bash
cd implementations/rust
cargo test cross_verify
# Expected: test result: ok. 14 passed
```

---

## Vector format

Each vector in `cross_verify_vectors.json` has one of two shapes:

**Hash / canonical JSON vectors (CV-01 through CV-06)**
```json
{
  "id": "CV-01",
  "name": "SHA-256 of known string",
  "type": "hash",
  "inputs": { "algorithm": "sha256", "data_utf8": "The quick brown fox..." },
  "expected": { "hash": "sha256-d7a8fbb3..." }
}
```

**Verification vectors (CV-07 through CV-14)**
```json
{
  "id": "CV-07",
  "name": "Valid manifest — hard match",
  "type": "verify",
  "inputs": { "asset_bytes_hex": "...", "manifest": { ... } },
  "expected": { "success": true, "match_type": "hard" }
}
```

---

## Adding vectors

When a new spec version introduces deterministic behavior changes:

1. Add the vector to `cross_verify_vectors.json` with the next CV number
2. Update all five implementation runners to handle it
3. Update `CONFORMANCE_VECTORS.md` in the repo root
4. All implementations must pass before the vector is considered normative
