# @aioschema/js

**AIOSchema v0.5.5 — Node.js reference implementation and CLI.**

Pure CommonJS. Zero external dependencies. Requires Node.js ≥ 18.

- Spec: [aioschema.org](https://aioschema.org)
- Hub: [aioschemahub.com](https://aioschemahub.com)

---

## Install

```bash
npm install @aioschema/js
```

For the CLI globally:
```bash
npm install -g @aioschema/js
```

---

## CLI

```bash
# Generate a manifest for a file
aioschema generate myfile.pdf

# Generate with a specific algorithm
aioschema generate myfile.pdf --algorithm sha384

# Generate with your creator_id
aioschema generate myfile.pdf --creator-id ed25519-fp-ebc64203390ddefc442ade9038e1ae18

# Verify a file against its manifest
aioschema verify myfile.pdf myfile.pdf.aios.json

# Show help
aioschema --help
```

The CLI writes `myfile.pdf.aios.json` alongside your file. The original file is never modified.

---

## API

```js
const { generateManifest, verifyManifest, generateKeypair } = require('@aioschema/js');

// Generate a manifest
const manifest = generateManifest('myfile.pdf');
// → writes myfile.pdf.aios.json, returns the manifest object

// Generate with signing
const { privateKey, publicKey } = generateKeypair();
const signed = generateManifest('myfile.pdf', { privateKey });

// Verify
const result = await verifyManifest('myfile.pdf', manifest);
console.log(result.success);     // true
console.log(result.match_type);  // "hard"

// Verify with signature check
const result2 = await verifyManifest('myfile.pdf', signed, { publicKey });
console.log(result2.signature_verified); // true
```

---

## Full API reference

```js
const aios = require('@aioschema/js');

// Core
aios.generateManifest(filePath, opts?)   // generate + save sidecar
aios.verifyManifest(filePath, manifest, opts?)  // verify asset against manifest

// Keys
aios.generateKeypair()                   // → { privateKey, publicKey }
aios.creatorIdFromPublicKey(pubKeyBytes) // → "ed25519-fp-<hex>"
aios.creatorIdAnonymous()                // → "anon"
aios.validateCreatorId(id)               // → boolean

// Hashing
aios.computeHash(data, algorithm?)       // → "sha256-<hex>"
aios.parseHashPrefix(hash)               // → { algorithm, hex }

// Canonical JSON
aios.canonicalJson(obj)                  // → sorted-key JSON string
aios.canonicalBytes(obj)                 // → Buffer of canonicalJson
aios.canonicalManifestBytes(manifest)    // → Buffer for manifest_signature

// Sidecar I/O
aios.sidecarPath(filePath)              // → "myfile.pdf.aios.json"
aios.saveSidecar(filePath, manifest)    // write manifest to disk
aios.loadSidecar(filePath)              // read manifest from disk

// Utilities
aios.uuidV7()                           // → UUID v7 string
aios.safeEqual(a, b)                    // timing-safe Buffer comparison

// Constants
aios.SPEC_VERSION                       // "0.5.5"
aios.SUPPORTED_VERSIONS                 // Set of accepted schema_version values
aios.CORE_HASH_FIELDS                   // ["asset_id", "schema_version", ...]
aios.DEFAULT_HASH_ALG                   // "sha256"
aios.SOFT_BINDING_THRESHOLD_DEFAULT     // 5
aios.SOFT_BINDING_THRESHOLD_MAX         // 10
aios.SIDECAR_SUFFIX                     // ".aios.json"
aios.HASH_REGEX                         // RegExp for hash format validation
```

---

## Running tests

```bash
# Unit tests (80 tests, Node built-in test runner)
node test_aioschema_v055.js

# Cross-implementation verification (14 deterministic vectors)
node cross_verify_node.js
```

---

## License

Apache 2.0. See [LICENSE.md](./LICENSE.md).

Specification: CC-BY 4.0 — [aioschema.org](https://aioschema.org)
