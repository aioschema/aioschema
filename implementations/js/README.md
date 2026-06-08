<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 Ovidiu Ancuta -->
<!-- aioschema/js v0.5.6 | AIOSchema spec v0.5.6 | https://aioschema.org -->

# AIOSchema v0.5.6 — Node.js Reference Implementation

Cryptographic content provenance for Node.js. Generates, anchors, and verifies
[AIOSchema](https://aioschema.org) v0.5.6 manifests.

```js
const aios = require("./aioschema_v056.js");

const asset  = require("fs").readFileSync("report.pdf");
const manifest = aios.generateManifest(asset, { algorithm: "sha256" });
const result   = await aios.verifyManifest(asset, manifest);

console.log(result.success);     // true
console.log(result.match_type);  // "hard"
```

---

## Requirements

- Node.js 18 or later (uses `node:test`, `node:crypto`)
- Zero external npm dependencies

---

## Quick start

### Level 1 — Hash binding (unsigned)

```js
const aios = require("./aioschema_v056.js");
const fs   = require("fs");

const asset    = fs.readFileSync("image.png");
const manifest = aios.generateManifest(asset, { algorithm: "sha256" });

// Save sidecar
fs.writeFileSync("image.png.aios.json", JSON.stringify(manifest, null, 2));

// Verify later
const loaded = JSON.parse(fs.readFileSync("image.png.aios.json"));
const result = await aios.verifyManifest(fs.readFileSync("image.png"), loaded);
console.log(result.success);    // true
console.log(result.match_type); // "hard"
```

### Level 2 — Signed manifest (Ed25519)

```js
const aios = require("./aioschema_v056.js");
const fs   = require("fs");

// Generate a keypair (32-byte seed, keep secret)
const { seed, publicKey } = aios.generateKeyPair();
const creatorId = aios.creatorIdFromPublicKey(publicKey);

const asset = fs.readFileSync("video.mp4");

const manifest = aios.generateManifest(asset, {
  algorithm: "sha256",
  creatorId,
  seed,
  extensions: {
    public_key: Buffer.from(publicKey).toString("base64"),
  },
});

// Verify — public key is embedded, no external key needed
const result = await aios.verifyManifest(asset, manifest);
console.log(result.success);                    // true
console.log(result.signature_verified);         // true
console.log(result.manifest_signature_verified);// true
console.log(result.public_key_fingerprint_match);// true
```

### AI disclosure (EU AI Act Article 50)

```js
const manifest = aios.generateManifest(asset, {
  algorithm: "sha256",
  extensions: {
    ai_declaration: {
      disclosure_required: true,
      ai_generated:        true,
      ai_manipulated:      false,
      human_reviewed:      true,
      standard_editing:    false,
    },
  },
});
```

### Multi-hash manifest

```js
// hash_original becomes an array — any supported hash passes verification
const manifest = aios.generateManifest(asset, {
  algorithms: ["sha256", "sha384"],
});
// manifest.core.hash_original → ["sha256-...", "sha384-..."]
```

---

## API reference

### `generateManifest(data, options)`

Generates an AIOSchema v0.5.6 manifest for the given asset.

**Parameters**

- `data` — `Buffer` — asset bytes
- `options`:

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `algorithm` | `string` | `"sha256"` | Primary hash algorithm (`"sha256"`, `"sha384"`, `"sha3-256"`) |
| `algorithms` | `string[]` | — | Multiple algorithms — produces array `hash_original` |
| `creatorId` | `string` | anonymous UUID v7 | Override `creator_id` |
| `seed` | `Buffer` | — | Ed25519 seed (32 bytes) — enables Level 2 signing |
| `extensions` | `object` | `{}` | Merged into the `extensions` block |

**Returns** `object` — the manifest (`{ core, extensions }`)

---

### `verifyManifest(data, manifest, options?)`

Runs the full §10 verification procedure against the asset bytes.

**Parameters**

- `data` — `Buffer` — asset bytes
- `manifest` — `object` — manifest to verify
- `options`:

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `verifyAnchor` | `boolean` | `false` | Call `anchorResolver` to check the anchor |
| `anchorResolver` | `function` | — | `async (anchorUri) => { asset_id, core_fingerprint, timestamp }` |
| `publicKeyHex` | `string` | — | Override public key for signature verification (usually not needed — use `extensions.public_key`) |

**Returns** `Promise<VerificationResult>`

---

### `VerificationResult`

| Property | Type | Description |
|----------|------|-------------|
| `success` | `boolean` | Overall pass/fail |
| `message` | `string` | Human-readable result |
| `match_type` | `"hard"` \| `"soft"` \| `null` | How the hash matched |
| `signature_verified` | `boolean` | Core Ed25519 signature verified |
| `manifest_signature_verified` | `boolean` | Full manifest signature verified |
| `public_key_fingerprint_match` | `boolean` | `extensions.public_key` fingerprint matched `creator_id` (§11.3) |
| `anchor_checked` | `boolean` | Anchor reference was resolved |
| `anchor_verified` | `boolean` | Anchor record matched manifest |
| `warnings` | `string[]` | Non-fatal issues |

---

### `generateKeyPair()`

Generates an Ed25519 keypair using OS CSPRNG.

**Returns** `{ seed: Buffer, publicKey: Buffer }` — both 32 bytes

---

### `creatorIdFromPublicKey(publicKey)`

Derives the `ed25519-fp-<32hex>` creator ID from a public key.

**Parameters** — `publicKey: Buffer` — 32-byte Ed25519 public key  
**Returns** `string` — e.g. `"ed25519-fp-7fcc5530c17565c99ea02d846ab0b5eb"`

---

### Constants

| Export | Value | Description |
|--------|-------|-------------|
| `SPEC_VERSION` | `"0.5.6"` | AIOSchema spec version |
| `CORE_HASH_FIELDS` | `string[]` | Fields that feed `core_fingerprint` (§5.6) |
| `MAX_EXTENSION_SIZE_BYTES` | `4096` | Hard ceiling on `extensions` block (§6.3) |

---

## What's in v0.5.6

- **`extensions.public_key`** — embed Ed25519 public key in the manifest; verifier
  cross-checks its SHA-256 fingerprint against `creator_id` for self-contained L2
  verification with no out-of-band key lookup (§11.3)
- **`extensions.ai_declaration`** — structured EU AI Act Article 50 disclosure fields;
  constraint enforced by verifier: `standard_editing=true` requires `disclosure_required=false` (§11.1)
- **Multi-hash `hash_original`** — array form; any supported algorithm match passes
  verification (§5.5)
- **Extension size enforcement** — `extensions` block capped at 4,096 bytes (§6.3)
- **`previous_version_anchor`** — provenance chain linking manifest versions (§5.1)
- **`extensions.description`** — human-readable provenance note, max 256 chars (§17.5.1)

---

## Running the tests

```bash
# 42 unit tests (Node built-in test runner, no dependencies)
node unit_tests_node.js

# 18 cross-implementation verification vectors
node cross_verify_node.js
```

Test breakdown:

| Suite | Count | File |
|-------|-------|------|
| `computeHash` | 8 | `unit_tests_node.js` |
| `parseHashPrefix` | 4 | `unit_tests_node.js` |
| `canonicalJson` | 6 | `unit_tests_node.js` |
| `canonicalBytes` | 2 | `unit_tests_node.js` |
| `safeEqual` | 3 | `unit_tests_node.js` |
| `verifyManifest` (CV-07–CV-14 + misc) | 11 | `unit_tests_node.js` |
| `verifyManifest` (TV-19–TV-24, v0.5.6) | 6 | `unit_tests_node.js` |
| `CORE_HASH_FIELDS` | 2 | `unit_tests_node.js` |
| **Total unit tests** | **42** | |
| Cross-implementation vectors (CV-01–CV-18) | 18 | `cross_verify_node.js` |

---

## Conformance

This implementation passes the full AIOSchema conformance suite:

- **42 unit tests**
- **24 conformance vectors** (TV-01–TV-24, §5.4)
- **18 cross-verification vectors** (CV-01–CV-18) — tested against the Python,
  TypeScript, Go, Rust, and .NET reference implementations

All six implementations are cryptographically interoperable. A manifest signed
by any implementation verifies correctly in all others.

---

## Implementation notes

- Zero npm dependencies — `node:crypto` and `node:test` only
- Ed25519 via `node:crypto` (`generateKeyPairSync`, `createSign`, `createVerify`)
- SHA-256, SHA-384, SHA3-256 via `node:crypto`
- Canonical JSON: recursive key sort, compact separators, UTF-8 — §5.6 conformant
- `asset_id` uses UUID v7 (time-ordered) for stable, sortable identifiers
- `creator_id` uses UUID v7 (anonymous) or `ed25519-fp-<32hex>` (attributed)
- Timing-safe comparison throughout (`timingSafeEqual` — §12.1)
- `hash_original` accepts both string (legacy) and array (multi-hash) forms —
  see §5.5 implementation note for deserialization guidance

---

## File structure

```
implementations/js/
├── aioschema_v056.js       # Main implementation
├── unit_tests_node.js      # 42 unit tests (node:test)
├── cross_verify_node.js    # 18 cross-implementation vectors
├── package.json            # version 0.5.6
└── README.md               # This file
```

---

## Links

- **Specification:** [aioschema.org](https://aioschema.org)
- **Field reference:** [aioschema.org/field-reference/v0-5-6/](https://aioschema.org/field-reference/v0-5-6/)
- **Hub and tools:** [aioschemahub.com](https://aioschemahub.com)
- **All implementations:** [github.com/aioschema/aioschema](https://github.com/aioschema/aioschema)
- **License:** Apache-2.0

<!-- end aioschema/js v0.5.6 | AIOSchema spec v0.5.6 | https://aioschema.org -->