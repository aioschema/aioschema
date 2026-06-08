<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 Ovidiu Ancuta -->
<!-- aioschema/typescript v0.5.6 | AIOSchema spec v0.5.6 | https://aioschema.org -->

# @aioschema/typescript

**AIOSchema v0.5.6 — TypeScript reference implementation.**

Pure TypeScript. Requires Node.js 18 or later. Compiles to CommonJS via `tsc`.

- Spec: [aioschema.org](https://aioschema.org)

---

## Install

```bash
npm install @aioschema/typescript
```

---

## API

```typescript
import { generateManifest, verifyManifest, creatorIdFromPublicKey } from "@aioschema/typescript";

// Generate a manifest
const manifest = generateManifest(assetBytes);

// Generate with Ed25519 signing
const manifest = generateManifest(assetBytes, {
  creatorId: "ed25519-fp-ebc64203390ddefc442ade9038e1ae18",
  privateKey: privateKeySeed,         // raw 32-byte Uint8Array
  extensions: { public_key: pubB64 }, // base64 public key for self-contained verification
});

// Verify
const result = await verifyManifest(assetBytes, manifest);
console.log(result.success);     // true
console.log(result.matchType);   // "exact"

// Verify with explicit public key
const result = await verifyManifest(assetBytes, manifest, { publicKey: pubKeyBytes });
console.log(result.signatureVerified); // true
```

---

## Full API reference

```typescript
// Manifest generation and verification
generateManifest(data: Uint8Array, opts?: GenerateOptions): Manifest
verifyManifest(assetData: Uint8Array, manifest: Manifest, opts?: VerifyOptions): Promise<VerificationResult>

// Keys
creatorIdFromPublicKey(publicKey: Uint8Array | KeyObject): string

// Hashing
computeHash(data: Uint8Array, algorithm: string): string
parseHash(s: string): [algorithm: string, hex: string]

// Canonical serialization
canonicalJson(o: unknown): Buffer
canonicalManifestBytes(m: Manifest): Buffer

// Serialization
manifestToJson(m: Manifest, indent?: number): string
manifestFromJson(s: string): Manifest

// Utilities
uuidV7(): string
anonymousCreatorId(): string
safeEqual(a: string, b: string): boolean

// RFC 3161 anchoring
anchorRfc3161(coreFingerprint: string, tsaUrl?: string, outPath?: string): Promise<RFC3161Result>
verifyRfc3161(tsrBytes: Buffer, coreFingerprint: string): { verified: boolean; message: string }

// Constants
SPEC_VERSION                    // "0.5.6"
SUPPORTED_VERSIONS              // ReadonlySet<string>
CORE_HASH_FIELDS                // readonly string[]
MAX_EXTENSION_SIZE_BYTES        // 4096
HASH_REGEX                      // RegExp
SOFT_BINDING_THRESHOLD_DEFAULT  // 0.95
SOFT_BINDING_THRESHOLD_MAX      // 0.99
```

---

## Running tests

```bash
# Compile
npx tsc

# Unit and conformance tests
npx ts-node test_aioschema_v055.ts

# Cross-implementation verification (18 deterministic vectors)
AIOSCHEMA_VECTORS=/path/to/cross_verify_vectors.json npx ts-node cross_verify_ts.ts
```

---

## File structure

```
implementations/typescript/
├── algorithms.ts           # Hash computation, canonical JSON, pHash, UUID v7
├── anchor.ts               # RFC 3161 anchoring (§9)
├── index.ts                # Public API barrel export
├── manifest.ts             # Manifest generation and signing
├── types.ts                # Type definitions and constants
├── verify.ts               # §10 verification procedure
├── test_aioschema_v055.ts  # Unit and conformance tests
├── cross_verify_ts.ts      # 18 cross-implementation vectors
├── tsconfig.json
├── cross_verify_vectors.json
├── README.md
└── LICENSE.md
```

**Never commit:** `dist/`, `node_modules/`, `*.js.map`

---

## License

Apache 2.0. See [LICENSE.md](./LICENSE.md).

Specification: CC-BY 4.0 — [aioschema.org](https://aioschema.org)

<!-- end aioschema/typescript v0.5.6 | AIOSchema spec v0.5.6 -->
