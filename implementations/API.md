# AIOSchema Public API (v0.5.5)

> **AIOSchema v0.5.5 (Technical Preview)**
> © 2026 Ovidiu Ancuta — Founder | https://aioschema.org
> Licensed under CC‑BY 4.0 — attribution required for reuse, modification, or redistribution.
> https://creativecommons.org/licenses/by/4.0/

This document defines the stable, language-agnostic API surface for AIOSchema
implementations. All official implementations (Python, TypeScript, Node.js, Go, Rust)
expose these functions with equivalent behavior. Language naming conventions apply
(snake_case in Python/Go/Rust, camelCase in JS/TS), but the contracts are identical.

---

## Types

### Manifest
```
{
  core:       CoreBlock
  extensions: object
}
```

### CoreBlock
```
{
  asset_id:                string        -- UUID v7 (SHOULD) or UUID v4 (MAY)
  schema_version:          string        -- e.g. "0.5.5"
  creation_timestamp:      string        -- ISO 8601 UTC, ends with "Z"
  hash_original:           string | string[]
  creator_id:              string        -- UUID (anonymous) or ed25519-fp-<32hex>
  core_fingerprint:        string        -- sha256-<64hex> or sha384-<96hex>
  signature:               string | null -- ed25519-<128hex>
  manifest_signature:      string | null -- ed25519-<128hex>
  anchor_reference:        string | null -- aios-anchor:<service-id>:<anchor-id>
  previous_version_anchor: string | null -- aios-anchor URI of predecessor
}
```

### VerificationResult
```
{
  success:                    boolean
  message:                    string
  match_type:                 "hard" | "soft" | null
  signature_verified:         boolean
  manifest_signature_verified: boolean
  anchor_checked:             boolean
  anchor_verified:            boolean
  warnings:                   string[]
}
```

### AnchorRecord
```
{
  asset_id:         string
  core_fingerprint: string
  timestamp:        string   -- ISO 8601 UTC
}
```

---

## Core Functions

### generateManifest(data, options)

Generate an AIOSchema v0.5.5 manifest for an asset.

**Parameters**
- `data` — asset bytes (Buffer / bytes / Uint8Array) or file path (string)
- `options`:
  - `algorithms` — `string[]` — hash algorithms to use. Default: `["sha256"]`. See §19.1.
  - `creatorId` — `string` — override creator_id. Default: anonymous UUID v7.
  - `anchorRef` — `string | null` — anchor URI in `aios-anchor:<svc>:<id>` format (§9.1).
  - `previousVersionAnchor` — `string | null` — anchor URI of predecessor version (§15).
  - `privateKey` — signing key object (language-specific). When provided, generates `signature` and `manifest_signature`.
  - `extensions` — `object` — additional extension fields merged into the manifest.
  - `saveSidecar` — `boolean` — write `<asset>.aios.json` sidecar. Default: `false`.

**Returns** `Manifest`

**Throws** if an unsupported algorithm is specified, or if anchor URI format is invalid.

---

### verifyManifest(data, manifest, options)

Verify an asset against an AIOSchema manifest. Executes all steps defined in §10.

**Parameters**
- `data` — asset bytes or file path
- `manifest` — `Manifest` object or raw dict/object
- `options`:
  - `publicKey` — verification key object (language-specific). Required if manifest is signed.
  - `softBindingThreshold` — `number` — Hamming distance policy threshold. Default: `5`, max: `10`. Never read from manifest (§6.2).
  - `verifyAnchor` — `boolean` — invoke `anchorResolver` to verify anchor. Default: `false`.
  - `anchorResolver` — `(ref: string) => AnchorRecord | null` — callable for anchor verification (§9.2). Returns `null` if record not found. Raises `AnchorVerificationError` on service error.

**Returns** `VerificationResult`

**Notes**
- Returns `success: false` on any normative failure. Never throws on verification failure.
- `match_type: "hard"` — bit-exact hash match.
- `match_type: "soft"` — perceptual hash match within threshold.
- Anchor mismatch does not fail verification — it produces a warning.

---

## Hash Functions

### computeHash(data, algorithm)

Compute a prefixed hash string over raw bytes.

**Parameters**
- `data` — bytes
- `algorithm` — registered algorithm token (§19.1). Default: `"sha256"`.

**Returns** `string` — format: `<alg>-<hex>` e.g. `"sha256-d7a8fb..."`

**Throws** if algorithm is not in the registry.

---

### canonicalJson(object)

Return compact, deterministic JSON with keys sorted alphabetically at all levels.
Used for `core_fingerprint` computation (§5.6) and `manifest_signature` (§5.8).

**Returns** `string`

---

### canonicalManifestBytes(manifest)

Return canonical bytes for `manifest_signature` computation. Sets
`manifest_signature` to `null` before serializing (bootstrap exclusion — §5.8).

**Returns** bytes (Buffer / bytes)

---

## Creator ID

### creatorIdAnonymous()

Generate an anonymous `creator_id` (UUID v7). No identity disclosed.

**Returns** `string`

---

### creatorIdFromPublicKey(pubKeyBytes)

Generate an attributed `creator_id` from raw Ed25519 public key bytes.
Returns `ed25519-fp-<32hex>` — SHA-256 fingerprint of the public key, first 128 bits.

**Parameters**
- `pubKeyBytes` — raw public key bytes (32 bytes)

**Returns** `string`

---

## Key Generation

### generateKeypair()

Generate an Ed25519 keypair for signing.

**Returns** `{ privateKey, publicKey }` — language-specific key objects.

---

## UUID

### uuidV7()

Generate a time-ordered UUID v7 identifier (preferred for `asset_id`).

**Returns** `string`

---

## Sidecar I/O

### sidecarPath(assetPath)

Return the canonical sidecar path for an asset: `<assetPath>.aios.json` (§8.2).

### saveSidecar(assetPath, manifest)

Write manifest as JSON to `<assetPath>.aios.json`.

### loadSidecar(assetPath)

Read and parse the sidecar at `<assetPath>.aios.json`.

**Throws** if no sidecar exists.

---

## Errors

### AnchorVerificationError

Raised by an `anchorResolver` to signal a service-level error (network failure,
timeout, invalid response). Distinct from a verification failure — the manifest
itself may be valid even if the anchor service is unreachable.

---

## Constants

| Constant | Value | Description |
|---|---|---|
| `SPEC_VERSION` | `"0.5.5"` | Current specification version |
| `SUPPORTED_VERSIONS` | Set of strings | All accepted `schema_version` values |
| `CORE_HASH_FIELDS` | Array of strings | Fields included in `core_fingerprint` computation |
| `SOFT_BINDING_THRESHOLD_DEFAULT` | `5` | Default verifier policy threshold |
| `SOFT_BINDING_THRESHOLD_MAX` | `10` | Maximum verifier policy threshold |
| `SIDECAR_SUFFIX` | `".aios.json"` | Sidecar file extension |

---

## Mechanism Registries (§19)

Algorithm support is registry-driven, not hardcoded. Implementations MUST use
registered mechanisms. New mechanisms may be proposed at
`https://aioschema.org/registry/propose`.

### Hash Algorithm Registry (§19.1)
| Token | Digest Length | Status |
|---|---|---|
| `sha256` | 64 hex chars | REQUIRED |
| `sha3-256` | 64 hex chars | OPTIONAL |
| `sha384` | 96 hex chars | OPTIONAL |

### Signature Algorithm Registry (§19.2)
| Token | Status |
|---|---|
| `ed25519` | REQUIRED |

### Soft Binding Algorithm Registry (§19.3)
| Token | Status |
|---|---|
| `pHash-v1` | OPTIONAL |
