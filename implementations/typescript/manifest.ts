// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ovidiu Ancuta
//
// aioschema/typescript v0.5.6 | AIOSchema spec v0.5.6
// https://aioschema.org

import nodeCrypto from "node:crypto";
import { SPEC_VERSION, CORE_HASH_FIELDS, Manifest, GenerateOptions, AIOSchemaError } from "./types";
import { computeHash, canonicalJson, uuidV7, anonymousCreatorId, pHashV1 } from "./algorithms";

// PKCS#8 DER header for Ed25519 32-byte seed
const PKCS8_ED25519_HEADER = Buffer.from([
  0x30, 0x2e, 0x02, 0x01, 0x01, 0x30, 0x05, 0x06,
  0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20
]);

/**
 * Wrap a raw 32-byte Ed25519 private key seed into a PKCS#8 DER buffer
 * that Node.js crypto can accept.
 */
function pkcs8WrapEd25519Seed(seed: Uint8Array): Buffer {
  if (seed.length !== 32) {
    throw new AIOSchemaError(`Ed25519 seed must be 32 bytes, got ${seed.length}`);
  }
  return Buffer.concat([PKCS8_ED25519_HEADER, Buffer.from(seed)]);
}

/**
 * Sign a message with an Ed25519 private key (raw 32-byte seed).
 * Returns hex string prefixed with "ed25519-".
 */
function signEd25519(message: Uint8Array, privateKeySeed: Uint8Array): string {
  const pkcs8Key = pkcs8WrapEd25519Seed(privateKeySeed);
  const keyObj = nodeCrypto.createPrivateKey({ key: pkcs8Key, format: "der", type: "pkcs8" });
  const sig = nodeCrypto.sign(null, Buffer.from(message), keyObj);
  return "ed25519-" + sig.toString("hex");
}

/**
 * Derive creator_id from an Ed25519 public key (raw 32 bytes or KeyObject).
 */
export function creatorIdFromPublicKey(publicKey: Uint8Array | nodeCrypto.KeyObject): string {
  let pubRaw: Uint8Array;
  if (publicKey instanceof Uint8Array || Buffer.isBuffer(publicKey)) {
    pubRaw = publicKey;
  } else {
    pubRaw = (publicKey as nodeCrypto.KeyObject).export({ type: "spki", format: "der" }).slice(-32);
  }
  const fpHash = nodeCrypto.createHash("sha256").update(pubRaw).digest("hex").slice(0, 32);
  return `ed25519-fp-${fpHash}`;
}

/**
 * Derive the Ed25519 public key (raw 32 bytes) from a private key seed.
 */
function publicKeyFromSeed(seed: Uint8Array): Uint8Array {
  const pkcs8Key = pkcs8WrapEd25519Seed(seed);
  const keyObj = nodeCrypto.createPrivateKey({ key: pkcs8Key, format: "der", type: "pkcs8" });
  const pubKeyObj = nodeCrypto.createPublicKey(keyObj);
  return pubKeyObj.export({ type: "spki", format: "der" }).slice(-32);
}

export function generateManifest(data: Uint8Array, opts: GenerateOptions = {}): Manifest {
  const algs = opts.algorithms ?? ["sha256"];
  for (const a of algs) { try { computeHash(new Uint8Array(0), a); } catch { throw new AIOSchemaError(`Unsupported algorithm: ${a}`); } }

  const hashOriginal = algs.length === 1 ? computeHash(data, algs[0]) : algs.map(a => computeHash(data, a));
  let creatorId = opts.creatorId ?? anonymousCreatorId();

  // If privateKey provided, derive creator_id from public key
  let pubKeyRaw: Uint8Array | null = null;
  if (opts.privateKey) {
    pubKeyRaw = publicKeyFromSeed(opts.privateKey);
    const derivedCid = creatorIdFromPublicKey(pubKeyRaw);
    if (!opts.creatorId) {
      creatorId = derivedCid;
    }
  }

  const coreForFp: Record<string, unknown> = {
    asset_id: uuidV7(),
    schema_version: opts.schemaVersion ?? SPEC_VERSION,
    creation_timestamp: new Date().toISOString().replace(/\.\d{3}Z$/, "Z"),
    hash_original: hashOriginal,
    creator_id: creatorId,
  };
  const fpAlg = algs[0].startsWith("sha384") ? "sha384" : "sha256";
  const cfp = computeHash(canonicalJson(coreForFp), fpAlg);
  const core: Record<string, unknown> = { ...coreForFp, core_fingerprint: cfp };

  // Sign core fields if private key provided
  if (opts.privateKey) {
    const coreSig = signEd25519(canonicalJson(coreForFp), opts.privateKey);
    core.signature = coreSig;
  }

  if (opts.anchorReference) core.anchor_reference = opts.anchorReference;
  if (opts.previousVersionAnchor) core.previous_version_anchor = opts.previousVersionAnchor;

  const extensions: Record<string, unknown> = { soft_binding: pHashV1(data), ...(opts.extensions ?? {}) };

  // Manifest signature if private key provided
  if (opts.privateKey) {
    const manifestForSig = { core: { ...core, manifest_signature: null }, extensions };
    const manifestBytes = canonicalJson(manifestForSig);
    core.manifest_signature = signEd25519(manifestBytes, opts.privateKey);
  }

  return { core: core as any, extensions };
}

export function manifestToJson(m: Manifest, indent = 2): string { return JSON.stringify(m, null, indent); }
export function manifestFromJson(s: string): Manifest {
  const o = JSON.parse(s);
  if (!o.core) throw new AIOSchemaError("Invalid manifest: missing core");
  return { core: o.core, extensions: o.extensions ?? {} };
}
export function canonicalManifestBytes(m: Manifest): Buffer { return canonicalJson(m); }
// -- end aioschema/typescript v0.5.6 | AIOSchema spec v0.5.6 --
