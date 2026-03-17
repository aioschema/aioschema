"use strict";
/**
 * AIOSchema v0.5.5 — Node.js Reference Implementation
 * =====================================================
 * Pure CommonJS. Zero external dependencies.
 * Requires Node.js >= 18.
 *
 * Spec: https://aioschema.org
 */

const crypto = require("node:crypto");
const fs     = require("node:fs");
const path   = require("node:path");

// ── Spec constants ────────────────────────────────────────────────────────────

const SPEC_VERSION = "0.5.5";

const SUPPORTED_VERSIONS = new Set([
  "0.1", "0.2", "0.3", "0.3.1", "0.4", "0.5", "0.5.1", "0.5.5",
]);

const CORE_HASH_FIELDS = [
  "asset_id",
  "schema_version",
  "creation_timestamp",
  "hash_original",
  "creator_id",
];

const DEFAULT_HASH_ALG             = "sha256";
const SOFT_BINDING_THRESHOLD_DEFAULT = 5;
const SOFT_BINDING_THRESHOLD_MAX     = 10;
const SIDECAR_SUFFIX               = ".aios.json";
const DEFAULT_MAX_FILE_BYTES       = 2 * 1024 ** 3; // 2 GB

// ── Regex patterns ────────────────────────────────────────────────────────────

const HASH_REGEX     = /^(sha256|sha3-256)-[0-9a-f]{64}$|^sha384-[0-9a-f]{96}$/;
const SIG_PATTERN    = /^ed25519-[0-9a-f]{128}$/;
const ANCHOR_PATTERN = /^aios-anchor:[a-z0-9_-]+:[a-zA-Z0-9_-]+$/;
const TS_PATTERN     = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;
const CREATOR_ATTR   = /^ed25519-fp-[0-9a-f]{32}$/;
const UUID_PATTERN   = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

// ── Error types ───────────────────────────────────────────────────────────────

class AnchorVerificationError extends Error {
  constructor(message) {
    super(message);
    this.name = "AnchorVerificationError";
  }
}

// ── UUID v7 ───────────────────────────────────────────────────────────────────

let _uuidLastMs = 0n;
let _uuidSeq    = 0;

function uuidV7() {
  const tsMs = BigInt(Date.now());
  if (tsMs === _uuidLastMs) {
    _uuidSeq = (_uuidSeq + 1) & 0x0FFF;
  } else {
    _uuidSeq    = crypto.randomBytes(2).readUInt16BE(0) & 0x0FFF;
    _uuidLastMs = tsMs;
  }
  const randB = crypto.randomBytes(8);
  // Clear variant bits, set variant 10xx
  randB[0] = (randB[0] & 0x3F) | 0x80;

  const hi = (tsMs << 16n) | (0x7n << 12n) | BigInt(_uuidSeq);
  const buf = Buffer.alloc(16);
  buf.writeBigUInt64BE(hi, 0);
  buf.writeBigUInt64BE(
    (BigInt(randB.readUInt32BE(0)) << 32n) | BigInt(randB.readUInt32BE(4)),
    8
  );
  // Force variant bits on byte 8
  buf[8] = (buf[8] & 0x3F) | 0x80;

  const hex = buf.toString("hex");
  return `${hex.slice(0,8)}-${hex.slice(8,12)}-${hex.slice(12,16)}-${hex.slice(16,20)}-${hex.slice(20)}`;
}

// ── Hash computation ──────────────────────────────────────────────────────────

function computeHash(data, algorithm = DEFAULT_HASH_ALG) {
  switch (algorithm) {
    case "sha256":
    case "sha384":
    case "sha3-256":
      return `${algorithm}-${crypto.createHash(algorithm).update(data).digest("hex")}`;
    default:
      throw new Error(`Unsupported hash algorithm: ${algorithm}`);
  }
}

/** Alias matching test suite import name */
const parseHash = parseHashPrefix;

function parseHashPrefix(value) {
  if (!HASH_REGEX.test(value)) {
    throw new Error(
      `Invalid hash value ${JSON.stringify(value)}: ` +
      `expected (sha256|sha3-256)-<64hex> or sha384-<96hex>`
    );
  }
  if (value.startsWith("sha3-256-")) return ["sha3-256", value.slice(9)];
  const dash = value.indexOf("-");
  return [value.slice(0, dash), value.slice(dash + 1)];
}

// ── Canonical JSON ────────────────────────────────────────────────────────────

function canonicalJson(obj) {
  if (obj === null || typeof obj !== "object") return JSON.stringify(obj);
  if (Array.isArray(obj)) return "[" + obj.map(canonicalJson).join(",") + "]";
  const keys = Object.keys(obj).sort();
  return "{" + keys.map(k => JSON.stringify(k) + ":" + canonicalJson(obj[k])).join(",") + "}";
}

function canonicalBytes(obj) {
  return Buffer.from(canonicalJson(obj), "utf8");
}

/**
 * Canonical bytes for manifest_signature — manifest_signature set to null (§5.8).
 * Accepts either a plain manifest object or a Manifest-like {core, extensions} object.
 */
function canonicalManifestBytes(manifest) {
  const m = typeof manifest.toDict === "function" ? manifest.toDict() : manifest;
  const copy = JSON.parse(JSON.stringify(m));
  copy.core.manifest_signature = null;
  return canonicalBytes(copy);
}

// ── Timing-safe comparison ────────────────────────────────────────────────────

function safeEqual(a, b) {
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(Buffer.from(a, "utf8"), Buffer.from(b, "utf8"));
}

// ── Core fingerprint helpers ──────────────────────────────────────────────────

function coreFieldBytes(core) {
  const subset = {};
  for (const field of CORE_HASH_FIELDS) {
    if (Object.prototype.hasOwnProperty.call(core, field)) subset[field] = core[field];
  }
  return canonicalBytes(subset);
}

function effectiveCoreFingerprint(core) {
  return core.core_fingerprint ?? core.hash_schema_block ?? null;
}

// ── Ed25519 key operations ────────────────────────────────────────────────────

/**
 * Generate an Ed25519 keypair.
 * Returns { privateKey, publicKey } as Node KeyObject instances.
 */
function generateKeypair() {
  return crypto.generateKeyPairSync("ed25519");
}

/**
 * Sign message with an Ed25519 private key (KeyObject).
 * Returns "ed25519-<128hex>" string.
 */
function signEd25519(message, privateKey) {
  const sig = crypto.sign(null, message, privateKey);
  return `ed25519-${sig.toString("hex")}`;
}

/**
 * Verify an ed25519-<hex> signature string.
 * publicKey may be a KeyObject or raw 32-byte Buffer/Uint8Array (SPKI DER or raw).
 */
function verifyEd25519(message, sigHex, publicKey) {
  const sigBytes = Buffer.from(sigHex.slice("ed25519-".length), "hex");
  let keyObj;
  if (publicKey && typeof publicKey === "object" && typeof publicKey.export === "function") {
    // Already a KeyObject
    keyObj = publicKey;
  } else {
    // Raw bytes — wrap in SPKI DER
    const rawBytes = Buffer.isBuffer(publicKey) ? publicKey : Buffer.from(publicKey);
    keyObj = crypto.createPublicKey({
      key:    Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), rawBytes]),
      format: "der",
      type:   "spki",
    });
  }
  return crypto.verify(null, message, keyObj, sigBytes);
}

// ── Creator ID (§5.7) ─────────────────────────────────────────────────────────

function creatorIdAnonymous() {
  return uuidV7();
}

/**
 * Derive attributed creator_id from a public key.
 * Accepts a KeyObject, DER SPKI Buffer, or raw 32-byte Buffer.
 * Returns "ed25519-fp-<32hex>".
 */
function creatorIdFromPublicKey(publicKey) {
  let rawBytes;
  if (publicKey && typeof publicKey.export === "function") {
    // KeyObject — export raw bytes
    rawBytes = publicKey.export({ type: "spki", format: "der" }).slice(-32);
  } else {
    const buf = Buffer.isBuffer(publicKey) ? publicKey : Buffer.from(publicKey);
    // If DER SPKI (44 bytes for Ed25519), take last 32
    rawBytes = buf.length === 44 ? buf.slice(12) : buf.slice(-32);
  }
  const fp = crypto.createHash("sha256").update(rawBytes).digest("hex").slice(0, 32);
  return `ed25519-fp-${fp}`;
}

function validateCreatorId(cid) {
  if (CREATOR_ATTR.test(cid)) return; // attributed — valid
  if (UUID_PATTERN.test(cid)) return;  // anonymous UUID — valid
  throw new Error(`Invalid creator_id: ${JSON.stringify(cid)}`);
}

// ── Sidecar I/O (§8.2) ───────────────────────────────────────────────────────

function sidecarPath(assetPath) {
  return assetPath + SIDECAR_SUFFIX;
}

function saveSidecar(assetPath, manifest) {
  const sp   = sidecarPath(assetPath);
  const data = typeof manifest.toDict === "function"
    ? manifest.toDict()
    : manifest;
  fs.writeFileSync(sp, JSON.stringify(data, null, 2), "utf8");
  return sp;
}

function loadSidecar(assetPath) {
  const sp = sidecarPath(assetPath);
  if (!fs.existsSync(sp)) throw new Error(`No sidecar found at: ${sp}`);
  return JSON.parse(fs.readFileSync(sp, "utf8"));
}

// ── Manifest class ────────────────────────────────────────────────────────────

class Manifest {
  constructor(core, extensions = {}) {
    this.core       = core;
    this.extensions = extensions;
  }
  toDict() {
    return { core: { ...this.core }, extensions: { ...this.extensions } };
  }
  toJsonString(indent = 2) {
    return JSON.stringify(this.toDict(), null, indent);
  }
  toJSON() {
    return this.toDict();
  }
  static fromDict(data) {
    return new Manifest(data.core ?? {}, data.extensions ?? {});
  }
}

// ── Generate manifest ─────────────────────────────────────────────────────────

/**
 * Generate an AIOSchema v0.5.5 manifest.
 *
 * @param {string} filePath  — path to the asset file
 * @param {object} [opts]
 * @param {object} [opts.privateKey]            — Ed25519 KeyObject (for signing)
 * @param {string|string[]} [opts.hashAlgorithms] — default "sha256"
 * @param {string} [opts.creatorId]             — override creator_id
 * @param {string} [opts.anchorRef]             — anchor_reference URI
 * @param {string} [opts.previousVersionAnchor] — previous_version_anchor URI
 * @param {object} [opts.extensions]            — merged into extensions block
 * @param {boolean} [opts.saveSidecar]          — write .aios.json alongside asset
 * @param {number} [opts.maxFileBytes]          — file size guard
 * @returns {Manifest}
 */
function generateManifest(filePath, opts = {}) {
  // File I/O
  if (!fs.existsSync(filePath)) throw new Error(`Asset not found: ${filePath}`);
  const stat = fs.statSync(filePath);
  const maxBytes = opts.maxFileBytes ?? DEFAULT_MAX_FILE_BYTES;
  if (stat.size > maxBytes) throw new Error(`File ${stat.size} bytes exceeds maxFileBytes=${maxBytes}`);
  const fileBytes = fs.readFileSync(filePath);

  // Validate anchor formats (§9.1)
  if (opts.anchorRef != null && !ANCHOR_PATTERN.test(opts.anchorRef)) {
    throw new Error(`anchorRef ${JSON.stringify(opts.anchorRef)} must match 'aios-anchor:<svc>:<id>'`);
  }
  if (opts.previousVersionAnchor != null && !ANCHOR_PATTERN.test(opts.previousVersionAnchor)) {
    throw new Error(`previousVersionAnchor ${JSON.stringify(opts.previousVersionAnchor)} must match 'aios-anchor:<svc>:<id>'`);
  }

  // Hash algorithms
  const rawAlgs = opts.hashAlgorithms ?? DEFAULT_HASH_ALG;
  const algList = Array.isArray(rawAlgs) ? rawAlgs : [rawAlgs];
  for (const alg of algList) {
    if (!["sha256", "sha384", "sha3-256"].includes(alg)) {
      throw new Error(`Unsupported hash algorithm: ${alg}`);
    }
  }

  // Compute hashes (§5.5)
  const hashes = algList.map(alg => computeHash(fileBytes, alg));
  const hashOriginal = hashes.length === 1 ? hashes[0] : hashes;

  // Creator ID
  let cid;
  if (opts.creatorId != null) {
    validateCreatorId(opts.creatorId);
    cid = opts.creatorId;
  } else if (opts.privateKey != null) {
    cid = creatorIdFromPublicKey(opts.privateKey.asymmetricKeyType === "ed25519"
      ? crypto.createPublicKey(opts.privateKey)
      : opts.privateKey);
  } else {
    cid = creatorIdAnonymous();
  }

  // Timestamp
  const creationTimestamp = new Date().toISOString().replace(/\.\d{3}Z$/, "Z");

  // Core block (without core_fingerprint — bootstrap rule §5.6)
  const coreForFp = {
    asset_id:           uuidV7(),
    schema_version:     SPEC_VERSION,
    creation_timestamp: creationTimestamp,
    hash_original:      hashOriginal,
    creator_id:         cid,
  };

  // core_fingerprint (§5.6) — hash of canonical core fields using first algorithm
  const cfpBytes = coreFieldBytes(coreForFp);
  const coreFingerprint = computeHash(cfpBytes, algList[0]);

  // Core signature (§5.1)
  let signatureHex = null;
  if (opts.privateKey != null) {
    signatureHex = signEd25519(cfpBytes, opts.privateKey);
  }

  // Assemble core (manifest_signature comes after extensions are known)
  const core = {
    ...coreForFp,
    core_fingerprint:        coreFingerprint,
    signature:               signatureHex,
    manifest_signature:      null,
    anchor_reference:        opts.anchorRef ?? null,
    previous_version_anchor: opts.previousVersionAnchor ?? null,
  };

  // Extensions
  const ext = {
    software:         "AIOSchema-JS-Ref-v0.5.5",
    compliance_level: opts.privateKey != null ? 2 : 1,
    ...(opts.extensions ?? {}),
  };

  // Manifest signature (§5.8) — signs entire manifest (core + extensions)
  if (opts.privateKey != null) {
    const manifestObj = { core, extensions: ext };
    const mBytes = canonicalManifestBytes(manifestObj);
    core.manifest_signature = signEd25519(mBytes, opts.privateKey);
  }

  const manifest = new Manifest(core, ext);

  if (opts.saveSidecar) saveSidecar(filePath, manifest);

  return manifest;
}

// ── Verify manifest (§10) ─────────────────────────────────────────────────────

/**
 * Execute the AIOSchema §10 verification procedure.
 *
 * First argument may be:
 *   - a file path string (asset read from disk)
 *   - a Buffer/Uint8Array (raw asset bytes)
 *
 * Second argument may be:
 *   - a plain manifest object {core, extensions}
 *   - a Manifest instance
 *
 * @param {string|Buffer|Uint8Array} assetOrPath
 * @param {object|Manifest}          manifest
 * @param {object}                   [opts]
 * @param {object}  [opts.publicKey]            — Ed25519 KeyObject or raw 32-byte Buffer
 * @param {number}  [opts.softBindingThreshold] — default 5
 * @param {boolean} [opts.verifyAnchor]         — enable Level 3 anchor check
 * @param {Function}[opts.anchorResolver]       — async (ref) => record | null
 * @returns {Promise<VerificationResult>}
 */
async function verifyManifest(assetOrPath, manifest, opts = {}) {
  // Resolve asset bytes
  let assetData;
  if (typeof assetOrPath === "string") {
    if (!fs.existsSync(assetOrPath)) {
      return fail(`Asset not found: ${assetOrPath}`);
    }
    assetData = fs.readFileSync(assetOrPath);
  } else {
    assetData = Buffer.isBuffer(assetOrPath) ? assetOrPath : Buffer.from(assetOrPath);
  }

  // Normalise manifest
  const mObj = typeof manifest.toDict === "function" ? manifest.toDict() : manifest;
  const core  = mObj.core ?? {};
  const ext   = mObj.extensions ?? {};

  const warns = [];
  const threshold = Math.min(
    opts.softBindingThreshold ?? SOFT_BINDING_THRESHOLD_DEFAULT,
    SOFT_BINDING_THRESHOLD_MAX
  );

  // §10 Step 1 — Schema version
  if (!SUPPORTED_VERSIONS.has(core.schema_version)) {
    return fail(`Unsupported schema_version ${JSON.stringify(core.schema_version)}; ` +
      `supported: ${[...SUPPORTED_VERSIONS].join(", ")}`);
  }

  // §10 Step 2 — Required fields
  if (!core.asset_id)           return fail("missing required field: asset_id");
  if (!core.creation_timestamp) return fail("missing required field: creation_timestamp");
  if (!core.creator_id)         return fail("missing required field: creator_id");
  const cfpVal = effectiveCoreFingerprint(core);
  if (!cfpVal)                  return fail("missing required field: core_fingerprint");
  const hoList = hashOriginalList(core.hash_original);
  if (hoList.length === 0)      return fail("missing required field: hash_original");

  // §10 Step 3 — Timestamp format
  if (!TS_PATTERN.test(core.creation_timestamp)) {
    return fail(`creation_timestamp ${JSON.stringify(core.creation_timestamp)} ` +
      `is not a valid UTC ISO-8601 timestamp (must end with Z)`);
  }

  // §10 Step 4 — creator_id format
  if (!CREATOR_ATTR.test(core.creator_id) && !UUID_PATTERN.test(core.creator_id)) {
    return fail(`creator_id ${JSON.stringify(core.creator_id)} has invalid format`);
  }

  // §10 Step 5 — hash_original format
  for (const h of hoList) {
    if (!HASH_REGEX.test(h)) return fail(`hash_original value ${JSON.stringify(h)} has invalid format`);
  }

  // §10 Step 6 — Canonical core bytes
  const cfBytes = coreFieldBytes(core);

  // §10 Step 7 — Content hash (hard match)
  let hardMatch = false;
  let supportedFound = false;
  for (const h of hoList) {
    let alg;
    try { [alg] = parseHashPrefix(h); } catch { warns.push(`skipping malformed hash ${h}`); continue; }
    supportedFound = true;
    let computed;
    try { computed = computeHash(assetData, alg); } catch { warns.push(`algorithm ${alg} not supported, skipping`); continue; }
    if (safeEqual(computed, h)) { hardMatch = true; break; }
  }

  if (!supportedFound) return fail("no supported hash algorithm found in hash_original; cannot verify content");

  // §10 Step 8 — Soft binding (not implemented; warn if present)
  let softMatch = false;
  if (!hardMatch && ext.soft_binding) {
    warns.push(
      `soft_binding present but not evaluated ` +
      `(image processing not available in this implementation; policy threshold=${threshold})`
    );
  }

  // §10 Step 9
  if (!hardMatch && !softMatch) {
    return fail("content mismatch: hash did not match asset. Asset may be tampered or replaced.");
  }

  const matchType = hardMatch ? "hard" : "soft";

  // §10 Step 10 — core_fingerprint integrity
  let cfpAlg;
  try { [cfpAlg] = parseHashPrefix(cfpVal); }
  catch (e) { return { ...fail(`core_fingerprint has invalid format: ${e.message}`), match_type: matchType }; }
  const computedCfp = computeHash(cfBytes, cfpAlg);
  if (!safeEqual(computedCfp, cfpVal)) {
    return {
      ...fail("manifest integrity check failed: core_fingerprint mismatch. Core metadata may have been tampered."),
      match_type: matchType,
    };
  }

  // §10 Step 11 — Core signature
  let signatureVerified = false;
  if (core.signature != null) {
    if (!SIG_PATTERN.test(core.signature)) {
      return { ...fail("signature has invalid format; expected ed25519-<128hex>"), match_type: matchType };
    }
    if (!opts.publicKey) {
      return { ...fail("manifest is signed but no public key was provided"), match_type: matchType };
    }
    if (!verifyEd25519(cfBytes, core.signature, opts.publicKey)) {
      return { ...fail("core signature verification failed: invalid signature or wrong key"), match_type: matchType };
    }
    signatureVerified = true;
  }

  // §10 Step 12 — Manifest signature
  let manifestSigVerified = false;
  if (core.manifest_signature != null) {
    if (!SIG_PATTERN.test(core.manifest_signature)) {
      return { ...fail("manifest_signature has invalid format; expected ed25519-<128hex>"), match_type: matchType };
    }
    if (!opts.publicKey) {
      return { ...fail("manifest_signature present but no public key was provided"), match_type: matchType };
    }
    const mBytes = canonicalManifestBytes(mObj);
    if (!verifyEd25519(mBytes, core.manifest_signature, opts.publicKey)) {
      return { ...fail("manifest signature verification failed: invalid or extensions tampered"), match_type: matchType };
    }
    manifestSigVerified = true;
  }

  // §10 Step 13 — Anchor verification
  let anchorChecked = false;
  let anchorVerified = false;
  const anchor = core.anchor_reference;
  if (anchor) {
    if (opts.verifyAnchor && opts.anchorResolver) {
      anchorChecked = true;
      try {
        const record = await opts.anchorResolver(anchor);
        if (!record) {
          warns.push(`anchor record not found: ${JSON.stringify(anchor)}`);
        } else {
          const idMatch  = safeEqual(record.asset_id,         core.asset_id);
          const cfpMatch = safeEqual(record.core_fingerprint, cfpVal);
          if (idMatch && cfpMatch) {
            anchorVerified = true;
          } else {
            warns.push(`anchor record mismatch for ${JSON.stringify(anchor)}. Asset may have been re-signed.`);
          }
        }
      } catch (e) {
        warns.push(`anchor verification error: ${e.message}`);
      }
    } else {
      warns.push(
        `anchor_reference present (${JSON.stringify(anchor)}) but not verified. ` +
        `Pass verifyAnchor=true and anchorResolver= for Level 3 compliance.`
      );
    }
  }

  // §10 Step 14 — Success
  const contentDesc = softMatch ? "perceptual (soft)" : "bit-exact";
  const sigDesc = signatureVerified && manifestSigVerified
    ? "core + manifest signatures verified"
    : signatureVerified ? "core signature verified" : "unsigned";

  return {
    success:                     true,
    message:                     `Verified: ${contentDesc} content match, ${sigDesc}. Provenance intact.`,
    match_type:                  matchType,
    signature_verified:          signatureVerified,
    manifest_signature_verified: manifestSigVerified,
    anchor_checked:              anchorChecked,
    anchor_verified:             anchorVerified,
    warnings:                    warns,
  };
}

// ── RFC 3161 stubs (§9, §16.4) ────────────────────────────────────────────────

/**
 * Submit a core_fingerprint to an RFC 3161 TSA.
 * Returns { anchor_reference, tsr_bytes, tsa_url, verified, message }.
 * In this reference implementation, network calls are not made by default.
 * Pass tsa_url to actually submit (requires network access).
 */
async function anchorRfc3161(coreFingerprint, tsaUrl = "https://freetsa.org/tsr", outPath = null) {
  const [, hashHex] = coreFingerprint.split("-").slice(0, 1).concat(coreFingerprint.slice(coreFingerprint.indexOf("-") + 1));
  // Return stub — actual TSA submission requires http(s) client
  return {
    anchor_reference: `aios-anchor:rfc3161:${hashHex.slice(0, 32)}`,
    tsr_bytes:        null,
    tsa_url:          tsaUrl,
    verified:         false,
    message:          "RFC 3161 submission not available in this environment",
  };
}

/**
 * Verify an RFC 3161 TSR buffer against a core_fingerprint.
 * Returns { verified, message }.
 */
function verifyRfc3161(tsrBytes, coreFingerprint) {
  if (!tsrBytes || tsrBytes.length < 10) {
    return { verified: false, message: "TSR too short or empty" };
  }
  if (tsrBytes[0] !== 0x30) {
    return { verified: false, message: "TSR does not appear to be valid DER" };
  }
  const [, hashHex] = [null, coreFingerprint.slice(coreFingerprint.indexOf("-") + 1)];
  const hashBytes = Buffer.from(hashHex, "hex");
  const verified  = tsrBytes.includes(hashBytes);
  return {
    verified,
    message: verified
      ? "Hash confirmed present in TSR — RFC 3161 timestamp valid"
      : "Hash not found in TSR — verification failed",
  };
}

// ── Internal helpers ──────────────────────────────────────────────────────────

function fail(message) {
  return {
    success:                     false,
    message,
    match_type:                  null,
    signature_verified:          false,
    manifest_signature_verified: false,
    anchor_checked:              false,
    anchor_verified:             false,
    warnings:                    [],
  };
}

function hashOriginalList(hashOriginal) {
  if (!hashOriginal) return [];
  if (Array.isArray(hashOriginal)) return hashOriginal;
  return [hashOriginal];
}

// ── Exports ───────────────────────────────────────────────────────────────────

module.exports = {
  // Manifest generation and verification
  generateManifest,
  verifyManifest,
  Manifest,

  // Key operations
  generateKeypair,
  signEd25519,
  verifyEd25519,

  // Creator ID
  creatorIdAnonymous,
  creatorIdFromPublicKey,
  validateCreatorId,

  // Hashing
  computeHash,
  parseHashPrefix,
  parseHash: parseHashPrefix,  // alias

  // Canonical serialization
  canonicalJson,
  canonicalBytes,
  canonicalManifestBytes,
  coreFieldBytes,
  effectiveCoreFingerprint,

  // Timing-safe comparison
  safeEqual,

  // Sidecar I/O
  sidecarPath,
  saveSidecar,
  loadSidecar,

  // UUID
  uuidV7,

  // RFC 3161
  anchorRfc3161,
  verifyRfc3161,

  // Error types
  AnchorVerificationError,

  // Constants
  SPEC_VERSION,
  SUPPORTED_VERSIONS,
  CORE_HASH_FIELDS,
  DEFAULT_HASH_ALG,
  SOFT_BINDING_THRESHOLD_DEFAULT,
  SOFT_BINDING_THRESHOLD_MAX,
  SIDECAR_SUFFIX,

  // Patterns
  HASH_REGEX,
  SIG_PATTERN,
  ANCHOR_PATTERN,
  TS_PATTERN,
  CREATOR_ATTR,
  UUID_PATTERN,
};
