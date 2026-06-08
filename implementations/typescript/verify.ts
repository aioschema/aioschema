// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ovidiu Ancuta
//
// aioschema/typescript v0.5.6 | AIOSchema spec v0.5.6
// https://aioschema.org

import * as nodeCrypto from "crypto";
import {
  SUPPORTED_VERSIONS, HASH_REGEX, CORE_HASH_FIELDS, MatchType,
  Manifest, VerificationResult, VerifyOptions, AnchorVerificationError,
  MAX_EXTENSION_SIZE_BYTES
} from "./types";
import {
  computeHash, parseHash, safeEqual, canonicalJson,
  pHashV1, pHashSimilarity,
  SOFT_BINDING_THRESHOLD_DEFAULT, SOFT_BINDING_THRESHOLD_MAX
} from "./algorithms";
import { canonicalManifestBytes } from "./manifest";

function fail(message: string, extra: Partial<VerificationResult> = {}): VerificationResult {
  return {
    success: false, message,
    matchType: "none" as MatchType,
    signatureVerified: false, manifestSignatureVerified: false,
    anchorVerified: false, warnings: [], ...extra
  };
}

function pass(message: string, extra: Partial<VerificationResult> = {}): VerificationResult {
  return {
    success: true, message,
    matchType: "exact" as MatchType,
    signatureVerified: false, manifestSignatureVerified: false,
    anchorVerified: false, warnings: [], ...extra
  };
}

export async function verifyManifest(
  assetData: Uint8Array,
  manifest: Manifest,
  options: VerifyOptions = {}
): Promise<VerificationResult> {
  const warnings: string[] = [];
  const core = manifest.core;
  const ext = manifest.extensions;
  const softThreshold = Math.min(
    options.softThreshold ?? SOFT_BINDING_THRESHOLD_DEFAULT,
    SOFT_BINDING_THRESHOLD_MAX
  );

  // §6.3 — Extension size limit
  if (ext && Object.keys(ext).length > 0) {
    const extSize = Buffer.byteLength(JSON.stringify(ext), "utf-8");
    if (extSize > MAX_EXTENSION_SIZE_BYTES) {
      return fail(`Extensions size (${extSize} bytes) exceeds limit of ${MAX_EXTENSION_SIZE_BYTES} bytes (§6.3)`);
    }
  }

  // §11.1 — ai_declaration constraint validation
  const aiDecl = ext?.ai_declaration as Record<string, unknown> | undefined;
  if (aiDecl && typeof aiDecl === "object") {
    if (aiDecl.standard_editing === true && aiDecl.disclosure_required === true) {
      return fail(
        "ai_declaration constraint violation: standard_editing is true but " +
        "disclosure_required is also true. Per Article 50.2, standard editing " +
        "does not trigger AI disclosure obligations."
      );
    }
    if (aiDecl.human_reviewed === true && !ext?.["compliance_eu_art50"]) {
      warnings.push(
        "ai_declaration.human_reviewed is true but compliance_eu_art50 " +
        "extension is absent (SHOULD be present per §11.1)"
      );
    }
  }

  // §11.3 — public_key fingerprint cross-check
  let embeddedPublicKey: Uint8Array | null = null;
  const pkB64 = ext?.public_key as string | undefined;
  if (pkB64 && typeof pkB64 === "string") {
    try {
      const pkBytes = Buffer.from(pkB64, "base64");
      if (pkBytes.length !== 32) {
        return fail(`extensions.public_key decoded to ${pkBytes.length} bytes, expected 32 (Ed25519)`);
      }
      // Fingerprint cross-check: SHA-256(pubkey)[:32 hex] must match creator_id
      const fpHash = nodeCrypto.createHash("sha256").update(pkBytes).digest("hex").slice(0, 32);
      const expectedCreatorId = `ed25519-fp-${fpHash}`;
      if (!safeEqual(core.creator_id, expectedCreatorId)) {
        return fail(
          "extensions.public_key fingerprint cross-check failed: " +
          "embedded key does not belong to declared creator_id. " +
          `Expected ed25519-fp derived from key: ${expectedCreatorId}, ` +
          `manifest creator_id: ${core.creator_id}`
        );
      }
      embeddedPublicKey = pkBytes;
    } catch {
      return fail("extensions.public_key is not valid Base64");
    }
  }

  // Step 1: schema_version
  if (!SUPPORTED_VERSIONS.has(core.schema_version)) {
    return fail(`Unsupported schema_version '${core.schema_version}'. Supported: [${[...SUPPORTED_VERSIONS].join(", ")}]`);
  }

  // Step 2: required fields
  const missing = (CORE_HASH_FIELDS as readonly string[]).filter(f => !(f in core));
  if (!("core_fingerprint" in core) && !("hash_schema_block" in core)) missing.push("core_fingerprint");
  if (missing.length > 0) return fail(`Missing required core fields: [${missing.sort().join(", ")}]`);

  // Step 3: asset_id
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(core.asset_id))
    return fail(`Invalid asset_id format: ${core.asset_id}`);

  // Step 4: creator_id — ed25519-fp- fingerprint or anonymous UUID
  if (!/^ed25519-fp-[0-9a-f]{32}$/.test(core.creator_id) &&
      !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(core.creator_id))
    return fail(`Invalid creator_id format: ${core.creator_id}`);

  // Step 5: hash_original
  const hashes = Array.isArray(core.hash_original) ? core.hash_original : [core.hash_original];
  if (hashes.length === 0) return fail("hash_original must not be empty");
  for (const h of hashes) if (!HASH_REGEX.test(h)) return fail(`Invalid hash_original format: ${h}`);

  // Step 6: core_fingerprint
  const cfp = (core.core_fingerprint ?? core.hash_schema_block) as string;
  if (!cfp || !HASH_REGEX.test(cfp)) return fail(`Invalid core_fingerprint format: ${cfp}`);

  // Step 7: exact hash match
  let exactMatch = false;
  for (const hashStr of hashes) {
    const [alg] = parseHash(hashStr);
    if (safeEqual(computeHash(assetData, alg), hashStr)) { exactMatch = true; break; }
  }

  // Step 8: soft binding
  let matchType: MatchType = "none";
  if (exactMatch) {
    matchType = "exact";
  } else {
    const sb = manifest.extensions?.soft_binding as string | undefined;
    if (sb && typeof sb === "string") {
      const sim = pHashSimilarity(pHashV1(assetData), sb);
      if (sim >= softThreshold) {
        matchType = "soft";
        warnings.push(`Soft binding matched at ${(sim*100).toFixed(1)}%.`);
      }
    }
    if (matchType === "none") {
      return fail("Asset hash does not match manifest.", { matchType, warnings });
    }
  }

  // Step 9: core_fingerprint integrity
  const coreForFp: Record<string, unknown> = {};
  for (const f of CORE_HASH_FIELDS) coreForFp[f] = (core as unknown as Record<string,unknown>)[f];
  const [cfpAlg] = parseHash(cfp);
  if (!safeEqual(computeHash(canonicalJson(coreForFp), cfpAlg), cfp)) {
    return fail("Manifest integrity check failed: core_fingerprint mismatch. Core metadata may have been tampered.", { matchType, warnings });
  }

  // Step 10: signature (optional) — §11.3: prefer embedded key if no external key provided
  const verifyKeyRaw = options.publicKey ?? embeddedPublicKey;
  // Pre-compute SPKI-wrapped public key for signature verification
  const SPKI_ED25519_HEADER = Buffer.from([0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00]);
  let pubKeyObj: ReturnType<typeof nodeCrypto.createPublicKey> | null = null;
  if (verifyKeyRaw) {
    const verifyKeySpki = Buffer.concat([SPKI_ED25519_HEADER, Buffer.from(verifyKeyRaw)]);
    pubKeyObj = nodeCrypto.createPublicKey({ key: verifyKeySpki, format: "der", type: "spki" });
  }

  let signatureVerified = false;
  if (core.signature) {
    if (!verifyKeyRaw) {
      return fail("Manifest is signed but no public key was provided (neither externally nor via extensions.public_key).", { matchType, warnings });
    }
    try {
      const sig = Buffer.from(core.signature.replace(/^ed25519-/, ""), "hex");
      const coreBytes = Buffer.from(canonicalJson(coreForFp), "utf-8");
      signatureVerified = nodeCrypto.verify(null, coreBytes, pubKeyObj!, sig);
      if (!signatureVerified) return fail("Core signature verification failed: invalid signature or wrong key.", { matchType, warnings });
    } catch (e) { return fail(`Signature verification error: ${e instanceof Error ? e.message : String(e)}`, { matchType, warnings }); }
  }

  // Step 11: manifest_signature (optional) — §11.3: prefer embedded key
  let manifestSignatureVerified = false;
  if (core.manifest_signature) {
    if (!verifyKeyRaw) {
      return fail("manifest_signature present but no public key was provided (neither externally nor via extensions.public_key).", { matchType, warnings });
    }
    try {
      // Nullify manifest_signature before computing canonical bytes (§5.8)
      const manifestForSig = { core: { ...manifest.core, manifest_signature: null }, extensions: manifest.extensions };
      const mBytes = canonicalJson(manifestForSig);
      const sig = Buffer.from(core.manifest_signature.replace(/^ed25519-/, ""), "hex");

      manifestSignatureVerified = nodeCrypto.verify(null, mBytes, pubKeyObj, sig);
      if (!manifestSignatureVerified) return fail("Manifest signature verification failed: invalid or extensions tampered.", { matchType, warnings });
    } catch (e) { warnings.push(`Manifest signature verification skipped: crypto error: ${e instanceof Error ? e.message : String(e)}`); }
  }

  // Step 12: anchor (optional)
  let anchorVerified = false;
  if (core.anchor_reference) {
    if (options.verifyAnchor && options.anchorResolver) {
      try {
        const record = await options.anchorResolver(core.anchor_reference);
        if (!record) {
          warnings.push("Anchor record not found.");
        } else {
          const rCfp = (record.core_fingerprint ?? (record as Record<string,unknown>).hash_schema_block ?? "") as string;
          anchorVerified = safeEqual(rCfp, cfp) && safeEqual(record.asset_id, core.asset_id);
          if (!anchorVerified) warnings.push("Anchor record fields do not match manifest.");
        }
      } catch (e) { warnings.push(`Anchor verification failed: ${(e as Error).message}`); }
    } else if (options.verifyAnchor) {
      warnings.push("Anchor present but no anchorResolver provided.");
    } else {
      warnings.push("Anchor present but verifyAnchor=false — not checked.");
    }
  }

  return pass(
    matchType === "exact" ? "✓ PASS: Exact hash match" : "✓ PASS: Soft binding match",
    { matchType, signatureVerified, manifestSignatureVerified, anchorVerified, warnings }
  );
}
// -- end aioschema/typescript v0.5.6 | AIOSchema spec v0.5.6 --
