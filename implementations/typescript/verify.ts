/**
 * AIOSchema v0.5.5 — Verification procedure (§10)
 */

import * as nodeCrypto from "crypto";
import {
  SUPPORTED_VERSIONS, HASH_REGEX, CORE_HASH_FIELDS, MatchType,
  Manifest, VerificationResult, VerifyOptions, AnchorVerificationError
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
  const softThreshold = Math.min(
    options.softThreshold ?? SOFT_BINDING_THRESHOLD_DEFAULT,
    SOFT_BINDING_THRESHOLD_MAX
  );

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

  // Step 4: creator_id
  if (!/^ed25519-fp-[0-9a-f]{32}$/.test(core.creator_id))
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

  // Step 10: signature (optional)
  let signatureVerified = false;
  if (core.signature && options.publicKey) {
    try {
      const hashStr = Array.isArray(core.hash_original) ? core.hash_original[0] : core.hash_original;
      const hashBytes = Buffer.from(hashStr.split("-")[1], "hex");
      const sig = Buffer.from(core.signature, "base64url");
      const verifyFn = (nodeCrypto as any).createVerify("ed25519");
      verifyFn.update(hashBytes);
      signatureVerified = verifyFn.verify(
        { key: Buffer.from(options.publicKey), format: "der", type: "spki" }, sig
      );
      if (!signatureVerified) warnings.push("Signature verification failed.");
    } catch { warnings.push("Signature verification skipped: crypto error."); }
  } else if (core.signature) {
    warnings.push("Signature present but no public key provided — skipped.");
  }

  // Step 11: manifest_signature (optional)
  let manifestSignatureVerified = false;
  if (core.manifest_signature && options.publicKey) {
    try {
      const mBytes = canonicalManifestBytes(manifest);
      const sig = Buffer.from(core.manifest_signature, "base64url");
      const verifyFn = (nodeCrypto as any).createVerify("ed25519");
      verifyFn.update(mBytes);
      manifestSignatureVerified = verifyFn.verify(
        { key: Buffer.from(options.publicKey), format: "der", type: "spki" }, sig
      );
      if (!manifestSignatureVerified) warnings.push("Manifest signature verification failed.");
    } catch { warnings.push("Manifest signature verification skipped: crypto error."); }
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
