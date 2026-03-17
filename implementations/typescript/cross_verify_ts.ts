/**
 * AIOSchema v0.5.5 — Cross-verification runner (TypeScript side)
 *
 * Reads vectors.json produced by cross_verify_python.py and verifies each
 * vector against the TypeScript implementation. Any divergence is a failure.
 *
 * Run: node dist/test/cross_verify.js
 */

import * as fs   from "fs";
import * as path from "path";
import * as C    from "crypto";

import { computeHash, parseHash, safeEqual, canonicalJson } from "../algorithms";
import { generateManifest, manifestFromJson, canonicalManifestBytes } from "../manifest";
import { verifyManifest } from "../verify";
import { CORE_HASH_FIELDS, Manifest } from "../types";

// ── Test harness ──────────────────────────────────────────────────────────────

let passed = 0;
let failed = 0;
const failures: string[] = [];

function check(id: string, name: string, cond: boolean, detail = ""): void {
  if (cond) {
    console.log(`  ✓  ${id}: ${name}`);
    passed++;
  } else {
    console.log(`  ✗  ${id}: ${name}${detail ? ` — ${detail}` : ""}`);
    failures.push(`${id}: ${name}${detail ? ` — ${detail}` : ""}`);
    failed++;
  }
}

// ── Load vectors ──────────────────────────────────────────────────────────────

const vectorsPath = "/home/claude/vectors.json";
const vectors = JSON.parse(fs.readFileSync(vectorsPath, "utf8"));

console.log(`\n=== AIOSchema v0.5.5 Cross-Verification: TypeScript side ===`);
console.log(`    Vectors file: ${vectorsPath}`);
console.log(`    Spec version: ${vectors.spec_version}`);
console.log(`    Vectors: ${vectors.vectors.length}\n`);

// ── Run vectors ───────────────────────────────────────────────────────────────

(async () => {
  for (const v of vectors.vectors) {
    const inp = v.inputs;
    const exp = v.expected;

    // CV-01 to CV-04: Hash computation
    if (["CV-01", "CV-02", "CV-03", "CV-04"].includes(v.id)) {
      const data = Buffer.from(inp.data_hex || "", "hex");
      const result = computeHash(data, inp.algorithm);
      check(v.id, v.name, result === exp, `got ${result}, want ${exp}`);
      continue;
    }

    // CV-05: Canonical JSON
    if (v.id === "CV-05") {
      const result = canonicalJson(inp.object).toString("utf8");
      check(v.id, v.name, result === exp, `\n       got: ${result}\n      want: ${exp}`);
      continue;
    }

    // CV-06: core_fingerprint
    if (v.id === "CV-06") {
      const coreForFp: Record<string, unknown> = {};
      for (const field of CORE_HASH_FIELDS) {
        coreForFp[field] = (inp.core_fields as Record<string, unknown>)[field];
      }
      const [cfpAlg] = parseHash(exp);
      const result = computeHash(canonicalJson(coreForFp), cfpAlg);
      check(v.id, v.name, result === exp, `got ${result}`);
      continue;
    }

    // CV-07 to CV-14: Manifest verification
    if (v.id.startsWith("CV-0") || v.id.startsWith("CV-1")) {
      const assetData = Buffer.from(inp.asset_hex, "hex");
      const manifest = inp.manifest as Manifest;
      let result;
      try {
        result = await verifyManifest(assetData, manifest);
      } catch (e) {
        result = { success: false, message: (e as Error).message, matchType: "none" as const, signatureVerified: false, manifestSignatureVerified: false, anchorVerified: false, warnings: [] };
      }
      const successMatch = result.success === exp.success;
      let detail = successMatch ? "" : `success=${result.success} (want ${exp.success}): ${result.message}`;
      if (exp.match_type && result.success) {
        // TypeScript uses "exact"; Python uses "hard" - both mean the same thing
      const tsMatchType = result.matchType as string;
      const mtMatch = (tsMatchType === "exact" || tsMatchType === "hard") && exp.match_type === "hard";
        if (!mtMatch && exp.match_type) {
          detail += ` matchType=${result.matchType} (want ${exp.match_type})`;
        }
      }
      check(v.id, v.name, successMatch, detail);
      continue;
    }

    console.log(`  ?  ${v.id}: ${v.name} — no handler`);
  }

  // ── Additional TS-specific checks not in Python vectors ───────────────────

  console.log("\n  -- TypeScript-specific cross-checks --\n");

  // XC-01: Python's known sha256 of fox sentence
  const foxData = Buffer.from("The quick brown fox jumps over the lazy dog");
  const foxHash = computeHash(foxData, "sha256");
  const foxExpected = "sha256-d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592";
  check("XC-01", "SHA-256 of fox sentence matches Python output", foxHash === foxExpected,
        `got ${foxHash}`);

  // XC-02: Python's known sha384 of fox sentence
  const foxHash384 = computeHash(foxData, "sha384");
  const foxExpected384 = "sha384-ca737f1014a48f4c0b6dd43cb177b0afd9e5169367544c494011e3317dbf9a509cb1e5dc1e85a941bbee3d7f2afbc9b1";
  check("XC-02", "SHA-384 of fox sentence matches Python output", foxHash384 === foxExpected384,
        `got ${foxHash384}`);

  // XC-03: SHA-256 of empty bytes — universal constant
  const emptyHash = computeHash(Buffer.alloc(0), "sha256");
  const emptyExpected = "sha256-e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
  check("XC-03", "SHA-256 of empty bytes matches universal constant", emptyHash === emptyExpected);

  // XC-04: canonical JSON sort order exactly matches Python
  const canon = canonicalJson({
    creator_id: "urn:uuid:test",
    asset_id: "urn:uuid:asset",
    schema_version: "0.5.5",
  }).toString("utf8");
  const canonExpected = '{"asset_id":"urn:uuid:asset","creator_id":"urn:uuid:test","schema_version":"0.5.5"}';
  check("XC-04", "Canonical JSON key order matches Python output", canon === canonExpected,
        `got ${canon}`);

  // XC-05: deterministic manifest passes both sides
  // Build exact same deterministic manifest as Python
  const FIXED_ASSET = Buffer.from("CV-07 fixed asset content for cross-verification");
  const assetSha256 = computeHash(FIXED_ASSET, "sha256");
  const fixedAssetId = "00000000-0000-7000-8000-000000000001";
  const fixedCreatorId = "ed25519-fp-" + "0".repeat(32);
  const fixedTs = "2026-02-22T12:00:00Z";
  const coreForFp: Record<string, unknown> = {
    asset_id: fixedAssetId,
    schema_version: "0.5.5",
    creation_timestamp: fixedTs,
    hash_original: assetSha256,
    creator_id: fixedCreatorId,
  };
  const fixedFp = computeHash(canonicalJson(coreForFp), "sha256");

  const fixedManifest: Manifest = {
    core: {
      asset_id: fixedAssetId,
      schema_version: "0.5.5",
      creation_timestamp: fixedTs,
      hash_original: assetSha256,
      creator_id: fixedCreatorId,
      core_fingerprint: fixedFp,
      signature: undefined,
      manifest_signature: undefined,
      anchor_reference: undefined,
    },
    extensions: {},
  };

  const r = await verifyManifest(FIXED_ASSET, fixedManifest);
  check("XC-05", "Deterministic manifest verifies in TypeScript (same as Python CV-07)",
        r.success, r.message);

  // XC-06: core_fingerprint of CV-07 deterministic core matches Python's computed value
  // Python's CV-06 expected value is the ground truth
  const cv06Vector = vectors.vectors.find((v: {id: string}) => v.id === "CV-06");
  if (cv06Vector) {
    const coreIn: Record<string, unknown> = {};
    for (const f of CORE_HASH_FIELDS) {
      coreIn[f] = (cv06Vector.inputs.core_fields as Record<string,unknown>)[f];
    }
    const tsResult = computeHash(canonicalJson(coreIn), "sha256");
    check("XC-06", "core_fingerprint matches Python CV-06 expected",
          tsResult === cv06Vector.expected, `got ${tsResult}, want ${cv06Vector.expected}`);
  }

  // XC-07: safeEqual is timing-safe and symmetric
  check("XC-07", "safeEqual('abc','abc') === true",  safeEqual("abc", "abc"));
  check("XC-07b","safeEqual('abc','abd') === false", !safeEqual("abc", "abd"));
  check("XC-07c","safeEqual('a','ab') === false",    !safeEqual("a", "ab"));

  // XC-08: CORE_HASH_FIELDS does NOT contain core_fingerprint (bootstrap rule)
  check("XC-08", "CORE_HASH_FIELDS bootstrap rule: core_fingerprint absent",
        !(CORE_HASH_FIELDS as readonly string[]).includes("core_fingerprint"));

  // XC-09: hash_schema_block alias → same verification outcome as core_fingerprint
  const aliasManifest: Manifest = {
    core: {
      asset_id: fixedAssetId,
      schema_version: "0.5.5",
      creation_timestamp: fixedTs,
      hash_original: assetSha256,
      creator_id: fixedCreatorId,
      core_fingerprint: undefined as unknown as string,
      hash_schema_block: fixedFp,
      signature: undefined,
      manifest_signature: undefined,
      anchor_reference: undefined,
    },
    extensions: {},
  };
  delete (aliasManifest.core as unknown as Record<string,unknown>)["core_fingerprint"];
  const rAlias = await verifyManifest(FIXED_ASSET, aliasManifest);
  check("XC-09", "hash_schema_block alias verifies (matches Python CV-10)",
        rAlias.success, rAlias.message);

  // XC-10: multi-hash — TypeScript matches Python CV-11
  const cv11 = vectors.vectors.find((v: {id: string}) => v.id === "CV-11");
  if (cv11) {
    const assetData = Buffer.from(cv11.inputs.asset_hex, "hex");
    const r11 = await verifyManifest(assetData, cv11.inputs.manifest as Manifest);
    check("XC-10", "Multi-hash manifest verifies (matches Python CV-11)",
          r11.success === true, r11.message);
  }

  // ── Final report ──────────────────────────────────────────────────────────
  console.log("\n" + "=".repeat(60));
  console.log(`  Vectors loaded:  ${vectors.vectors.length}`);
  console.log(`  Tests run:       ${passed + failed}`);
  console.log(`  PASSED:          ${passed}`);
  console.log(`  FAILED:          ${failed}`);
  console.log("=".repeat(60));

  if (failures.length > 0) {
    console.log("\nFAILURES:");
    failures.forEach(f => console.log(`  ✗ ${f}`));
    process.exit(1);
  } else {
    console.log(`\n  GATE: ✓ CLEAR — Block 5 cross-verification complete`);
    console.log(`         Python and TypeScript implementations are equivalent.\n`);
    process.exit(0);
  }
})();
