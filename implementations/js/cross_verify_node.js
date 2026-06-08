"use strict";
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ovidiu Ancuta
//
// aioschema/js v0.5.6 | AIOSchema spec v0.5.6
// https://aioschema.org

const fs   = require("node:fs");
const path = require("node:path");
const aios = require("./aioschema_v055.js");
const { computeHash, canonicalJson, canonicalBytes, CORE_HASH_FIELDS, verifyManifest } = aios;

// Load vectors
const candidates = [
  process.env.AIOSCHEMA_VECTORS,
  path.join(__dirname, "../mnt/project/cross_verify_vectors.json"),
  "/mnt/project/cross_verify_vectors.json",
  path.join(__dirname, "cross_verify_vectors.json"),
].filter(Boolean);

let vectorsPath;
for (const p of candidates) {
  if (fs.existsSync(p)) { vectorsPath = p; break; }
}
if (!vectorsPath) {
  console.error("cross_verify_vectors.json not found. Set AIOSCHEMA_VECTORS env var.");
  process.exit(1);
}

const vectors = JSON.parse(fs.readFileSync(vectorsPath, "utf8")).vectors;

async function run() {
  let passed = 0;
  let failed = 0;
  const lines = [];

  for (const v of vectors) {
    try {
      // CV-01 to CV-04: hash computation
      if (v.inputs.data_hex !== undefined && v.inputs.algorithm) {
        const data   = Buffer.from(v.inputs.data_hex, "hex");
        const result = computeHash(data, v.inputs.algorithm);
        const ok     = result === v.expected;
        if (ok) { passed++; lines.push(`  ✓ ${v.id}: ${v.name}`); }
        else    { failed++; lines.push(`  ✗ ${v.id}: ${v.name}\n    expected: ${v.expected}\n    got:      ${result}`); }
        continue;
      }
      // CV-05: canonical JSON
      if (v.inputs.object) {
        const result = canonicalJson(v.inputs.object);
        const ok     = result === v.expected;
        if (ok) { passed++; lines.push(`  ✓ ${v.id}: ${v.name}`); }
        else    { failed++; lines.push(`  ✗ ${v.id}: ${v.name}\n    expected: ${v.expected}\n    got:      ${result}`); }
        continue;
      }
      // CV-06: core_fingerprint
      if (v.inputs.core_fields) {
        const subset = {};
        for (const field of CORE_HASH_FIELDS) {
          if (Object.prototype.hasOwnProperty.call(v.inputs.core_fields, field)) {
            subset[field] = v.inputs.core_fields[field];
          }
        }
        const canon  = canonicalBytes(subset);
        const result = computeHash(canon, "sha256");
        const ok     = result === v.expected;
        if (ok) { passed++; lines.push(`  ✓ ${v.id}: ${v.name}`); }
        else    { failed++; lines.push(`  ✗ ${v.id}: ${v.name}\n    expected: ${v.expected}\n    got:      ${result}`); }
        continue;
      }
      // CV-07 to CV-14: manifest verification
      if (v.inputs.asset_hex !== undefined && v.inputs.manifest) {
        const asset  = Buffer.from(v.inputs.asset_hex, "hex");
        const result = await verifyManifest(asset, v.inputs.manifest);
        const ok = result.success === v.expected.success &&
          (!v.expected.match_type || result.match_type === v.expected.match_type);
        if (ok) { passed++; lines.push(`  ✓ ${v.id}: ${v.name}`); }
        else {
          failed++;
          lines.push(
            `  ✗ ${v.id}: ${v.name}\n` +
            `    expected: success=${v.expected.success} match_type=${v.expected.match_type ?? "any"}\n` +
            `    got:      success=${result.success} match_type=${result.match_type} msg=${result.message}`
          );
        }
        continue;
      }
      lines.push(`  ? ${v.id}: unrecognised vector shape`);
    } catch (e) {
      failed++;
      lines.push(`  ✗ ${v.id}: ${v.name} — ERROR: ${e.message}`);
    }
  }

  console.log("\nAIOSchema v0.5.6 — Node.js Cross-Verify");
  console.log("=".repeat(50));
  lines.forEach(l => console.log(l));
  console.log("=".repeat(50));
  console.log(`Vectors: ${vectors.length}  |  PASS: ${passed}  |  FAIL: ${failed}`);
  console.log(failed === 0 ? "✓ ALL PASS" : "✗ FAILURES DETECTED");
  process.exit(failed === 0 ? 0 : 1);
}

run();
// -- end aioschema/js v0.5.6 | AIOSchema spec v0.5.6 --
