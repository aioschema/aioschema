"use strict";
const { test, describe, before, after } = require("node:test");
const assert = require("node:assert/strict");
const fs     = require("node:fs");
const os     = require("node:os");
const path   = require("node:path");
const crypto = require("node:crypto");

const aios = require("./aioschema_v055.js");
const {
  generateManifest, verifyManifest, generateKeypair, computeHash, parseHash,
  safeEqual, canonicalJson, canonicalBytes, canonicalManifestBytes,
  creatorIdAnonymous, creatorIdFromPublicKey, validateCreatorId, uuidV7,
  sidecarPath, saveSidecar, loadSidecar, AnchorVerificationError,
  SPEC_VERSION, SUPPORTED_VERSIONS, CORE_HASH_FIELDS,
  SOFT_BINDING_THRESHOLD_DEFAULT, SOFT_BINDING_THRESHOLD_MAX, HASH_REGEX,
} = aios;

function makeTempFile(data, suffix = ".bin") {
  const fp = path.join(os.tmpdir(), `aios-test-${crypto.randomBytes(8).toString("hex")}${suffix}`);
  fs.writeFileSync(fp, data);
  return fp;
}
function cleanup(...paths) {
  for (const p of paths) {
    try { fs.unlinkSync(p); } catch {}
    try { fs.unlinkSync(sidecarPath(p)); } catch {}
  }
}
function makeAsset(content = "AIOSchema test asset content") { return Buffer.from(content); }

describe("TV-01 through TV-12", () => {
  test("TV-01: Valid manifest roundtrip", async () => {
    const data = makeAsset("TV-01"); const fp = makeTempFile(data);
    try {
      const { privateKey, publicKey } = generateKeypair();
      const m = generateManifest(fp, { privateKey });
      const r = await verifyManifest(fp, m, { publicKey });
      assert.ok(r.success, r.message); assert.equal(r.match_type, "hard"); assert.ok(r.signature_verified);
    } finally { cleanup(fp); }
  });
  test("TV-02: Tampered hash_original fails", async () => {
    const fp = makeTempFile(makeAsset("TV-02"));
    try {
      const m = generateManifest(fp); const t = JSON.parse(JSON.stringify(m));
      t.core.hash_original = "sha256-" + "ab".repeat(32);
      const r = await verifyManifest(fp, t); assert.ok(!r.success);
    } finally { cleanup(fp); }
  });
  test("TV-03: Tampered core_fingerprint fails", async () => {
    const fp = makeTempFile(makeAsset("TV-03"));
    try {
      const m = generateManifest(fp); const t = JSON.parse(JSON.stringify(m));
      t.core.core_fingerprint = "sha256-" + "cd".repeat(32);
      const r = await verifyManifest(fp, t); assert.ok(!r.success); assert.match(r.message.toLowerCase(), /tampered|mismatch/);
    } finally { cleanup(fp); }
  });
  test("TV-04: Soft binding skipped", async () => { /* image processing not available */ });
  test("TV-05: Soft binding skipped", async () => { /* image processing not available */ });
  test("TV-06: Valid signature verified", async () => {
    const fp = makeTempFile(makeAsset("TV-06"));
    try {
      const { privateKey, publicKey } = generateKeypair();
      const m = generateManifest(fp, { privateKey });
      const r = await verifyManifest(fp, m, { publicKey });
      assert.ok(r.success); assert.ok(r.signature_verified);
    } finally { cleanup(fp); }
  });
  test("TV-07: Wrong public key fails", async () => {
    const fp = makeTempFile(makeAsset("TV-07"));
    try {
      const { privateKey } = generateKeypair(); const { publicKey: wrongPub } = generateKeypair();
      const m = generateManifest(fp, { privateKey });
      const r = await verifyManifest(fp, m, { publicKey: wrongPub }); assert.ok(!r.success);
    } finally { cleanup(fp); }
  });
  test("TV-08: Unsigned passes without signature_verified", async () => {
    const fp = makeTempFile(makeAsset("TV-08"));
    try {
      const m = generateManifest(fp); assert.equal(m.core.signature, null);
      const r = await verifyManifest(fp, m); assert.ok(r.success); assert.ok(!r.signature_verified);
    } finally { cleanup(fp); }
  });
  test("TV-09: Missing required fields each fail", async () => {
    const fp = makeTempFile(makeAsset("TV-09"));
    try {
      const m = generateManifest(fp);
      for (const f of ["asset_id","schema_version","creation_timestamp","hash_original","creator_id","core_fingerprint"]) {
        const t = JSON.parse(JSON.stringify(m)); delete t.core[f];
        const r = await verifyManifest(fp, t); assert.ok(!r.success, `Should fail with missing '${f}'`);
      }
    } finally { cleanup(fp); }
  });
  test("TV-10: Invalid timestamp (no T and Z) fails", async () => {
    const fp = makeTempFile(makeAsset("TV-10"));
    try {
      const m = generateManifest(fp); const t = JSON.parse(JSON.stringify(m));
      t.core.creation_timestamp = "2026-02-20 12:00:00";
      const r = await verifyManifest(fp, t); assert.ok(!r.success);
    } finally { cleanup(fp); }
  });
  test("TV-11: Non-UTC timestamp fails", async () => {
    const fp = makeTempFile(makeAsset("TV-11"));
    try {
      const m = generateManifest(fp); const t = JSON.parse(JSON.stringify(m));
      t.core.creation_timestamp = "2026-02-20T12:00:00+05:00";
      const r = await verifyManifest(fp, t); assert.ok(!r.success);
    } finally { cleanup(fp); }
  });
  test("TV-12: Unknown schema_version fails", async () => {
    const fp = makeTempFile(makeAsset("TV-12"));
    try {
      const m = generateManifest(fp); const t = JSON.parse(JSON.stringify(m));
      t.core.schema_version = "9.99";
      const r = await verifyManifest(fp, t); assert.ok(!r.success); assert.match(r.message, /schema_version/);
    } finally { cleanup(fp); }
  });
});

describe("TV-13 through TV-18", () => {
  test("TV-13: Multi-hash manifest", async () => {
    const fp = makeTempFile(makeAsset("TV-13"));
    try {
      const m = generateManifest(fp, { hashAlgorithms: ["sha256", "sha384"] });
      assert.ok(Array.isArray(m.core.hash_original)); assert.equal(m.core.hash_original.length, 2);
      const algs = m.core.hash_original.map(h => h.split("-")[0]);
      assert.ok(algs.includes("sha256")); assert.ok(algs.includes("sha384"));
      const r = await verifyManifest(fp, m); assert.ok(r.success, r.message); assert.equal(r.match_type, "hard");
    } finally { cleanup(fp); }
  });
  test("TV-14: manifest_signature verified", async () => {
    const fp = makeTempFile(makeAsset("TV-14"));
    try {
      const { privateKey, publicKey } = generateKeypair();
      const m = generateManifest(fp, { privateKey });
      assert.ok(m.core.manifest_signature);
      const r = await verifyManifest(fp, m, { publicKey });
      assert.ok(r.success, r.message); assert.ok(r.manifest_signature_verified);
    } finally { cleanup(fp); }
  });
  test("TV-15: Tampered extensions fail manifest_signature", async () => {
    const fp = makeTempFile(makeAsset("TV-15"));
    try {
      const { privateKey, publicKey } = generateKeypair();
      const m = generateManifest(fp, { privateKey }); const t = JSON.parse(JSON.stringify(m));
      t.extensions["x-attacker"] = "payload";
      const r = await verifyManifest(fp, t, { publicKey }); assert.ok(!r.success); assert.match(r.message.toLowerCase(), /manifest/);
    } finally { cleanup(fp); }
  });
  test("TV-16: SHA-384 single-hash manifest", async () => {
    const fp = makeTempFile(makeAsset("TV-16"));
    try {
      const m = generateManifest(fp, { hashAlgorithms: ["sha384"] });
      assert.ok(typeof m.core.hash_original === "string");
      assert.ok(m.core.hash_original.startsWith("sha384-"));
      assert.equal(m.core.hash_original.length, 7 + 96);
      const r = await verifyManifest(fp, m); assert.ok(r.success, r.message);
    } finally { cleanup(fp); }
  });
  test("TV-17: Anchor verified", async () => {
    const fp = makeTempFile(makeAsset("TV-17"));
    try {
      const m = generateManifest(fp, { anchorRef: "aios-anchor:test-svc:record-001" });
      const mockResolver = async () => ({ asset_id: m.core.asset_id, core_fingerprint: m.core.core_fingerprint, timestamp: m.core.creation_timestamp });
      const r = await verifyManifest(fp, m, { verifyAnchor: true, anchorResolver: mockResolver });
      assert.ok(r.success, r.message); assert.ok(r.anchor_checked); assert.ok(r.anchor_verified);
    } finally { cleanup(fp); }
  });
  test("TV-18: Anchor present, verifyAnchor=false — warning not failure", async () => {
    const fp = makeTempFile(makeAsset("TV-18"));
    try {
      const m = generateManifest(fp, { anchorRef: "aios-anchor:test-svc:record-002" });
      const r = await verifyManifest(fp, m, { verifyAnchor: false });
      assert.ok(r.success, r.message); assert.ok(!r.anchor_checked); assert.ok(!r.anchor_verified);
      assert.ok(r.warnings.some(w => w.toLowerCase().includes("anchor")));
    } finally { cleanup(fp); }
  });
});

describe("Multi-Hash (§5.5)", () => {
  test("Single-string hash_original accepted", async () => {
    const fp = makeTempFile(makeAsset()); try { const m = generateManifest(fp, { hashAlgorithms: ["sha256"] }); assert.ok(typeof m.core.hash_original === "string"); const r = await verifyManifest(fp, m); assert.ok(r.success); } finally { cleanup(fp); }
  });
  test("Multi-hash array generated", async () => {
    const fp = makeTempFile(makeAsset()); try { const m = generateManifest(fp, { hashAlgorithms: ["sha256", "sha384"] }); assert.ok(Array.isArray(m.core.hash_original)); assert.equal(m.core.hash_original.length, 2); } finally { cleanup(fp); }
  });
  test("Any matching algorithm succeeds", async () => {
    const fp = makeTempFile(makeAsset("multi-hash-test"));
    try {
      const m = generateManifest(fp, { hashAlgorithms: ["sha256", "sha384"] });
      const t = JSON.parse(JSON.stringify(m));
      t.core.hash_original[0] = "sha256-" + "00".repeat(32);
      const coreForFp = {}; for (const f of CORE_HASH_FIELDS) coreForFp[f] = t.core[f];
      t.core.core_fingerprint = computeHash(canonicalBytes(coreForFp), "sha256");
      const r = await verifyManifest(fp, t); assert.ok(r.success, r.message);
    } finally { cleanup(fp); }
  });
  test("All algorithms fail → failure", async () => {
    const fp = makeTempFile(makeAsset());
    try {
      const m = generateManifest(fp, { hashAlgorithms: ["sha256", "sha384"] }); const t = JSON.parse(JSON.stringify(m));
      t.core.hash_original = ["sha256-" + "00".repeat(32), "sha384-" + "00".repeat(48)];
      const r = await verifyManifest(fp, t); assert.ok(!r.success);
    } finally { cleanup(fp); }
  });
  test("Empty hash array rejected", async () => {
    const fp = makeTempFile(makeAsset());
    try {
      const m = generateManifest(fp); const t = JSON.parse(JSON.stringify(m)); t.core.hash_original = [];
      const r = await verifyManifest(fp, t); assert.ok(!r.success); assert.match(r.message.toLowerCase(), /empty|missing/);
    } finally { cleanup(fp); }
  });
  test("core_fingerprint uses first algorithm", async () => {
    const fp = makeTempFile(makeAsset()); try { const m = generateManifest(fp, { hashAlgorithms: ["sha256", "sha384"] }); assert.ok(m.core.core_fingerprint.startsWith("sha256-")); } finally { cleanup(fp); }
  });
  test("Multi-hash sidecar roundtrip", async () => {
    const fp = makeTempFile(makeAsset());
    try {
      const m = generateManifest(fp, { hashAlgorithms: ["sha256", "sha384"], saveSidecar: true });
      const loaded = loadSidecar(fp); assert.deepEqual(m.core.hash_original, loaded.core.hash_original);
    } finally { cleanup(fp); }
  });
});

describe("SHA-384 (§5.3.1)", () => {
  test("SHA-384 hash format correct", () => { const h = computeHash(Buffer.from("test"), "sha384"); assert.ok(h.startsWith("sha384-")); assert.equal(h.length, 7 + 96); });
  test("SHA-384 regex accepts 96-hex", () => { assert.ok(HASH_REGEX.test("sha384-" + "ab".repeat(48))); });
  test("SHA-384 regex rejects 64-hex", () => { assert.ok(!HASH_REGEX.test("sha384-" + "ab".repeat(32))); });
  test("SHA-256 regex rejects 96-hex", () => { assert.ok(!HASH_REGEX.test("sha256-" + "ab".repeat(48))); });
  test("SHA-384 manifest verifies", async () => { const fp = makeTempFile(makeAsset()); try { const m = generateManifest(fp, { hashAlgorithms: ["sha384"] }); const r = await verifyManifest(fp, m); assert.ok(r.success, r.message); } finally { cleanup(fp); } });
  test("SHA-384 core_fingerprint correct", async () => { const fp = makeTempFile(makeAsset()); try { const m = generateManifest(fp, { hashAlgorithms: ["sha384"] }); assert.ok(m.core.core_fingerprint.startsWith("sha384-")); } finally { cleanup(fp); } });
});

describe("manifest_signature (§5.8)", () => {
  test("Generated when signed", async () => { const fp = makeTempFile(makeAsset()); try { const { privateKey } = generateKeypair(); const m = generateManifest(fp, { privateKey }); assert.ok(m.core.manifest_signature); assert.ok(m.core.manifest_signature.startsWith("ed25519-")); } finally { cleanup(fp); } });
  test("Null when unsigned", async () => { const fp = makeTempFile(makeAsset()); try { const m = generateManifest(fp); assert.equal(m.core.manifest_signature, null); } finally { cleanup(fp); } });
  test("Tampered extensions fail", async () => {
    const fp = makeTempFile(makeAsset()); try {
      const { privateKey, publicKey } = generateKeypair(); const m = generateManifest(fp, { privateKey }); const t = JSON.parse(JSON.stringify(m)); t.extensions["x-attacker-injected"] = "payload";
      const r = await verifyManifest(fp, t, { publicKey }); assert.ok(!r.success); assert.match(r.message.toLowerCase(), /manifest/);
    } finally { cleanup(fp); }
  });
  test("Bootstrap exclusion — manifest_signature null in canonical bytes", async () => {
    const fp = makeTempFile(makeAsset()); try { const { privateKey } = generateKeypair(); const m = generateManifest(fp, { privateKey }); const cb = canonicalManifestBytes(m); const parsed = JSON.parse(cb.toString("utf8")); assert.equal(parsed.core.manifest_signature, null); } finally { cleanup(fp); }
  });
  test("Wrong key fails manifest_signature", async () => {
    const fp = makeTempFile(makeAsset()); try { const { privateKey } = generateKeypair(); const { publicKey: wrongPub } = generateKeypair(); const m = generateManifest(fp, { privateKey }); const r = await verifyManifest(fp, m, { publicKey: wrongPub }); assert.ok(!r.success); } finally { cleanup(fp); }
  });
  test("manifest_signature requires publicKey", async () => {
    const fp = makeTempFile(makeAsset()); try { const { privateKey } = generateKeypair(); const m = generateManifest(fp, { privateKey }); const r = await verifyManifest(fp, m, { publicKey: null }); assert.ok(!r.success); assert.match(r.message, /public key/); } finally { cleanup(fp); }
  });
  test("Sidecar integrity roundtrip", async () => {
    const fp = makeTempFile(makeAsset()); try { const { privateKey, publicKey } = generateKeypair(); generateManifest(fp, { privateKey, saveSidecar: true }); const loaded = loadSidecar(fp); const r = await verifyManifest(fp, loaded, { publicKey }); assert.ok(r.success); assert.ok(r.manifest_signature_verified); } finally { cleanup(fp); }
  });
});

describe("Soft-Binding Threshold (§6.2, §8.3)", () => {
  test("Default threshold is 5", () => { assert.equal(SOFT_BINDING_THRESHOLD_DEFAULT, 5); });
  test("Max threshold is 10", () => { assert.equal(SOFT_BINDING_THRESHOLD_MAX, 10); });
  test("Threshold clamped — hard match still succeeds", async () => { const fp = makeTempFile(makeAsset()); try { const m = generateManifest(fp); const r = await verifyManifest(fp, m, { softBindingThreshold: 999 }); assert.ok(r.success); } finally { cleanup(fp); } });
  test("threshold_info in manifest ignored by verifier", async () => {
    const fp = makeTempFile(makeAsset()); try {
      const m = generateManifest(fp, { extensions: { soft_binding: { algorithm: "pHash-v1", fingerprint: "00".repeat(8), threshold_info: 64 } } });
      const r = await verifyManifest(fp, m, { softBindingThreshold: 5 }); assert.ok(r.success);
    } finally { cleanup(fp); }
  });
});

describe("Anchor Verification (§9, §10 Step 13)", () => {
  function mockFetcher(manifest, match = true) {
    return async () => match
      ? { asset_id: manifest.core.asset_id, core_fingerprint: manifest.core.core_fingerprint, timestamp: manifest.core.creation_timestamp }
      : { asset_id: "wrong-id", core_fingerprint: "sha256-" + "00".repeat(32), timestamp: "2026-01-01T00:00:00Z" };
  }
  test("anchor_verified=true on matching record", async () => { const fp = makeTempFile(makeAsset()); try { const m = generateManifest(fp, { anchorRef: "aios-anchor:svc:id001" }); const r = await verifyManifest(fp, m, { verifyAnchor: true, anchorResolver: mockFetcher(m, true) }); assert.ok(r.success); assert.ok(r.anchor_checked); assert.ok(r.anchor_verified); } finally { cleanup(fp); } });
  test("Anchor mismatch gives warning, manifest valid", async () => { const fp = makeTempFile(makeAsset()); try { const m = generateManifest(fp, { anchorRef: "aios-anchor:svc:id002" }); const r = await verifyManifest(fp, m, { verifyAnchor: true, anchorResolver: mockFetcher(m, false) }); assert.ok(r.success); assert.ok(r.anchor_checked); assert.ok(!r.anchor_verified); assert.ok(r.warnings.some(w => w.toLowerCase().includes("mismatch"))); } finally { cleanup(fp); } });
  test("Anchor not found gives warning", async () => { const fp = makeTempFile(makeAsset()); try { const m = generateManifest(fp, { anchorRef: "aios-anchor:svc:id003" }); const r = await verifyManifest(fp, m, { verifyAnchor: true, anchorResolver: async () => null }); assert.ok(r.success); assert.ok(!r.anchor_verified); assert.ok(r.warnings.some(w => w.toLowerCase().includes("not found"))); } finally { cleanup(fp); } });
  test("Anchor service error gives warning", async () => { const fp = makeTempFile(makeAsset()); try { const m = generateManifest(fp, { anchorRef: "aios-anchor:svc:id004" }); const r = await verifyManifest(fp, m, { verifyAnchor: true, anchorResolver: async () => { throw new AnchorVerificationError("Service timeout"); } }); assert.ok(r.success); assert.ok(r.warnings.some(w => w.toLowerCase().includes("anchor verification error"))); } finally { cleanup(fp); } });
  test("verifyAnchor=false — not checked, warning emitted", async () => { const fp = makeTempFile(makeAsset()); try { const m = generateManifest(fp, { anchorRef: "aios-anchor:svc:id005" }); const r = await verifyManifest(fp, m, { verifyAnchor: false }); assert.ok(!r.anchor_checked); assert.ok(!r.anchor_verified); assert.ok(r.warnings.some(w => w.toLowerCase().includes("anchor"))); } finally { cleanup(fp); } });
  test("Invalid anchorRef format rejected on generate", () => { const fp = makeTempFile(makeAsset()); try { assert.throws(() => generateManifest(fp, { anchorRef: "not-a-valid-anchor" }), /anchorRef/); } finally { cleanup(fp); } });
});

describe("Backward Compatibility (§14)", () => {
  test("hash_schema_block alias accepted", async () => {
    const fp = makeTempFile(Buffer.from("backward compat test")); try {
      const m = generateManifest(fp); const t = JSON.parse(JSON.stringify(m));
      t.core.hash_schema_block = t.core.core_fingerprint; delete t.core.core_fingerprint;
      const r = await verifyManifest(fp, t); assert.ok(r.success, `hash_schema_block alias must be accepted: ${r.message}`);
    } finally { cleanup(fp); }
  });
  test("All prior schema_version values accepted", async () => {
    const fp = makeTempFile(makeAsset()); try {
      const m = generateManifest(fp);
      for (const v of ["0.1","0.2","0.3","0.3.1","0.4","0.5","0.5.1","0.5.5"]) {
        const t = JSON.parse(JSON.stringify(m)); t.core.schema_version = v;
        const coreForFp = {}; for (const f of CORE_HASH_FIELDS) coreForFp[f] = t.core[f];
        t.core.core_fingerprint = computeHash(canonicalBytes(coreForFp), "sha256");
        const r = await verifyManifest(fp, t); assert.ok(r.success, `schema_version ${v} should be accepted: ${r.message}`);
      }
    } finally { cleanup(fp); }
  });
  test("v0.4-style manifest without manifest_signature passes", async () => {
    const fp = makeTempFile(makeAsset()); try { const m = generateManifest(fp); const t = JSON.parse(JSON.stringify(m)); delete t.core.manifest_signature; const r = await verifyManifest(fp, t); assert.ok(r.success); assert.ok(!r.manifest_signature_verified); } finally { cleanup(fp); }
  });
});

describe("previous_version_anchor (§15)", () => {
  test("Stored when provided", async () => { const fp = makeTempFile(makeAsset()); try { const m = generateManifest(fp, { previousVersionAnchor: "aios-anchor:opentimestamps:abc123def456" }); assert.equal(m.core.previous_version_anchor, "aios-anchor:opentimestamps:abc123def456"); } finally { cleanup(fp); } });
  test("Null by default (genesis)", async () => { const fp = makeTempFile(makeAsset()); try { const m = generateManifest(fp); assert.equal(m.core.previous_version_anchor, null); } finally { cleanup(fp); } });
  test("Invalid format raises", () => { const fp = makeTempFile(makeAsset()); try { assert.throws(() => generateManifest(fp, { previousVersionAnchor: "not-a-valid-anchor" }), /previousVersionAnchor/); } finally { cleanup(fp); } });
  test("previous_version_anchor NOT in CORE_HASH_FIELDS", () => { assert.ok(!CORE_HASH_FIELDS.includes("previous_version_anchor")); });
  test("Verification passes with version chain fields", async () => {
    const fp = makeTempFile(makeAsset()); try {
      const { privateKey, publicKey } = generateKeypair();
      const m = generateManifest(fp, { privateKey, previousVersionAnchor: "aios-anchor:opentimestamps:prevanchor001", anchorRef: "aios-anchor:opentimestamps:thisanchor001" });
      const r = await verifyManifest(fp, m, { publicKey }); assert.ok(r.success, r.message); assert.ok(r.signature_verified); assert.ok(r.manifest_signature_verified);
    } finally { cleanup(fp); }
  });
  test("Preserved in sidecar roundtrip", async () => {
    const fp = makeTempFile(makeAsset()); try { generateManifest(fp, { previousVersionAnchor: "aios-anchor:opentimestamps:genesis001", saveSidecar: true }); const loaded = loadSidecar(fp); assert.equal(loaded.core.previous_version_anchor, "aios-anchor:opentimestamps:genesis001"); } finally { cleanup(fp); }
  });
});

describe("core_fingerprint rename and alias (§5.6)", () => {
  test("Generated manifest has core_fingerprint, not hash_schema_block", async () => { const fp = makeTempFile(makeAsset()); try { const m = generateManifest(fp); assert.ok("core_fingerprint" in m.core); assert.ok(!("hash_schema_block" in m.core)); } finally { cleanup(fp); } });
  test("core_fingerprint format valid (sha256-<64hex>)", async () => { const fp = makeTempFile(makeAsset()); try { const m = generateManifest(fp); assert.ok(m.core.core_fingerprint.startsWith("sha256-")); assert.equal(m.core.core_fingerprint.length, 7 + 64); } finally { cleanup(fp); } });
  test("Tampered core_fingerprint triggers failure", async () => { const fp = makeTempFile(makeAsset()); try { const m = generateManifest(fp); const t = JSON.parse(JSON.stringify(m)); t.core.core_fingerprint = "sha256-" + "0".repeat(64); const r = await verifyManifest(fp, t); assert.ok(!r.success); assert.match(r.message.toLowerCase(), /core_fingerprint|tampered|mismatch/); } finally { cleanup(fp); } });
});

describe("Creator ID (§5.7)", () => {
  test("Anonymous creator_id is UUID v7", async () => { const fp = makeTempFile(makeAsset()); try { const m = generateManifest(fp); assert.match(m.core.creator_id, /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i); } finally { cleanup(fp); } });
  test("Attributed creator_id derived from public key", () => { const { publicKey } = generateKeypair(); const cid = creatorIdFromPublicKey(publicKey); assert.match(cid, /^ed25519-fp-[0-9a-f]{32}$/); });
  test("Attributed creator_id accepted by verifier", async () => {
    const fp = makeTempFile(makeAsset()); try {
      const { privateKey, publicKey } = generateKeypair(); const cid = creatorIdFromPublicKey(publicKey);
      const m = generateManifest(fp, { privateKey, creatorId: cid }); const r = await verifyManifest(fp, m, { publicKey }); assert.ok(r.success, r.message);
    } finally { cleanup(fp); }
  });
});

describe("Version constants", () => {
  test("SPEC_VERSION is 0.5.5", () => { assert.equal(SPEC_VERSION, "0.5.5"); });
  test("SUPPORTED_VERSIONS includes 0.5.5", () => { assert.ok(SUPPORTED_VERSIONS.has("0.5.5")); });
  test("SUPPORTED_VERSIONS includes all prior versions", () => { for (const v of ["0.1","0.2","0.3","0.3.1","0.4","0.5","0.5.1"]) assert.ok(SUPPORTED_VERSIONS.has(v), `Missing version ${v}`); });
  test("Generated manifest defaults to 0.5.5", async () => { const fp = makeTempFile(makeAsset()); try { const m = generateManifest(fp); assert.equal(m.core.schema_version, "0.5.5"); } finally { cleanup(fp); } });
});

describe("Canonical bytes (§5.6, §5.8)", () => {
  test("canonicalJson sorts keys", () => { assert.equal(canonicalJson({ b: 2, a: 1 }), '{"a":1,"b":2}'); });
  test("canonicalJson handles nested objects and arrays", () => { assert.equal(canonicalJson({ z: [3, 1], a: { y: 2, x: 1 } }), '{"a":{"x":1,"y":2},"z":[3,1]}'); });
  test("canonicalJson handles null", () => { assert.equal(canonicalJson(null), "null"); });
  test("canonicalManifestBytes zeroes manifest_signature", async () => {
    const fp = makeTempFile(makeAsset()); try { const { privateKey } = generateKeypair(); const m = generateManifest(fp, { privateKey }); const cb = canonicalManifestBytes(m); const parsed = JSON.parse(cb.toString("utf8")); assert.equal(parsed.core.manifest_signature, null); assert.ok(m.core.manifest_signature); } finally { cleanup(fp); }
  });
  test("canonicalManifestBytes is deterministic", async () => { const fp = makeTempFile(makeAsset()); try { const m = generateManifest(fp); const b1 = canonicalManifestBytes(m); const b2 = canonicalManifestBytes(m); assert.deepEqual(b1, b2); } finally { cleanup(fp); } });
});

describe("RFC 3161 support (§9, §16.4)", () => {
  test("anchorRfc3161 is callable", () => { assert.ok(typeof aios.anchorRfc3161 === "function"); });
  test("verifyRfc3161 is callable", () => { assert.ok(typeof aios.verifyRfc3161 === "function"); });
  test("verifyRfc3161 returns verified/message keys", () => {
    const hashHex = "a".repeat(64);
    const mockTsr = Buffer.concat([Buffer.from([0x30, 32]), Buffer.from(hashHex.slice(0, 32), "hex")]);
    const result  = aios.verifyRfc3161(mockTsr, "sha256-" + hashHex);
    assert.ok("verified" in result); assert.ok("message" in result);
  });
});

// ---------------------------------------------------------------------------
// TV-19: Key Rotation via previous_version_anchor
// ---------------------------------------------------------------------------

describe("TV-19: Key Rotation via previous_version_anchor", () => {

  test("TV-19a: v1 manifest signs with key A and anchors", async () => {
    // Establish the genesis manifest signed with the original key.
    const fp = makeTempFile(makeAsset("key-rotation-asset"));
    try {
      const { privateKey: keyA, publicKey: pubA } = generateKeypair();
      const v1 = generateManifest(fp, {
        privateKey: keyA,
        anchorRef:  "aios-anchor:opentimestamps:v1-anchor-abc123",
      });

      assert.ok(v1.core.signature,          "v1 must be signed");
      assert.ok(v1.core.manifest_signature, "v1 must have manifest_signature");
      assert.equal(v1.core.anchor_reference, "aios-anchor:opentimestamps:v1-anchor-abc123");
      assert.equal(v1.core.previous_version_anchor, null, "v1 is genesis");

      const r1 = await verifyManifest(fp, v1, { publicKey: pubA });
      assert.ok(r1.success, `v1 verify: ${r1.message}`);
      assert.ok(r1.signature_verified);
      assert.ok(r1.manifest_signature_verified);
    } finally { cleanup(fp); }
  });

  test("TV-19b: v2 manifest re-signs with new key B, chains to v1 anchor", async () => {
    // Key rotation: v2 is signed by the new key, not the original.
    // The previous_version_anchor cryptographically links it to v1.
    const fp = makeTempFile(makeAsset("key-rotation-asset"));
    try {
      const { privateKey: keyB, publicKey: pubB } = generateKeypair();
      const v2 = generateManifest(fp, {
        privateKey:             keyB,
        previousVersionAnchor:  "aios-anchor:opentimestamps:v1-anchor-abc123",
        anchorRef:              "aios-anchor:opentimestamps:v2-anchor-def456",
      });

      assert.ok(v2.core.signature,          "v2 must be signed with new key");
      assert.ok(v2.core.manifest_signature, "v2 must have manifest_signature");
      assert.equal(v2.core.previous_version_anchor, "aios-anchor:opentimestamps:v1-anchor-abc123");
      assert.equal(v2.core.anchor_reference,        "aios-anchor:opentimestamps:v2-anchor-def456");

      // v2 verifies cleanly with key B — no knowledge of key A required
      const r2 = await verifyManifest(fp, v2, { publicKey: pubB });
      assert.ok(r2.success, `v2 verify with new key: ${r2.message}`);
      assert.ok(r2.signature_verified);
      assert.ok(r2.manifest_signature_verified);
    } finally { cleanup(fp); }
  });

  test("TV-19c: v2 with old key A fails (key rotation is irreversible)", async () => {
    // Using the old key on the v2 manifest must fail — proving the rotation
    // is a one-way operation. The new manifest is bound to the new key only.
    const fp = makeTempFile(makeAsset("key-rotation-asset"));
    try {
      const { privateKey: keyA, publicKey: pubA } = generateKeypair();
      const { privateKey: keyB                  } = generateKeypair();

      // v2 signed with key B
      const v2 = generateManifest(fp, {
        privateKey:            keyB,
        previousVersionAnchor: "aios-anchor:opentimestamps:v1-anchor-abc123",
      });

      // Attempting to verify v2 with key A must fail
      const r = await verifyManifest(fp, v2, { publicKey: pubA });
      assert.ok(!r.success, "Verifying v2 with old key A must fail");
    } finally { cleanup(fp); }
  });

  test("TV-19d: creator_id changes across rotation — both manifests valid independently", async () => {
    // creator_id is allowed to change on key rotation (new attributed ID from new key).
    // Each manifest is self-consistent and independently verifiable.
    const fp = makeTempFile(makeAsset("key-rotation-asset"));
    try {
      const { privateKey: keyA, publicKey: pubA } = generateKeypair();
      const { privateKey: keyB, publicKey: pubB } = generateKeypair();

      const cidA = creatorIdFromPublicKey(pubA);
      const cidB = creatorIdFromPublicKey(pubB);
      assert.notEqual(cidA, cidB, "Rotated keys must produce different creator_ids");

      const v1 = generateManifest(fp, { privateKey: keyA, creatorId: cidA, anchorRef: "aios-anchor:opentimestamps:v1-anchor-abc123" });
      const v2 = generateManifest(fp, { privateKey: keyB, creatorId: cidB, previousVersionAnchor: "aios-anchor:opentimestamps:v1-anchor-abc123" });

      const r1 = await verifyManifest(fp, v1, { publicKey: pubA });
      const r2 = await verifyManifest(fp, v2, { publicKey: pubB });
      assert.ok(r1.success, `v1 verify: ${r1.message}`);
      assert.ok(r2.success, `v2 verify: ${r2.message}`);
      assert.equal(v1.core.creator_id, cidA);
      assert.equal(v2.core.creator_id, cidB);
    } finally { cleanup(fp); }
  });

  test("TV-19e: full chain — anchor resolver confirms version continuity", async () => {
    // Level 3: the anchor resolver is called for v2's anchor_reference.
    // The resolver confirms v2's asset_id and core_fingerprint, proving
    // the rotated manifest has been independently witnessed.
    const fp = makeTempFile(makeAsset("key-rotation-asset"));
    try {
      const { privateKey: keyB, publicKey: pubB } = generateKeypair();

      const v2 = generateManifest(fp, {
        privateKey:            keyB,
        previousVersionAnchor: "aios-anchor:opentimestamps:v1-anchor-abc123",
        anchorRef:             "aios-anchor:opentimestamps:v2-anchor-def456",
      });

      const mockResolver = async (ref) => {
        assert.equal(ref, "aios-anchor:opentimestamps:v2-anchor-def456");
        return {
          asset_id:         v2.core.asset_id,
          core_fingerprint: v2.core.core_fingerprint,
          timestamp:        v2.core.creation_timestamp,
        };
      };

      const r = await verifyManifest(fp, v2, {
        publicKey:      pubB,
        verifyAnchor:   true,
        anchorResolver: mockResolver,
      });

      assert.ok(r.success,                   `full chain verify: ${r.message}`);
      assert.ok(r.signature_verified,         "signature verified with new key");
      assert.ok(r.manifest_signature_verified,"manifest_signature verified");
      assert.ok(r.anchor_checked,             "anchor was checked");
      assert.ok(r.anchor_verified,            "anchor was confirmed");
      assert.equal(v2.core.previous_version_anchor, "aios-anchor:opentimestamps:v1-anchor-abc123", "v1 anchor preserved in chain");
    } finally { cleanup(fp); }
  });

});
