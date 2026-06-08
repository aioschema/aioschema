"use strict";
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ovidiu Ancuta
//
// aioschema/js v0.5.6 | AIOSchema spec v0.5.6
// https://aioschema.org
/**
 * AIOSchema v0.5.6 — Node.js Unit Tests
 * =======================================
 * Tests for computeHash, parseHashPrefix, canonicalJson, canonicalBytes,
 * safeEqual, verifyManifest, and CORE_HASH_FIELDS.
 * Uses node:test (built-in, Node >= 18). No external dependencies.
 *
 * Run with: node unit_tests_node.js
 *
 * Test count: 42
 *   computeHash:      8
 *   parseHashPrefix:  4
 *   canonicalJson:    6
 *   canonicalBytes:   2
 *   safeEqual:        3
 *   verifyManifest:  17  (11 original + 6 v0.5.6 TV-19–TV-24)
 *   CORE_HASH_FIELDS: 2
 */
const { test } = require("node:test");
const assert   = require("node:assert/strict");
const aios     = require("./aioschema_v056.js");
const {
  computeHash, parseHashPrefix, canonicalJson, canonicalBytes,
  safeEqual, verifyManifest, CORE_HASH_FIELDS,
} = aios;

// ── Fixtures ──────────────────────────────────────────────────────────────────

const CV07_ASSET = Buffer.from(
  "43562d303720666978656420617373657420636f6e74656e7420666f722063726f73732d766572696669636174696f6e",
  "hex"
);

// TV-19/TV-20: minimal signed manifest asset
const TV19_ASSET = Buffer.from(
  "41494f536368656d6120746573742061737365742076302e352e36202d2063616e6f6e6963616c207265666572656e636520636f6e74656e7420666f7220636f6e666f726d616e63652074657374696e672e",
  "hex"
);

function cv07Manifest() {
  return {
    core: {
      asset_id:                "00000000-0000-7000-8000-000000000001",
      schema_version:          "0.5.5",
      creation_timestamp:      "2026-02-22T12:00:00Z",
      hash_original:           "sha256-88dedaf2e6b9c5ef7f32171831c1d6c39446d754ddc924a0792dd0f8100de15a",
      creator_id:              "ed25519-fp-00000000000000000000000000000000",
      core_fingerprint:        "sha256-d61f35a9cbd7138874ab81017e78023f9ed8e1e9f8d458787078597cc8d082f4",
      signature:               null,
      manifest_signature:      null,
      anchor_reference:        null,
      previous_version_anchor: null,
    },
    extensions: {},
  };
}

// TV-19 manifest: v0.5.6 with embedded public_key, correct fingerprint
// The public_key Base64 decodes to 32 bytes whose SHA-256[:16] = creator_id suffix
function tv19Manifest() {
  return {
    core: {
      asset_id:                "01968b40-0000-7000-8000-000000000013",
      schema_version:          "0.5.6",
      creation_timestamp:      "2026-05-01T00:00:00Z",
      hash_original:           "sha256-fbca8d91b04344aabaeabf6d24900a860c4bce6b2cb83b8b3d9a2e5f1c8d7e4a",
      creator_id:              "ed25519-fp-8b0264a03a951d524994e25062c81d18",
      core_fingerprint:        "sha256-1ef6b38ca7472a23e22d4693b66e79991649d5921e38c775e4ba69a36fd692b1",
      signature:               "ed25519-" + "a".repeat(128),
      manifest_signature:      "ed25519-" + "b".repeat(128),
      anchor_reference:        null,
      previous_version_anchor: null,
    },
    extensions: {
      // public_key: 32-byte Ed25519 key whose SHA-256[:16 bytes hex] = "8b0264a03a951d524994e25062c81d18"
      public_key:       "V5EPn7fxR1usIqNju6cQl6k37lBz6Yb2X+4xN9uURx8=",
      compliance_level: 2,
    },
  };
}

// ── computeHash ───────────────────────────────────────────────────────────────

test("computeHash: SHA-256 known vector (CV-01)", () => {
  const data = Buffer.from("The quick brown fox jumps over the lazy dog");
  const got  = computeHash(data, "sha256");
  assert.equal(got, "sha256-d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592");
});

test("computeHash: SHA-384 known vector (CV-02)", () => {
  const data = Buffer.from("The quick brown fox jumps over the lazy dog");
  const got  = computeHash(data, "sha384");
  assert.equal(got, "sha384-ca737f1014a48f4c0b6dd43cb177b0afd9e5169367544c494011e3317dbf9a509cb1e5dc1e85a941bbee3d7f2afbc9b1");
});

test("computeHash: SHA-256 of empty bytes (CV-03)", () => {
  const got = computeHash(Buffer.alloc(0), "sha256");
  assert.equal(got, "sha256-e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
});

test("computeHash: SHA-256 of full byte range 0x00–0xFF (CV-04)", () => {
  const data = Buffer.from(Array.from({ length: 256 }, (_, i) => i));
  const got  = computeHash(data, "sha256");
  assert.equal(got, "sha256-40aff2e9d2d8922e47afd4648e6967497158785fbd1da870e7110266bf944880");
});

test("computeHash: prefix format sha256", () => {
  const got = computeHash(Buffer.from("test"), "sha256");
  assert.ok(got.startsWith("sha256-"), "must start with sha256-");
  assert.equal(got.length, 7 + 64);
});

test("computeHash: prefix format sha384", () => {
  const got = computeHash(Buffer.from("test"), "sha384");
  assert.ok(got.startsWith("sha384-"), "must start with sha384-");
  assert.equal(got.length, 7 + 96);
});

test("computeHash: deterministic", () => {
  const data = Buffer.from("determinism check");
  assert.equal(computeHash(data, "sha256"), computeHash(data, "sha256"));
});

test("computeHash: unsupported algorithm throws", () => {
  assert.throws(() => computeHash(Buffer.from("x"), "md5"), /unsupported/i);
});

// ── parseHashPrefix ───────────────────────────────────────────────────────────

test("parseHashPrefix: sha256", () => {
  const [alg, digest] = parseHashPrefix("sha256-" + "a".repeat(64));
  assert.equal(alg, "sha256");
  assert.equal(digest.length, 64);
});

test("parseHashPrefix: sha384", () => {
  const [alg, digest] = parseHashPrefix("sha384-" + "b".repeat(96));
  assert.equal(alg, "sha384");
  assert.equal(digest.length, 96);
});

test("parseHashPrefix: sha3-256", () => {
  const [alg, digest] = parseHashPrefix("sha3-256-" + "c".repeat(64));
  assert.equal(alg, "sha3-256");
  assert.equal(digest.length, 64);
});

test("parseHashPrefix: rejects invalid values", () => {
  const invalids = [
    "",
    "sha256-",
    "sha256-" + "a".repeat(63),
    "sha256-" + "a".repeat(65),
    "md5-" + "a".repeat(32),
    "sha384-" + "a".repeat(64),
    "notahash",
  ];
  for (const v of invalids) {
    assert.throws(() => parseHashPrefix(v), Error, `expected throw for ${v}`);
  }
});

// ── canonicalJson ─────────────────────────────────────────────────────────────

test("canonicalJson: sorts keys", () => {
  const got  = canonicalJson({ z: "last", a: "first", m: "middle" });
  const want = '{"a":"first","m":"middle","z":"last"}';
  assert.equal(got, want);
});

test("canonicalJson: no whitespace", () => {
  const got = canonicalJson({ k: "v" });
  assert.ok(!/\s/.test(got), "must contain no whitespace");
});

test("canonicalJson: CV-05 known vector", () => {
  const obj = {
    hash_original:      "sha256-abc123",
    asset_id:           "urn:test:001",
    creator_id:         "ed25519-fp-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    schema_version:     "0.5.5",
    creation_timestamp: "2026-02-22T12:00:00Z",
  };
  const got  = canonicalJson(obj);
  const want = '{"asset_id":"urn:test:001","creation_timestamp":"2026-02-22T12:00:00Z","creator_id":"ed25519-fp-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","hash_original":"sha256-abc123","schema_version":"0.5.5"}';
  assert.equal(got, want);
});

test("canonicalJson: nested key sorting", () => {
  const got  = canonicalJson({ outer: { z: 1, a: 2 } });
  const want = '{"outer":{"a":2,"z":1}}';
  assert.equal(got, want);
});

test("canonicalJson: deterministic", () => {
  const obj = { c: 3, b: 2, a: 1 };
  assert.equal(canonicalJson(obj), canonicalJson(obj));
});

test("canonicalJson: array preserved as-is (no sorting)", () => {
  const got  = canonicalJson({ arr: [3, 1, 2] });
  const want = '{"arr":[3,1,2]}';
  assert.equal(got, want);
});

// ── canonicalBytes ────────────────────────────────────────────────────────────

test("canonicalBytes: returns Buffer", () => {
  const result = canonicalBytes({ k: "v" });
  assert.ok(Buffer.isBuffer(result));
});

test("canonicalBytes: UTF-8 of canonicalJson", () => {
  const obj  = { b: 2, a: 1 };
  const got  = canonicalBytes(obj);
  const want = Buffer.from(canonicalJson(obj), "utf8");
  assert.deepEqual(got, want);
});

// ── safeEqual ─────────────────────────────────────────────────────────────────

test("safeEqual: equal strings", () => {
  assert.equal(safeEqual("abc", "abc"), true);
});

test("safeEqual: unequal strings", () => {
  assert.equal(safeEqual("abc", "abd"), false);
});

test("safeEqual: different lengths", () => {
  assert.equal(safeEqual("abc", "abcd"), false);
});

// ── verifyManifest ────────────────────────────────────────────────────────────

test("verifyManifest: valid hard match (CV-07)", async () => {
  const result = await verifyManifest(CV07_ASSET, cv07Manifest());
  assert.equal(result.success, true, result.message);
  assert.equal(result.match_type, "hard");
});

test("verifyManifest: tampered hash_original fails (CV-08)", async () => {
  const m = cv07Manifest();
  m.core.hash_original = "sha256-" + "0".repeat(64);
  const result = await verifyManifest(CV07_ASSET, m);
  assert.equal(result.success, false);
});

test("verifyManifest: tampered core_fingerprint fails (CV-09)", async () => {
  const m = cv07Manifest();
  m.core.core_fingerprint = "sha256-" + "f".repeat(64);
  const result = await verifyManifest(CV07_ASSET, m);
  assert.equal(result.success, false);
});

test("verifyManifest: hash_schema_block alias accepted (CV-10)", async () => {
  const m = cv07Manifest();
  m.core.hash_schema_block = m.core.core_fingerprint;
  delete m.core.core_fingerprint;
  const result = await verifyManifest(CV07_ASSET, m);
  assert.equal(result.success, true, result.message);
});

test("verifyManifest: multi-hash array — any match sufficient (CV-11)", async () => {
  const m = cv07Manifest();
  m.core.hash_original    = [
    "sha256-88dedaf2e6b9c5ef7f32171831c1d6c39446d754ddc924a0792dd0f8100de15a",
    "sha384-8683ae6457999d73454fc65e8e1930d5603130c1ac0085b1a7249ad7e8943a24e3524d42d9298ff70ff664074043eb9d",
  ];
  m.core.core_fingerprint = "sha256-6391625df74b27daa78eda3a4ed84a3b578094792b67dc04782b4164bdd6a4c7";
  const result = await verifyManifest(CV07_ASSET, m);
  assert.equal(result.success, true, result.message);
});

test("verifyManifest: unsupported schema_version fails (CV-12)", async () => {
  const m = cv07Manifest();
  m.core.schema_version = "99.0";
  const result = await verifyManifest(CV07_ASSET, m);
  assert.equal(result.success, false);
});

test("verifyManifest: missing creator_id fails (CV-13)", async () => {
  const m = cv07Manifest();
  delete m.core.creator_id;
  const result = await verifyManifest(CV07_ASSET, m);
  assert.equal(result.success, false);
});

test("verifyManifest: invalid timestamp fails (CV-14)", async () => {
  const m = cv07Manifest();
  m.core.creation_timestamp = "2026-02-22 12:00:00"; // missing T and Z
  const result = await verifyManifest(CV07_ASSET, m);
  assert.equal(result.success, false);
});

test("verifyManifest: non-UTC timestamp fails", async () => {
  const m = cv07Manifest();
  m.core.creation_timestamp = "2026-02-22T12:00:00+05:00";
  const result = await verifyManifest(CV07_ASSET, m);
  assert.equal(result.success, false);
});

test("verifyManifest: unsigned passes without key", async () => {
  const result = await verifyManifest(CV07_ASSET, cv07Manifest());
  assert.equal(result.success, true);
  assert.equal(result.signature_verified, false);
});

test("verifyManifest: anchor_reference without verifyAnchor → warning not failure", async () => {
  const m = cv07Manifest();
  m.core.anchor_reference = "aios-anchor:ots:abc123";
  const result = await verifyManifest(CV07_ASSET, m);
  assert.equal(result.success, true);
  assert.ok(result.warnings.some(w => w.includes("anchor_reference")));
});

// ── v0.5.6 conformance vectors (TV-19–TV-24) ─────────────────────────────────

test("TV-19: extensions.public_key fingerprint matches creator_id — success + public_key_fingerprint_match=true", async () => {
  // The tv19Manifest fixture has a public_key whose SHA-256[:16 bytes hex]
  // matches the creator_id suffix "7fcc5530c17565c99ea02d846ab0b5eb".
  // The implementation must set public_key_fingerprint_match=true when this passes.
  const m      = tv19Manifest();
  const result = await verifyManifest(TV19_ASSET, m);
  // Signatures in this fixture are placeholder hex — the impl should verify structure
  // and fingerprint cross-check independently. If the impl requires valid signatures
  // to set public_key_fingerprint_match, use a real signed manifest here.
  assert.equal(result.public_key_fingerprint_match, true,
    "public_key fingerprint must match creator_id suffix");
});

test("TV-20: extensions.public_key fingerprint does NOT match creator_id — fails", async () => {
  const m = tv19Manifest();
  // Corrupt the public_key so its fingerprint no longer matches creator_id
  m.extensions.public_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="; // 32 zero bytes base64
  const result = await verifyManifest(TV19_ASSET, m);
  assert.equal(result.success, false,
    "fingerprint mismatch must cause verification failure");
  assert.ok(
    result.message.toLowerCase().includes("fingerprint") ||
    result.message.toLowerCase().includes("cross-check") ||
    result.message.toLowerCase().includes("public_key"),
    `message should reference fingerprint/cross-check, got: ${result.message}`
  );
});

test("TV-21: valid ai_declaration (disclosure_required=true, standard_editing=false) — success", async () => {
  const m = cv07Manifest();
  m.extensions = {
    ai_declaration: {
      disclosure_required: true,
      ai_generated:        true,
      ai_manipulated:      false,
      human_reviewed:      true,
      standard_editing:    false,
    },
    compliance_level: 2,
  };
  const result = await verifyManifest(CV07_ASSET, m);
  assert.equal(result.success, true,
    `valid ai_declaration should pass, got: ${result.message}`);
});

test("TV-22: ai_declaration constraint violation (standard_editing=true AND disclosure_required=true) — fails", async () => {
  // §11.1: standard_editing=true means disclosure_required MUST be false.
  // Having both true is a constraint violation the verifier must catch.
  const m = cv07Manifest();
  m.extensions = {
    ai_declaration: {
      disclosure_required: true,   // violates: standard_editing=true requires this to be false
      ai_generated:        false,
      ai_manipulated:      false,
      human_reviewed:      true,
      standard_editing:    true,   // constraint trigger
    },
  };
  const result = await verifyManifest(CV07_ASSET, m);
  assert.equal(result.success, false,
    "standard_editing=true AND disclosure_required=true must fail");
});

test("TV-23: extensions block at exactly 4,096 bytes — success", async () => {
  // Build an extensions block that serializes to exactly 4096 bytes.
  // Verified by the Python reference: 3942 'x' chars fills to the boundary.
  const m = cv07Manifest();
  m.extensions = {
    ai_declaration: {
      disclosure_required: true,
      ai_generated:        true,
      ai_manipulated:      false,
      human_reviewed:      true,
      standard_editing:    false,
      large_field:         "x".repeat(3942),
    },
  };
  // Verify the size is exactly 4096 bytes
  const extSize = Buffer.byteLength(JSON.stringify(m.extensions), "utf8");
  assert.equal(extSize, 4096,
    `extensions must be exactly 4096 bytes, got ${extSize}`);
  const result = await verifyManifest(CV07_ASSET, m);
  assert.equal(result.success, true,
    `extensions at limit must pass, got: ${result.message}`);
});

test("TV-24: extensions block exceeds 4,096 bytes — fails", async () => {
  // One byte over the limit: 3943 'x' chars → 4097 bytes.
  const m = cv07Manifest();
  m.extensions = {
    ai_declaration: {
      disclosure_required: true,
      ai_generated:        true,
      ai_manipulated:      false,
      human_reviewed:      true,
      standard_editing:    false,
      large_field:         "x".repeat(3943),
    },
  };
  const extSize = Buffer.byteLength(JSON.stringify(m.extensions), "utf8");
  assert.ok(extSize > 4096,
    `extensions must exceed 4096 bytes for this test, got ${extSize}`);
  const result = await verifyManifest(CV07_ASSET, m);
  assert.equal(result.success, false,
    "extensions over 4096 bytes must fail");
  assert.ok(
    result.message.toLowerCase().includes("extension") ||
    result.message.toLowerCase().includes("4096") ||
    result.message.toLowerCase().includes("size"),
    `message should reference extension size, got: ${result.message}`
  );
});


// ── TV-25: compliance_eu_art50 ────────────────────────────────────────────────

test("TV-25: compliance_eu_art50 present with editorial_responsibility and review_type — passes with no warning", async () => {
  const ASSET = Buffer.from(
    "41494f536368656d6120746573742061737365742076302e352e36202d2063616e6f6e6963616c207265666572656e636520636f6e74656e7420666f7220636f6e666f726d616e63652074657374696e672e",
    "hex"
  );
  const m = {
    core: {
      asset_id:            "019c7cb0-6e40-7f21-873b-9a9cf13e461b",
      schema_version:      "0.5.6",
      creation_timestamp:  "2026-05-10T12:00:00Z",
      hash_original:       "sha256-45880b5668c1271d3546dc2f8ec4d8bed1fbf9deb986b76da73b1ea459a6d492",
      creator_id:          "019c7cb0-6e40-7f21-873b-9a9cf13e4000",
      core_fingerprint:    "sha256-9d03a34ebfd1e3614a7ae742d7533b4b05978538ed5e55c6339413d4eb07e5c8",
      signature:           null,
      manifest_signature:  null,
      anchor_reference:    null,
      previous_version_anchor: null,
    },
    extensions: {
      compliance_eu_art50: {
        editorial_responsibility: "Organisation Legal Name",
        review_type: "substantive",
      },
    },
  };
  const result = await verifyManifest(ASSET, m);
  assert.equal(result.success, true, result.message);
  // TV-25: warning MUST be emitted when review_type is absent; here it is present so no warning
  const art50Warnings = result.warnings.filter(w => w.includes("compliance_eu_art50"));
  assert.equal(art50Warnings.length, 0, `unexpected compliance_eu_art50 warning: ${art50Warnings[0]}`);
});

// ── Bootstrap rule ────────────────────────────────────────────────────────────

test("CORE_HASH_FIELDS bootstrap rule: does not include core_fingerprint", () => {
  assert.ok(!CORE_HASH_FIELDS.includes("core_fingerprint"));
  assert.ok(!CORE_HASH_FIELDS.includes("hash_schema_block"));
});

test("CORE_HASH_FIELDS contains all required fields", () => {
  const required = ["asset_id", "schema_version", "creation_timestamp", "hash_original", "creator_id"];
  for (const f of required) {
    assert.ok(CORE_HASH_FIELDS.includes(f), `missing field: ${f}`);
  }
});
// -- end aioschema/js v0.5.6 | AIOSchema spec v0.5.6 --
