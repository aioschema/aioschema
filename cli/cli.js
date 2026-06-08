#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ovidiu Ancuta
//
// aioschema/cli v0.5.13 | AIOSchema spec v0.5.6
// https://aioschema.org

"use strict";
/**
 * AIOSchema v0.5.6: CLI
 * ======================
 * Usage:
 *   aioschema keygen
 *   aioschema generate <file> [--algorithm sha256|sha384] [--creator-id <id>]
 *                             [--private-key <base64>] [--ext key=value]
 *   aioschema verify <file> <manifest.aios.json> [--public-key <base64>]
 *   aioschema --version
 *   aioschema --help
 */

const fs     = require("node:fs");
const path   = require("node:path");
const crypto = require("node:crypto");
const aios   = require("@aioschema/js");

const {
  generateManifest,
  verifyManifest,
  sidecarPath,
  generateKeypair,
  creatorIdFromPublicKey,
  SPEC_VERSION,
} = aios;

// ── Argument parsing ──────────────────────────────────────────────────────────

const args = process.argv.slice(2);

if (args.length === 0 || args[0] === "--help" || args[0] === "-h") {
  printHelp();
  process.exit(0);
}

if (args[0] === "--version" || args[0] === "-v") {
  console.log(`AIOSchema v${SPEC_VERSION}`);
  process.exit(0);
}

const command = args[0];

if (command === "keygen") {
  runKeygen();
} else if (command === "generate") {
  runGenerate(args.slice(1));
} else if (command === "verify") {
  runVerify(args.slice(1));
} else {
  console.error(`Unknown command: ${command}`);
  console.error(`Run 'aioschema --help' for usage.`);
  process.exit(1);
}

// ── Commands ──────────────────────────────────────────────────────────────────

function runKeygen() {
  const { privateKey, publicKey } = generateKeypair();
  const creatorId = creatorIdFromPublicKey(publicKey);

  // Export raw 32-byte public key as base64 for --public-key flag
  const pubKeyDer  = publicKey.export({ type: "spki", format: "der" });
  const pubKeyB64  = pubKeyDer.slice(-32).toString("base64");

  // Export raw 32-byte private key seed as base64 for --private-key flag
  const privKeyDer = privateKey.export({ type: "pkcs8", format: "der" });
  const privKeyB64 = privKeyDer.slice(-32).toString("base64");

  console.log(`AIOSchema keypair generated`);
  console.log(`  creator_id:  ${creatorId}`);
  console.log(`  public_key:  ${pubKeyB64}`);
  console.log(`  private_key: ${privKeyB64}`);
  console.log(``);
  console.log(`Store private_key securely. Use --private-key to sign manifests (Level 2).`);
  console.log(`Use --public-key to verify signed manifests.`);
}

function runGenerate(args) {
  const positional = [];
  const opts       = {};
  const algorithms = [];

  for (let i = 0; i < args.length; i++) {
    if (args[i] === "--algorithm" || args[i] === "-a") {
      algorithms.push(args[++i]);
    } else if (args[i] === "--creator-id") {
      opts.creatorId = args[++i];
    } else if (args[i] === "--private-key") {
      const raw = args[++i];
      try {
        const seed = Buffer.from(raw, "base64");
        if (seed.length !== 32) throw new Error(`expected 32 bytes, got ${seed.length}`);
        // Reconstruct PKCS8 DER for Ed25519 from raw 32-byte seed
        const pkcs8Prefix = Buffer.from(
          "302e020100300506032b657004220420", "hex"
        );
        opts.privateKey = crypto.createPrivateKey({
          key:    Buffer.concat([pkcs8Prefix, seed]),
          format: "der",
          type:   "pkcs8",
        });
      } catch (e) {
        console.error(`Error loading private key: ${e.message}`);
        process.exit(1);
      }
    } else if (args[i] === "--ext") {
      const raw = args[++i];
      const eq  = raw.indexOf("=");
      if (eq === -1) {
        console.error(`Error: --ext requires key=value format, got: ${raw}`);
        process.exit(1);
      }
      opts.extensions = opts.extensions || {};
      opts.extensions[raw.slice(0, eq)] = raw.slice(eq + 1);
    } else {
      positional.push(args[i]);
    }
  }

  if (algorithms.length === 1) {
    opts.hashAlgorithms = algorithms[0];
  } else if (algorithms.length > 1) {
    opts.hashAlgorithms = algorithms;
  }
  // If no --algorithm provided, library default (sha256) is used

  const filePath = positional[0];
  if (!filePath) {
    console.error("Error: file path required.\nUsage: aioschema generate <file>");
    process.exit(1);
  }
  if (!fs.existsSync(filePath)) {
    console.error(`Error: file not found: ${filePath}`);
    process.exit(1);
  }

  try {
    const manifest = generateManifest(filePath, opts);
    const out      = sidecarPath(filePath);

    fs.writeFileSync(out, JSON.stringify(manifest, null, 2), "utf8");

    const level = manifest.extensions && manifest.extensions.compliance_level != null
      ? manifest.extensions.compliance_level
      : 1;

    console.log(`Manifest written: ${out}`);
    console.log(`  compliance_level: ${level}`);
    console.log(`  asset_id:         ${manifest.core.asset_id}`);
    console.log(`  hash_original:    ${Array.isArray(manifest.core.hash_original)
      ? manifest.core.hash_original.join(", ")
      : manifest.core.hash_original}`);
    console.log(`  core_fingerprint: ${manifest.core.core_fingerprint}`);
    console.log(`  creator_id:       ${manifest.core.creator_id}`);
    if (manifest.core.signature) {
      console.log(`  signature:        present`);
      console.log(`  manifest_sig:     present`);
    }
    if (opts.extensions) {
      console.log(`  extensions:       ${Object.keys(opts.extensions).join(", ")}`);
    }
  } catch (err) {
    console.error(`Error generating manifest: ${err.message}`);
    process.exit(1);
  }
}

async function runVerify(args) {
  const positional = [];
  const opts       = {};

  for (let i = 0; i < args.length; i++) {
    if (args[i] === "--public-key") {
      const raw = args[++i];
      try {
        const rawBytes = Buffer.from(raw, "base64");
        if (rawBytes.length !== 32) throw new Error(`expected 32 bytes, got ${rawBytes.length}`);
        // Wrap in SPKI DER
        const spkiPrefix = Buffer.from("302a300506032b6570032100", "hex");
        opts.publicKey = crypto.createPublicKey({
          key:    Buffer.concat([spkiPrefix, rawBytes]),
          format: "der",
          type:   "spki",
        });
      } catch (e) {
        console.error(`Error loading public key: ${e.message}`);
        process.exit(1);
      }
    } else {
      positional.push(args[i]);
    }
  }

  const filePath     = positional[0];
  const manifestPath = positional[1];

  if (!filePath || !manifestPath) {
    console.error("Error: file path and manifest path required.");
    console.error("Usage: aioschema verify <file> <manifest.aios.json> [--public-key <base64>]");
    process.exit(1);
  }
  if (!fs.existsSync(filePath)) {
    console.error(`Error: file not found: ${filePath}`);
    process.exit(1);
  }
  if (!fs.existsSync(manifestPath)) {
    console.error(`Error: manifest not found: ${manifestPath}`);
    process.exit(1);
  }

  let manifest;
  try {
    manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
  } catch (err) {
    console.error(`Error reading manifest: ${err.message}`);
    process.exit(1);
  }

  try {
    const result = await verifyManifest(filePath, manifest, opts);

    if (result.success) {
      console.log(`VERIFIED`);
      console.log(`  match_type:               ${result.match_type}`);
      if (result.signature_verified)          console.log(`  signature:                verified`);
      if (result.manifest_signature_verified) console.log(`  manifest_signature:       verified`);
      if (result.anchor_checked)              console.log(`  anchor:                   ${result.anchor_verified ? "verified" : "checked (mismatch)"}`);
      if (result.warnings && result.warnings.length > 0) {
        result.warnings.forEach(w => console.log(`  warning:                  ${w}`));
      }
    } else {
      console.log(`FAILED`);
      console.log(`  reason: ${result.message}`);
      process.exit(2);
    }
  } catch (err) {
    console.error(`Error during verification: ${err.message}`);
    process.exit(1);
  }
}

// ── Help ──────────────────────────────────────────────────────────────────────

function printHelp() {
  console.log(`
AIOSchema v${SPEC_VERSION} | Cryptographic content provenance

USAGE
  aioschema keygen
  aioschema generate <file> [options]
  aioschema verify <file> <manifest.aios.json> [options]

COMMANDS
  keygen      Generate an Ed25519 keypair and print creator_id, public_key, private_key
  generate    Generate a .aios.json manifest for a file
  verify      Verify a file against its manifest

OPTIONS (generate)
  --algorithm, -a   Hash algorithm: sha256 (default) or sha384 (repeatable for multi-hash)
  --creator-id      Creator ID in ed25519-fp-<hex> format (use keygen to derive)
  --private-key     Base64-encoded Ed25519 private key seed; enables Level 2 signing
  --ext key=value   Add an extension field (repeatable)

OPTIONS (verify)
  --public-key      Base64-encoded Ed25519 public key (32 bytes); required for signed manifests

GLOBAL
  --version, -v     Print version
  --help, -h        Print this help

EXAMPLES
  # Generate a keypair (do once; store private_key securely)
  aioschema keygen

  # Level 1: unsigned manifest
  aioschema generate report.pdf

  # Level 1: with creator ID and SHA-384
  aioschema generate image.png --algorithm sha384 --creator-id ed25519-fp-<hex>

  # Level 2: signed manifest
  aioschema generate article.md --private-key <base64>

  # Level 2: signed, with extensions
  aioschema generate article.md \\
    --private-key <base64> \\
    --ext asset_name=article.md \\
    --ext asset_type=document \\
    --ext description="My article description"

  # Verify: unsigned (Level 1)
  aioschema verify report.pdf report.pdf.aios.json

  # Verify: signed (Level 2)
  aioschema verify report.pdf report.pdf.aios.json --public-key <base64>

SPEC    https://aioschema.org
`);
}

// -- end aioschema/cli v0.5.13 | AIOSchema spec v0.5.6 --
