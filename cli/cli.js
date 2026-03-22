#!/usr/bin/env node
"use strict";
/**
 * AIOSchema v0.5.5 — CLI
 * ======================
 * Usage:
 *   aioschema generate <file> [--algorithm sha256|sha384] [--creator-id <id>] [--ext key=value]
 *   aioschema verify <file> <manifest.aios.json>
 *   aioschema --version
 *   aioschema --help
 */

const fs   = require("node:fs");
const path = require("node:path");
const aios = require("@aioschema/js");

const { generateManifest, verifyManifest, sidecarPath, SPEC_VERSION } = aios;

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

if (command === "generate") {
  runGenerate(args.slice(1));
} else if (command === "verify") {
  runVerify(args.slice(1));
} else {
  console.error(`Unknown command: ${command}`);
  console.error(`Run 'aioschema --help' for usage.`);
  process.exit(1);
}

// ── Commands ──────────────────────────────────────────────────────────────────

function runGenerate(args) {
  const positional = [];
  const opts       = {};

  for (let i = 0; i < args.length; i++) {
    if (args[i] === "--algorithm" || args[i] === "-a") {
      opts.hashAlgorithm = args[++i];
    } else if (args[i] === "--creator-id") {
      opts.creatorId = args[++i];
    } else if (args[i] === "--ext") {
      const raw = args[++i];
      const eq  = raw.indexOf("=");
      if (eq === -1) {
        console.error(`Error: --ext requires key=value format, got: ${raw}`);
        process.exit(1);
      }
      const k = raw.slice(0, eq);
      const v = raw.slice(eq + 1);
      opts.extensions = opts.extensions || {};
      opts.extensions[k] = v;
    } else {
      positional.push(args[i]);
    }
  }

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

    if (opts.extensions) {
      manifest.extensions = { ...manifest.extensions, ...opts.extensions };
    }

    fs.writeFileSync(out, JSON.stringify(manifest, null, 2), "utf8");
    console.log(`✓ Manifest written: ${out}`);
    console.log(`  asset_id:         ${manifest.core.asset_id}`);
    console.log(`  hash_original:    ${Array.isArray(manifest.core.hash_original)
      ? manifest.core.hash_original.join(", ")
      : manifest.core.hash_original}`);
    console.log(`  core_fingerprint: ${manifest.core.core_fingerprint}`);
    console.log(`  creator_id:       ${manifest.core.creator_id}`);
    if (opts.extensions) {
      console.log(`  extensions:       ${Object.keys(opts.extensions).join(", ")}`);
    }
  } catch (err) {
    console.error(`Error generating manifest: ${err.message}`);
    process.exit(1);
  }
}

async function runVerify(args) {
  const filePath     = args[0];
  const manifestPath = args[1];

  if (!filePath || !manifestPath) {
    console.error("Error: file path and manifest path required.");
    console.error("Usage: aioschema verify <file> <manifest.aios.json>");
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
    const result = await verifyManifest(filePath, manifest);

    if (result.success) {
      console.log(`◈ VERIFIED`);
      console.log(`  match_type: ${result.match_type}`);
      if (result.signature_verified) console.log(`  signature:  verified`);
      if (result.warnings && result.warnings.length > 0) {
        result.warnings.forEach(w => console.log(`  warning:    ${w}`));
      }
    } else {
      console.log(`✗ FAILED`);
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
AIOSchema v${SPEC_VERSION} — Cryptographic content provenance

USAGE
  aioschema generate <file> [options]
  aioschema verify <file> <manifest.aios.json>

COMMANDS
  generate    Generate a .aios.json manifest for a file
  verify      Verify a file against its manifest

OPTIONS (generate)
  --algorithm, -a   Hash algorithm: sha256 (default) or sha384
  --creator-id      Creator ID in ed25519-fp-<hex> format
  --ext key=value   Add an extension field (repeatable)

GLOBAL
  --version, -v     Print version
  --help, -h        Print this help

EXAMPLES
  aioschema generate report.pdf
  aioschema generate image.png --algorithm sha384
  aioschema generate article.md --creator-id  ed25519-fp-<hex> format
  aioschema generate article.md \\
    --creator-id  ed25519-fp-<hex> format \\
    --ext asset_name=article.md \\
    --ext asset_type=document \\
    --ext description="My article description"
  aioschema verify report.pdf report.pdf.aios.json

SPEC    https://aioschema.org
HUB     https://aioschemahub.com
`);
}
