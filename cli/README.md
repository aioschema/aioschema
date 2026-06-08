<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 Ovidiu Ancuta -->
<!-- aioschema/cli v0.5.13 | AIOSchema spec v0.5.6 | https://aioschema.org -->

# @aioschema/cli
**AIOSchema v0.5.6: Command-line tool for generating and verifying provenance manifests.**
- Spec: [aioschema.org](https://aioschema.org)

---

## Install

```bash
npm install -g @aioschema/cli
```

Available commands and options are printed automatically after install.

> **Note:** You can also run directly from source without installing:
> ```bash
> git clone https://github.com/aioschema/aioschema.git
> cd aioschema/tools/cli
> node cli.js --help
> ```

---

## Usage

```bash
# Generate a keypair (do once; store private_key securely)
aioschema keygen

# Generate an unsigned manifest (Level 1)
aioschema generate myfile.pdf

# Generate with SHA-384
aioschema generate myfile.pdf --algorithm sha384

# Generate with your creator ID (Level 1, attributed)
aioschema generate myfile.pdf --creator-id ed25519-fp-ebc64203390ddefc442ade9038e1ae18

# Generate a signed manifest (Level 2)
aioschema generate myfile.pdf --private-key <base64-private-key>

# Generate signed with extensions (Level 2)
aioschema generate article.md \
  --private-key <base64-private-key> \
  --ext asset_name=article.md \
  --ext asset_type=document \
  --ext description="My article about digital provenance"

# Verify an unsigned manifest (Level 1)
aioschema verify myfile.pdf myfile.pdf.aios.json

# Verify a signed manifest (Level 2)
aioschema verify myfile.pdf myfile.pdf.aios.json --public-key <base64-public-key>

# Help
aioschema --help

# Version
aioschema --version
```

---

## What it produces

Running `aioschema generate` writes a `.aios.json` manifest alongside your file:

```
myfile.pdf
myfile.pdf.aios.json   ← manifest
```

The manifest cryptographically describes your file: what it is, when it existed, and who created it. Verifiable forever by any conforming AIOSchema implementation.

---

## Compliance levels

| Level | Description | Requires |
|-------|-------------|----------|
| 1 | Unsigned: hash and core fingerprint | Nothing |
| 2 | Signed: adds Ed25519 signature over core and full manifest | `--private-key` on generate; `--public-key` on verify |
| 3 | Anchored: adds RFC 3161 timestamp | Anchor API key |

---

## Generating a keypair

Run `aioschema keygen` once. It prints three values:

```
creator_id:  ed25519-fp-<32 hex chars>
public_key:  <base64, 32 bytes>
private_key: <base64, 32 bytes>
```

Store `private_key` securely (environment variable, secrets manager, or encrypted file; never commit to version control). Use `creator_id` as your identity across all manifests. Pass `private_key` to `--private-key` when generating Level 2 manifests and `public_key` to `--public-key` when verifying them.

---

## Extension fields

Use `--ext key=value` to add metadata to the manifest's `extensions` block. The flag is repeatable; pass it once per field:

```bash
aioschema generate article.md \
  --private-key <base64> \
  --ext asset_name=article.md \
  --ext asset_type=document \
  --ext description="LinkedIn article: Understanding Digital Provenance"
```

Extension fields are informational and do not affect Core Block integrity or Level 1 verification.

---

## Library

For programmatic use, see [@aioschema/js](../../implementations/js/README.md).

---

## License

Apache 2.0. See [LICENSE.md](./LICENSE.md).
Specification: CC-BY 4.0, [aioschema.org](https://aioschema.org)

<!-- end aioschema/cli v0.5.13 | AIOSchema spec v0.5.6 | https://aioschema.org -->
