# @aioschema/cli
**AIOSchema v0.5.5 — Command-line tool for generating and verifying provenance manifests.**
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
> cd aioschema/cli
> node cli.js --help
> ```
---
## Usage
```bash
# Generate a manifest for any file
aioschema generate myfile.pdf
# Generate with SHA-384
aioschema generate myfile.pdf --algorithm sha384
# Generate with your creator ID
aioschema generate myfile.pdf --creator-id ed25519-fp-ebc64203390ddefc442ade9038e1ae18
# Generate with extension fields
aioschema generate article.md \
  --creator-id ed25519-fp-ebc64203390ddefc442ade9038e1ae18 \
  --ext asset_name=article.md \
  --ext asset_type=document \
  --ext description="My article about digital provenance"
# Verify a file against its manifest
aioschema verify myfile.pdf myfile.pdf.aios.json
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
The manifest cryptographically describes your file — what it is, when it existed, and who created it. Verifiable forever by any conforming AIOSchema implementation.
---
## Extension fields
Use `--ext key=value` to add metadata to the manifest's `extensions` block. The flag is repeatable — pass it once per field:
```bash
aioschema generate article.md \
  --creator-id ed25519-fp-ebc64203390ddefc442ade9038e1ae18 \
  --ext asset_name=article.md \
  --ext asset_type=document \
  --ext description="LinkedIn article: Understanding Digital Provenance"
```
Extension fields are informational and do not affect Core Block integrity or Level 1 verification.
---
## Creator ID
The `--creator-id` flag is optional but important.
**Without it:** a new unique ID is auto-generated every time you run `generate`. Each file gets a different creator ID — there is no link between them. This is fine for one-off provenance but means you cannot prove that two files came from the same author.
**With it:** every manifest you generate carries the same identity. Anyone verifying your files can confirm they all came from the same creator. This is the recommended approach for anyone publishing content, releasing software, or establishing a consistent authorship record.
Your creator ID is derived from your Ed25519 public key and has the format:
```
ed25519-fp-<64 hex characters>
```
Generate it once, store it safely, and use it for all your files. See the [implementation docs](../implementations/API.md) for how to generate a keypair and derive your creator ID.
---
## Library
For programmatic use, see [@aioschema/js](../implementations/js/README.md).
---
## License
Apache 2.0. See [LICENSE.md](./LICENSE.md).  
Specification: CC-BY 4.0 — [aioschema.org](https://aioschema.org)
