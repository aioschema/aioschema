# @aioschema/cli

**AIOSchema v0.5.5 — Command-line tool for generating and verifying provenance manifests.**

- Spec: [aioschema.org](https://aioschema.org)
- Hub: [aioschemahub.com](https://aioschemahub.com)

---

## Install
```bash
npm install -g @aioschema/cli
```

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

## Library

For programmatic use, see [@aioschema/js](../implementations/js/README.md).

---

## License

Apache 2.0. See [LICENSE.md](./LICENSE.md).  
Specification: CC-BY 4.0 — [aioschema.org](https://aioschema.org)
