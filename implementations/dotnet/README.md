<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 Ovidiu Ancuta -->
<!-- aioschema/dotnet v0.5.6 | AIOSchema spec v0.5.6 | https://aioschema.org -->

# AIOSchema v0.5.6 — .NET Reference Implementation

C# / .NET 8 reference implementation of the AIOSchema content provenance standard.

## Requirements

- .NET 8 SDK (no system packages required)

## Build and test

```bash
dotnet restore   # no network required (zero external NuGet dependencies)
dotnet run       # runs all 56 tests
```

## Test results

```
56 passed, 0 failed, 56 total
  - 42 unit tests
  - 18/18 cross-verification vectors
```

## Dependencies

| Dependency | Source | Purpose |
|---|---|---|
| .NET 8 BCL | Built-in | SHA-256, SHA-384, SHA3-256, SHA-512, JSON, UUID, BigInteger |

Zero external dependencies of any kind -- no NuGet packages, no system libraries.

## Source files

| File | Purpose |
|---|---|
| `Types.cs` | Constants, patterns, `CoreBlock`, `AIOSManifest`, `VerificationResult`, `CreatorId` |
| `Uuid7.cs` | UUID v7 generator |
| `Ed25519.cs` | Pure managed Ed25519 per RFC 8032 (no external deps) |
| `Algorithms.cs` | Hash, canonical JSON, core fingerprint, sign/verify |
| `Manifest.cs` | Manifest builder, JSON serialization, sidecar I/O |
| `Verify.cs` | 12-step verification procedure (§10) |
| `Program.cs` | Test runner (unit tests + cross-verify) |

## Key design notes

- Private key = 32-byte seed (RFC 8032). Public key = 32 bytes.
- `creator_id` fingerprint = SHA-256(public_key_bytes)[0:32 hex chars]
- SHA3-256 uses .NET 8 BCL `System.Security.Cryptography.SHA3_256` (FIPS 202)
- Canonical JSON: recursive key sort, no whitespace, UTF-8
- `core_fingerprint` must not appear in `CORE_HASH_FIELDS` (bootstrap rule)
- `hash_schema_block` accepted as deprecated alias for `core_fingerprint`

## Production deployment guidance

This is the AIOSchema Reference Implementation. Its primary purpose is to
provide a human-readable, zero-dependency source of truth for the specification.

**Verification** -- fully recommended for all contexts: manifest verification,
audit logging, conformance testing, and CI pipelines. The verifier uses public
keys only; no side-channel risk applies.

**Signing (reference / developer tooling)** -- suitable for cold-path signing:
manual manifest generation, developer tools, and test harnesses where signing
frequency is low and the environment is trusted.

**Signing (production / high-frequency)** -- for servers processing thousands
of manifests per second, or environments requiring formal side-channel resistance,
use the Hybrid Auditor/Vault model:
- **Verification path:** use this implementation (zero-dependency, auditable).
- **Signing path:** delegate to a FIPS-validated native library (libsodium,
  OpenSSL) or a Hardware Security Module (HSM/Azure Key Vault/AWS KMS).

This distinction is not a weakness of the reference implementation -- it is
correct architectural layering. The reference implementation defines what is
correct; the production signing path defines how to do it fast and safely
under adversarial conditions.

---

## Links
- **Specification:** [aioschema.org](https://aioschema.org)
- **Field reference:** [aioschema.org/field-reference/v0-5-6/](https://aioschema.org/field-reference/v0-5-6/)
- **All implementations:** [github.com/aioschema/aioschema](https://github.com/aioschema/aioschema)

---

## License

Apache 2.0. See [LICENSE.md](./LICENSE.md).

Specification: CC-BY 4.0 — [aioschema.org](https://aioschema.org)

<!-- end aioschema/dotnet v0.5.6 | AIOSchema spec v0.5.6 -->
