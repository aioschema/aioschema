<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 Ovidiu Ancuta -->
<!-- aioschema/go v0.5.6 | AIOSchema spec v0.5.6 | https://aioschema.org -->

# aioschema/go

**AIOSchema v0.5.6 — Go reference implementation.**

Pure Go. Zero external dependencies. Requires Go 1.21 or later.

- Spec: [aioschema.org](https://aioschema.org)

---

## Install

```bash
go get github.com/aioschemahub/aioschema
```

---

## API

```go
import "github.com/aioschemahub/aioschema"

// Generate a manifest
manifest, err := aioschema.GenerateManifest(assetBytes, aioschema.GenerateOptions{
    Algorithm: "sha256",
})

// Generate with Ed25519 signing
manifest, err := aioschema.GenerateManifest(assetBytes, aioschema.GenerateOptions{
    PrivateKey: privateKey,
    CreatorID:  "ed25519-fp-ebc64203390ddefc442ade9038e1ae18",
})

// Verify
result, err := aioschema.VerifyManifest(assetBytes, manifest, aioschema.VerifyOptions{})
fmt.Println(result.Success)    // true
fmt.Println(result.MatchType)  // "hard"

// Verify with explicit public key
result, err := aioschema.VerifyManifest(assetBytes, manifest, aioschema.VerifyOptions{
    PublicKeyHex: "d71a1ce4802db551a967d32b6cbc0fef4e8cd3f3939b697....",
})
fmt.Println(result.SignatureVerified) // true
```

---

## Full API reference

```go
// Manifest generation and verification
aioschema.GenerateManifest(assetData []byte, opts GenerateOptions) (*Manifest, error)
aioschema.VerifyManifest(assetData []byte, m *Manifest, opts VerifyOptions) (*VerificationResult, error)
aioschema.SignManifest(m *Manifest, privateKey ed25519.PrivateKey) error

// Creator ID
aioschema.CreatorIDFromPublicKey(pub ed25519.PublicKey) string

// Hashing
aioschema.ComputeHash(data []byte, algorithm string) (string, error)
aioschema.MustComputeHash(data []byte, algorithm string) string
aioschema.ParseHashPrefix(value string) (alg, digest string, err error)

// Canonical serialization
aioschema.CanonicalJSON(v interface{}) ([]byte, error)

// Sidecar I/O
aioschema.LoadManifest(path string) (*Manifest, error)
aioschema.SidecarPath(assetPath string) string

// Timing-safe comparison
aioschema.SafeEqual(a, b string) bool   // via algorithms package

// Constants
aioschema.SpecVersion                   // "0.5.6"
aioschema.SupportedVersions             // map[string]bool
aioschema.CoreHashFields                // []string
aioschema.DefaultHashAlgorithm          // "sha256"
aioschema.MaxExtensionSizeBytes         // 4096
aioschema.SoftBindingThresholdDefault   // 5
aioschema.SoftBindingThresholdMax       // 10
aioschema.SidecarSuffix                 // ".aios.json"
```

---

## Running tests

```bash
# Unit tests
go test ./...

# Cross-implementation verification (18 deterministic vectors)
AIOSCHEMA_VECTORS=/path/to/cross_verify_vectors.json go test -run TestCrossVerify ./...

# Verbose output
go test -v ./...
```

---

## File structure

```
implementations/go/
├── algorithms.go           # Hash computation, canonical JSON, regex patterns
├── manifest.go             # Manifest generation, signing, sidecar I/O
├── sha3.go                 # Pure Go SHA3-256 (zero external dependencies)
├── types.go                # Type definitions and constants
├── verify.go               # §10 verification procedure
├── aioschema_test.go       # Unit tests
├── cross_verify_test.go    # 18 cross-implementation vectors
├── go.mod                  # Module definition
├── cross_verify_vectors.json
├── README.md
└── LICENSE.md
```

---

## License

Apache 2.0. See [LICENSE.md](./LICENSE.md).

Specification: CC-BY 4.0 — [aioschema.org](https://aioschema.org)

<!-- end aioschema/go v0.5.6 | AIOSchema spec v0.5.6 -->
