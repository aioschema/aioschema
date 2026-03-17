package aioschema

import (
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

// ── Regex patterns (§5.3, §5.7, §5.4, §5.2) ─────────────────────────────────

var (
	// HashPattern: (sha256|sha3-256)-[0-9a-f]{64} OR sha384-[0-9a-f]{96}
	HashPattern = regexp.MustCompile(
		`^(sha256|sha3-256)-[0-9a-f]{64}$|^sha384-[0-9a-f]{96}$`,
	)

	// SignaturePattern: ed25519-<128 hex chars>
	SignaturePattern = regexp.MustCompile(`^ed25519-[0-9a-f]{128}$`)

	// AnchorPattern: aios-anchor:<method>:<id>
	AnchorPattern = regexp.MustCompile(`^aios-anchor:[a-z0-9_-]+:[a-zA-Z0-9_-]+$`)

	// TimestampPattern: strict ISO-8601 UTC with Z suffix (§5.2)
	TimestampPattern = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$`)

	// CreatorIDAttributedPattern: ed25519-fp-<32 hex chars>
	CreatorIDAttributedPattern = regexp.MustCompile(`^ed25519-fp-[0-9a-f]{32}$`)
)

// ── Hash computation ──────────────────────────────────────────────────────────

// ComputeHash hashes data with the named algorithm and returns a prefixed hex string.
// Supported algorithms: "sha256", "sha384", "sha3-256".
// Returns an error for unsupported algorithms.
func ComputeHash(data []byte, algorithm string) (string, error) {
	switch algorithm {
	case "sha256":
		h := sha256.Sum256(data)
		return "sha256-" + hex.EncodeToString(h[:]), nil
	case "sha384":
		h := sha512.Sum384(data)
		return "sha384-" + hex.EncodeToString(h[:]), nil
	case "sha3-256":
		h := sha3_256Sum(data)
		return "sha3-256-" + hex.EncodeToString(h[:]), nil
	default:
		return "", fmt.Errorf("unsupported hash algorithm %q; supported: sha256, sha384, sha3-256", algorithm)
	}
}

// MustComputeHash is like ComputeHash but panics on error (use only in tests).
func MustComputeHash(data []byte, algorithm string) string {
	s, err := ComputeHash(data, algorithm)
	if err != nil {
		panic(err)
	}
	return s
}

// ParseHashPrefix splits "alg-hexdigest" into (algorithm, hexdigest).
// Returns an error if the value does not match the hash pattern.
func ParseHashPrefix(value string) (alg, digest string, err error) {
	if !HashPattern.MatchString(value) {
		return "", "", fmt.Errorf("invalid hash value %q: expected (sha256|sha3-256)-<64hex> or sha384-<96hex>", value)
	}
	// sha3-256 has a hyphen in the algorithm token; handle it first.
	if strings.HasPrefix(value, "sha3-256-") {
		return "sha3-256", value[len("sha3-256-"):], nil
	}
	idx := strings.Index(value, "-")
	return value[:idx], value[idx+1:], nil
}

// safeEqualString performs a timing-safe string comparison (§12.1).
func safeEqualString(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// ── Canonical JSON ────────────────────────────────────────────────────────────

// CanonicalJSON returns the deterministic, compact JSON encoding of v with
// all object keys sorted recursively — the canonical form required by §5.6.
// The result is UTF-8 encoded bytes.
func CanonicalJSON(v interface{}) ([]byte, error) {
	sorted := sortValue(v)
	return json.Marshal(sorted)
}

// sortValue recursively sorts map keys to produce canonical JSON.
func sortValue(v interface{}) interface{} {
	switch val := v.(type) {
	case map[string]interface{}:
		// Build a sorted-key wrapper using json.RawMessage to preserve Go's
		// map marshaling sorted by key (Go's encoding/json sorts map keys).
		result := make(map[string]interface{}, len(val))
		for k, elem := range val {
			result[k] = sortValue(elem)
		}
		return result
	case []interface{}:
		result := make([]interface{}, len(val))
		for i, elem := range val {
			result[i] = sortValue(elem)
		}
		return result
	default:
		return v
	}
}

// canonicalCoreFields extracts only the CORE_HASH_FIELDS from a raw core map
// and returns their canonical JSON bytes. Used to compute/verify core_fingerprint.
func canonicalCoreFields(core map[string]interface{}) ([]byte, error) {
	subset := make(map[string]interface{}, len(CoreHashFields))
	for _, field := range CoreHashFields {
		if val, ok := core[field]; ok {
			subset[field] = val
		}
	}
	return CanonicalJSON(subset)
}

// canonicalManifestBytes serializes the entire manifest for manifest_signature
// verification (§5.8). manifest_signature is set to null before serialization
// to avoid circular dependency.
func canonicalManifestBytes(m map[string]interface{}) ([]byte, error) {
	// Deep copy to avoid mutating caller's data
	data, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	var copy_ map[string]interface{}
	if err := json.Unmarshal(data, &copy_); err != nil {
		return nil, err
	}
	if core, ok := copy_["core"].(map[string]interface{}); ok {
		core["manifest_signature"] = nil
	}
	return CanonicalJSON(copy_)
}
