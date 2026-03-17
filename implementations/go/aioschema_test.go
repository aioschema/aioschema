package aioschema_test

// aioschema_test.go
//
// Unit tests for:
//   - ComputeHash
//   - CanonicalJSON
//   - VerifyManifest (selected cases)

import (
	"strings"
	"testing"

	"github.com/aioschemahub/aioschema"
)

// ── ComputeHash ───────────────────────────────────────────────────────────────

func TestComputeHash_SHA256_KnownVector(t *testing.T) {
	// "The quick brown fox jumps over the lazy dog"
	data := []byte("The quick brown fox jumps over the lazy dog")
	got, err := aioschema.ComputeHash(data, "sha256")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := "sha256-d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592"
	if got != want {
		t.Errorf("got %s\nwant %s", got, want)
	}
}

func TestComputeHash_SHA384_KnownVector(t *testing.T) {
	data := []byte("The quick brown fox jumps over the lazy dog")
	got, err := aioschema.ComputeHash(data, "sha384")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := "sha384-ca737f1014a48f4c0b6dd43cb177b0afd9e5169367544c494011e3317dbf9a509cb1e5dc1e85a941bbee3d7f2afbc9b1"
	if got != want {
		t.Errorf("got %s\nwant %s", got, want)
	}
}

func TestComputeHash_SHA256_Empty(t *testing.T) {
	got, err := aioschema.ComputeHash([]byte{}, "sha256")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := "sha256-e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	if got != want {
		t.Errorf("got %s\nwant %s", got, want)
	}
}

func TestComputeHash_PrefixFormat(t *testing.T) {
	tests := []struct {
		alg    string
		prefix string
		length int // expected total length of result
	}{
		{"sha256", "sha256-", 7 + 64},
		{"sha384", "sha384-", 7 + 96},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.alg, func(t *testing.T) {
			got, err := aioschema.ComputeHash([]byte("test"), tc.alg)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !strings.HasPrefix(got, tc.prefix) {
				t.Errorf("result %q does not have prefix %q", got, tc.prefix)
			}
			if len(got) != tc.length {
				t.Errorf("result length %d, want %d", len(got), tc.length)
			}
		})
	}
}

func TestComputeHash_UnsupportedAlgorithm(t *testing.T) {
	_, err := aioschema.ComputeHash([]byte("x"), "md5")
	if err == nil {
		t.Error("expected error for unsupported algorithm md5, got nil")
	}
}

func TestComputeHash_Deterministic(t *testing.T) {
	data := []byte("determinism check")
	a, _ := aioschema.ComputeHash(data, "sha256")
	b, _ := aioschema.ComputeHash(data, "sha256")
	if a != b {
		t.Errorf("non-deterministic: %s != %s", a, b)
	}
}

// ── ParseHashPrefix ───────────────────────────────────────────────────────────

func TestParseHashPrefix_SHA256(t *testing.T) {
	alg, digest, err := aioschema.ParseHashPrefix("sha256-" + strings.Repeat("a", 64))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if alg != "sha256" {
		t.Errorf("alg=%q, want sha256", alg)
	}
	if len(digest) != 64 {
		t.Errorf("digest length %d, want 64", len(digest))
	}
}

func TestParseHashPrefix_SHA384(t *testing.T) {
	alg, digest, err := aioschema.ParseHashPrefix("sha384-" + strings.Repeat("b", 96))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if alg != "sha384" {
		t.Errorf("alg=%q, want sha384", alg)
	}
	if len(digest) != 96 {
		t.Errorf("digest length %d, want 96", len(digest))
	}
}

func TestParseHashPrefix_Invalid(t *testing.T) {
	invalids := []string{
		"",
		"sha256-",                     // missing digest
		"sha256-" + strings.Repeat("a", 63), // too short
		"sha256-" + strings.Repeat("a", 65), // too long
		"md5-" + strings.Repeat("a", 32),    // unsupported
		"sha384-" + strings.Repeat("a", 64), // wrong length for sha384
		"notahash",
	}
	for _, v := range invalids {
		v := v
		t.Run(v, func(t *testing.T) {
			_, _, err := aioschema.ParseHashPrefix(v)
			if err == nil {
				t.Errorf("expected error for %q, got nil", v)
			}
		})
	}
}

// ── CanonicalJSON ─────────────────────────────────────────────────────────────

func TestCanonicalJSON_SortsKeys(t *testing.T) {
	obj := map[string]interface{}{
		"z": "last",
		"a": "first",
		"m": "middle",
	}
	got, err := aioschema.CanonicalJSON(obj)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := `{"a":"first","m":"middle","z":"last"}`
	if string(got) != want {
		t.Errorf("got  %s\nwant %s", got, want)
	}
}

func TestCanonicalJSON_NoWhitespace(t *testing.T) {
	obj := map[string]interface{}{"k": "v"}
	got, err := aioschema.CanonicalJSON(obj)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.ContainsAny(string(got), " \t\n\r") {
		t.Errorf("canonical JSON must not contain whitespace, got: %s", got)
	}
}

func TestCanonicalJSON_KnownVector(t *testing.T) {
	// CV-05 inputs
	obj := map[string]interface{}{
		"hash_original":      "sha256-abc123",
		"asset_id":           "urn:test:001",
		"creator_id":         "ed25519-fp-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"schema_version":     "0.5.5",
		"creation_timestamp": "2026-02-22T12:00:00Z",
	}
	got, err := aioschema.CanonicalJSON(obj)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := `{"asset_id":"urn:test:001","creation_timestamp":"2026-02-22T12:00:00Z","creator_id":"ed25519-fp-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","hash_original":"sha256-abc123","schema_version":"0.5.5"}`
	if string(got) != want {
		t.Errorf("got  %s\nwant %s", got, want)
	}
}

func TestCanonicalJSON_NestedSorting(t *testing.T) {
	obj := map[string]interface{}{
		"outer": map[string]interface{}{
			"z": 1,
			"a": 2,
		},
	}
	got, err := aioschema.CanonicalJSON(obj)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := `{"outer":{"a":2,"z":1}}`
	if string(got) != want {
		t.Errorf("got  %s\nwant %s", got, want)
	}
}

func TestCanonicalJSON_Deterministic(t *testing.T) {
	obj := map[string]interface{}{
		"c": 3, "b": 2, "a": 1,
	}
	a, _ := aioschema.CanonicalJSON(obj)
	b, _ := aioschema.CanonicalJSON(obj)
	if string(a) != string(b) {
		t.Errorf("non-deterministic: %s vs %s", a, b)
	}
}

// ── VerifyManifest ────────────────────────────────────────────────────────────

// Helper: build the fixed CV-07 manifest
func cv07Manifest() *aioschema.Manifest {
	cfp := "sha256-d61f35a9cbd7138874ab81017e78023f9ed8e1e9f8d458787078597cc8d082f4"
	return &aioschema.Manifest{
		Core: aioschema.Core{
			AssetID:           "00000000-0000-7000-8000-000000000001",
			SchemaVersion:     "0.5.5",
			CreationTimestamp: "2026-02-22T12:00:00Z",
			HashOriginal:      aioschema.HashOriginal{Single: "sha256-88dedaf2e6b9c5ef7f32171831c1d6c39446d754ddc924a0792dd0f8100de15a"},
			CreatorID:         "ed25519-fp-00000000000000000000000000000000",
			CoreFingerprint:   &cfp,
		},
		Extensions: map[string]interface{}{},
	}
}

func cv07Asset() []byte {
	b, _ := hexDecodeStrict("43562d303720666978656420617373657420636f6e74656e7420666f722063726f73732d766572696669636174696f6e")
	return b
}

func hexDecodeStrict(s string) ([]byte, error) {
	b := make([]byte, len(s)/2)
	for i := 0; i < len(s); i += 2 {
		hi := hexVal(s[i])
		lo := hexVal(s[i+1])
		b[i/2] = (hi << 4) | lo
	}
	return b, nil
}

func hexVal(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10
	}
	return 0
}

func TestVerifyManifest_ValidHardMatch(t *testing.T) {
	result, err := aioschema.VerifyManifest(cv07Asset(), cv07Manifest(), aioschema.VerifyOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Success {
		t.Errorf("expected success, got: %s", result.Message)
	}
	if result.MatchType != "hard" {
		t.Errorf("match_type=%q, want hard", result.MatchType)
	}
}

func TestVerifyManifest_TamperedHashOriginal(t *testing.T) {
	m := cv07Manifest()
	bad := "sha256-" + strings.Repeat("0", 64)
	m.Core.HashOriginal = aioschema.HashOriginal{Single: bad}
	result, err := aioschema.VerifyManifest(cv07Asset(), m, aioschema.VerifyOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Success {
		t.Error("expected failure for tampered hash_original, got success")
	}
}

func TestVerifyManifest_TamperedCoreFingerprint(t *testing.T) {
	m := cv07Manifest()
	bad := "sha256-" + strings.Repeat("f", 64)
	m.Core.CoreFingerprint = &bad
	result, err := aioschema.VerifyManifest(cv07Asset(), m, aioschema.VerifyOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Success {
		t.Error("expected failure for tampered core_fingerprint, got success")
	}
}

func TestVerifyManifest_UnsupportedSchemaVersion(t *testing.T) {
	m := cv07Manifest()
	m.Core.SchemaVersion = "99.0"
	result, err := aioschema.VerifyManifest(cv07Asset(), m, aioschema.VerifyOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Success {
		t.Errorf("expected failure for unsupported schema_version, got success")
	}
}

func TestVerifyManifest_MissingCreatorID(t *testing.T) {
	m := cv07Manifest()
	m.Core.CreatorID = ""
	result, err := aioschema.VerifyManifest(cv07Asset(), m, aioschema.VerifyOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Success {
		t.Error("expected failure for missing creator_id, got success")
	}
}

func TestVerifyManifest_InvalidTimestamp(t *testing.T) {
	m := cv07Manifest()
	m.Core.CreationTimestamp = "2026-02-22 12:00:00" // missing T and Z
	result, err := aioschema.VerifyManifest(cv07Asset(), m, aioschema.VerifyOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Success {
		t.Error("expected failure for invalid timestamp format, got success")
	}
}

func TestVerifyManifest_HashSchemaBlockAlias(t *testing.T) {
	// CV-10: manifests using deprecated hash_schema_block must verify successfully
	hsb := "sha256-d61f35a9cbd7138874ab81017e78023f9ed8e1e9f8d458787078597cc8d082f4"
	m := &aioschema.Manifest{
		Core: aioschema.Core{
			AssetID:           "00000000-0000-7000-8000-000000000001",
			SchemaVersion:     "0.5.5",
			CreationTimestamp: "2026-02-22T12:00:00Z",
			HashOriginal:      aioschema.HashOriginal{Single: "sha256-88dedaf2e6b9c5ef7f32171831c1d6c39446d754ddc924a0792dd0f8100de15a"},
			CreatorID:         "ed25519-fp-00000000000000000000000000000000",
			HashSchemaBlock:   &hsb, // use deprecated alias, no CoreFingerprint
		},
		Extensions: map[string]interface{}{},
	}
	result, err := aioschema.VerifyManifest(cv07Asset(), m, aioschema.VerifyOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Success {
		t.Errorf("expected success with hash_schema_block alias, got: %s", result.Message)
	}
}

func TestVerifyManifest_MultiHash(t *testing.T) {
	// CV-11: multi-hash array — any match is sufficient
	cfp := "sha256-6391625df74b27daa78eda3a4ed84a3b578094792b67dc04782b4164bdd6a4c7"
	m := &aioschema.Manifest{
		Core: aioschema.Core{
			AssetID:           "00000000-0000-7000-8000-000000000001",
			SchemaVersion:     "0.5.5",
			CreationTimestamp: "2026-02-22T12:00:00Z",
			HashOriginal: aioschema.HashOriginal{
				Multi: []string{
					"sha256-88dedaf2e6b9c5ef7f32171831c1d6c39446d754ddc924a0792dd0f8100de15a",
					"sha384-8683ae6457999d73454fc65e8e1930d5603130c1ac0085b1a7249ad7e8943a24e3524d42d9298ff70ff664074043eb9d",
				},
				IsMulti: true,
			},
			CreatorID:       "ed25519-fp-00000000000000000000000000000000",
			CoreFingerprint: &cfp,
		},
		Extensions: map[string]interface{}{},
	}
	result, err := aioschema.VerifyManifest(cv07Asset(), m, aioschema.VerifyOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Success {
		t.Errorf("expected success for multi-hash manifest, got: %s", result.Message)
	}
}

func TestVerifyManifest_NonUTCTimestamp(t *testing.T) {
	m := cv07Manifest()
	m.Core.CreationTimestamp = "2026-02-22T12:00:00+05:00"
	result, err := aioschema.VerifyManifest(cv07Asset(), m, aioschema.VerifyOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Success {
		t.Error("expected failure for non-UTC timestamp (+HH:MM offset)")
	}
}

func TestVerifyManifest_AnchorWarningNotFailure(t *testing.T) {
	// anchor_reference present but VerifyAnchor=false → warning, not failure
	m := cv07Manifest()
	anchor := "aios-anchor:ots:abc123"
	m.Core.AnchorReference = &anchor
	result, err := aioschema.VerifyManifest(cv07Asset(), m, aioschema.VerifyOptions{
		VerifyAnchor: false,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Success {
		t.Errorf("anchor_reference with VerifyAnchor=false must not fail, got: %s", result.Message)
	}
	foundWarning := false
	for _, w := range result.Warnings {
		if strings.Contains(w, "anchor_reference") {
			foundWarning = true
		}
	}
	if !foundWarning {
		t.Error("expected warning about unverified anchor_reference")
	}
}

func TestVerifyManifest_UnsignedPassesWithoutKey(t *testing.T) {
	// unsigned manifests must pass even when no public key is provided
	result, err := aioschema.VerifyManifest(cv07Asset(), cv07Manifest(), aioschema.VerifyOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Success {
		t.Errorf("unsigned manifest must verify without a key: %s", result.Message)
	}
	if result.SignatureVerified {
		t.Error("SignatureVerified must be false for an unsigned manifest")
	}
}

// ── CoreHashFields bootstrap rule ─────────────────────────────────────────────

func TestCoreHashFields_BootstrapRule(t *testing.T) {
	// core_fingerprint must NOT be in CoreHashFields
	for _, field := range aioschema.CoreHashFields {
		if field == "core_fingerprint" || field == "hash_schema_block" {
			t.Errorf("CoreHashFields must not include %q (bootstrap rule violation)", field)
		}
	}
}

func TestCoreHashFields_ContainsRequired(t *testing.T) {
	required := []string{"asset_id", "schema_version", "creation_timestamp", "hash_original", "creator_id"}
	fields := make(map[string]bool)
	for _, f := range aioschema.CoreHashFields {
		fields[f] = true
	}
	for _, r := range required {
		if !fields[r] {
			t.Errorf("CoreHashFields missing required field %q", r)
		}
	}
}
