package aioschema_test

// cross_verify_test.go
//
// Loads cross_verify_vectors.json and asserts all 14 CV vectors pass.
// The vectors file must be present at ../../cross_verify_vectors.json
// (i.e., the project root when tests are run from the package directory),
// OR at the path specified by the AIOSCHEMA_VECTORS env var.

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/aioschemahub/aioschema"
)

// ── Vector file loader ────────────────────────────────────────────────────────

type vectorFile struct {
	SpecVersion string   `json:"spec_version"`
	Vectors     []vector `json:"vectors"`
}

type vector struct {
	ID          string          `json:"id"`
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Inputs      json.RawMessage `json:"inputs"`
	Expected    json.RawMessage `json:"expected"`
}

// hashInputs is used for CV-01..CV-04
type hashInputs struct {
	DataHex   string `json:"data_hex"`
	Algorithm string `json:"algorithm"`
}

// canonicalInputs is used for CV-05
type canonicalInputs struct {
	Object map[string]interface{} `json:"object"`
}

// fingerprintInputs is used for CV-06
type fingerprintInputs struct {
	CoreFields map[string]interface{} `json:"core_fields"`
}

// manifestInputs is used for CV-07..CV-14
type manifestInputs struct {
	AssetHex string                 `json:"asset_hex"`
	Manifest map[string]interface{} `json:"manifest"`
}

// expectedHash is used for CV-01..CV-06
type expectedHash = string

// expectedSuccess is used for CV-07..CV-14
type expectedSuccess struct {
	Success   bool   `json:"success"`
	MatchType string `json:"match_type,omitempty"`
}

func loadVectors(t *testing.T) *vectorFile {
	t.Helper()

	// Allow override via env var
	if p := os.Getenv("AIOSCHEMA_VECTORS"); p != "" {
		return readVectorFile(t, p)
	}

	// Try known relative paths from the test binary location
	_, thisFile, _, _ := runtime.Caller(0)
	candidates := []string{
		// Package sits at aioschema/; vectors.json is in project root
		filepath.Join(filepath.Dir(thisFile), "..", "..", "cross_verify_vectors.json"),
		filepath.Join(filepath.Dir(thisFile), "..", "cross_verify_vectors.json"),
		filepath.Join(filepath.Dir(thisFile), "cross_verify_vectors.json"),
		"cross_verify_vectors.json",
		"../../cross_verify_vectors.json",
		"../cross_verify_vectors.json",
	}
	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			return readVectorFile(t, p)
		}
	}
	t.Fatal("cross_verify_vectors.json not found; set AIOSCHEMA_VECTORS env var to its path")
	return nil
}

func readVectorFile(t *testing.T, path string) *vectorFile {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read vectors file %s: %v", path, err)
	}
	var vf vectorFile
	if err := json.Unmarshal(data, &vf); err != nil {
		t.Fatalf("parse vectors file: %v", err)
	}
	t.Logf("Loaded %d vectors from %s (spec_version=%s)", len(vf.Vectors), path, vf.SpecVersion)
	return &vf
}

// ── Main test ─────────────────────────────────────────────────────────────────

func TestCrossVerify_AllVectors(t *testing.T) {
	vf := loadVectors(t)

	if len(vf.Vectors) != 14 {
		t.Errorf("expected 14 vectors, got %d", len(vf.Vectors))
	}

	for _, v := range vf.Vectors {
		v := v // capture
		t.Run(fmt.Sprintf("%s/%s", v.ID, v.Name), func(t *testing.T) {
			switch v.ID {
			case "CV-01", "CV-02", "CV-03", "CV-04":
				runHashVector(t, v)
			case "CV-05":
				runCanonicalJSONVector(t, v)
			case "CV-06":
				runCoreFingerprintVector(t, v)
			case "CV-07", "CV-08", "CV-09", "CV-10", "CV-11", "CV-12", "CV-13", "CV-14":
				runManifestVerifyVector(t, v)
			default:
				t.Errorf("unknown vector id %q", v.ID)
			}
		})
	}
}

// ── CV-01..CV-04: Hash computation ───────────────────────────────────────────

func runHashVector(t *testing.T, v vector) {
	t.Helper()

	var inp hashInputs
	if err := json.Unmarshal(v.Inputs, &inp); err != nil {
		t.Fatalf("unmarshal inputs: %v", err)
	}

	var expected string
	if err := json.Unmarshal(v.Expected, &expected); err != nil {
		t.Fatalf("unmarshal expected: %v", err)
	}

	var data []byte
	if inp.DataHex != "" {
		var err error
		data, err = hex.DecodeString(inp.DataHex)
		if err != nil {
			t.Fatalf("decode data_hex: %v", err)
		}
	}

	got, err := aioschema.ComputeHash(data, inp.Algorithm)
	if err != nil {
		t.Fatalf("ComputeHash(%q): %v", inp.Algorithm, err)
	}
	if got != expected {
		t.Errorf("\n  got  %s\n  want %s", got, expected)
	}
}

// ── CV-05: Canonical JSON ─────────────────────────────────────────────────────

func runCanonicalJSONVector(t *testing.T, v vector) {
	t.Helper()

	var inp canonicalInputs
	if err := json.Unmarshal(v.Inputs, &inp); err != nil {
		t.Fatalf("unmarshal inputs: %v", err)
	}

	var expected string
	if err := json.Unmarshal(v.Expected, &expected); err != nil {
		t.Fatalf("unmarshal expected: %v", err)
	}

	got, err := aioschema.CanonicalJSON(inp.Object)
	if err != nil {
		t.Fatalf("CanonicalJSON: %v", err)
	}
	if string(got) != expected {
		t.Errorf("\n  got  %s\n  want %s", got, expected)
	}
}

// ── CV-06: core_fingerprint ───────────────────────────────────────────────────

func runCoreFingerprintVector(t *testing.T, v vector) {
	t.Helper()

	var inp fingerprintInputs
	if err := json.Unmarshal(v.Inputs, &inp); err != nil {
		t.Fatalf("unmarshal inputs: %v", err)
	}

	var expected string
	if err := json.Unmarshal(v.Expected, &expected); err != nil {
		t.Fatalf("unmarshal expected: %v", err)
	}

	// core_fingerprint = hash(canonicalJSON(CORE_HASH_FIELDS subset of core_fields))
	// Determine algorithm from expected value
	alg, _, err := aioschema.ParseHashPrefix(expected)
	if err != nil {
		t.Fatalf("parse expected hash prefix: %v", err)
	}

	subset := make(map[string]interface{})
	for _, field := range aioschema.CoreHashFields {
		if val, ok := inp.CoreFields[field]; ok {
			subset[field] = val
		}
	}
	canonical, err := aioschema.CanonicalJSON(subset)
	if err != nil {
		t.Fatalf("CanonicalJSON: %v", err)
	}
	got, err := aioschema.ComputeHash(canonical, alg)
	if err != nil {
		t.Fatalf("ComputeHash: %v", err)
	}
	if got != expected {
		t.Errorf("\n  got  %s\n  want %s", got, expected)
	}
}

// ── CV-07..CV-14: Manifest verification ──────────────────────────────────────

func runManifestVerifyVector(t *testing.T, v vector) {
	t.Helper()

	var inp manifestInputs
	if err := json.Unmarshal(v.Inputs, &inp); err != nil {
		t.Fatalf("unmarshal inputs: %v", err)
	}

	var exp expectedSuccess
	if err := json.Unmarshal(v.Expected, &exp); err != nil {
		t.Fatalf("unmarshal expected: %v", err)
	}

	// Decode asset bytes
	assetData, err := hex.DecodeString(inp.AssetHex)
	if err != nil {
		t.Fatalf("decode asset_hex: %v", err)
	}

	// Round-trip manifest through JSON to get a typed Manifest
	manifestJSON, err := json.Marshal(inp.Manifest)
	if err != nil {
		t.Fatalf("re-marshal manifest: %v", err)
	}
	var m aioschema.Manifest
	if err := json.Unmarshal(manifestJSON, &m); err != nil {
		t.Fatalf("unmarshal manifest: %v", err)
	}

	result, err := aioschema.VerifyManifest(assetData, &m, aioschema.VerifyOptions{})
	if err != nil {
		t.Fatalf("VerifyManifest returned error: %v", err)
	}

	if result.Success != exp.Success {
		t.Errorf("success=%v (want %v): %s", result.Success, exp.Success, result.Message)
	}

	// If expected match_type is specified and result succeeded, check it
	if exp.MatchType != "" && result.Success {
		if result.MatchType != exp.MatchType {
			t.Errorf("match_type=%q (want %q)", result.MatchType, exp.MatchType)
		}
	}
}
