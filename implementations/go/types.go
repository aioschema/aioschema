// Package aioschema implements the AIOSchema v0.5.5 content provenance standard.
// Spec: https://aioschema.org
package aioschema

import "encoding/json"

// SpecVersion is the version of the AIOSchema specification this package implements.
const SpecVersion = "0.5.5"

// SupportedVersions lists all schema_version values accepted by this verifier.
var SupportedVersions = map[string]bool{
	"0.1": true, "0.2": true, "0.3": true, "0.3.1": true,
	"0.4": true, "0.5": true, "0.5.1": true, "0.5.5": true,
}

// CoreHashFields are the manifest core fields that constitute the canonical input
// for core_fingerprint (§5.6). MUST NOT include core_fingerprint itself (bootstrap rule).
var CoreHashFields = []string{
	"asset_id",
	"schema_version",
	"creation_timestamp",
	"hash_original",
	"creator_id",
}

// DefaultHashAlgorithm is the default hash algorithm used when none is specified.
const DefaultHashAlgorithm = "sha256"

// SoftBindingThresholdDefault is the default pHash Hamming distance threshold (§8.3).
const SoftBindingThresholdDefault = 5

// SoftBindingThresholdMax is the maximum allowed threshold (§8.3).
const SoftBindingThresholdMax = 10

// SidecarSuffix is appended to asset paths to derive sidecar manifest paths (§8.2).
const SidecarSuffix = ".aios.json"

// HashOriginal is a discriminated union: either a single prefixed hash string,
// or an array of prefixed hash strings (§5.5, multi-hash support in v0.5+).
// It marshals/unmarshals transparently from JSON.
type HashOriginal struct {
	Single string
	Multi  []string
	IsMulti bool
}

func (h HashOriginal) MarshalJSON() ([]byte, error) {
	if h.IsMulti {
		return json.Marshal(h.Multi)
	}
	return json.Marshal(h.Single)
}

func (h *HashOriginal) UnmarshalJSON(data []byte) error {
	// Try array first
	var multi []string
	if err := json.Unmarshal(data, &multi); err == nil {
		h.Multi = multi
		h.IsMulti = true
		return nil
	}
	// Fall back to single string
	var single string
	if err := json.Unmarshal(data, &single); err != nil {
		return err
	}
	h.Single = single
	h.IsMulti = false
	return nil
}

// Strings returns all hash strings regardless of single vs multi form.
func (h HashOriginal) Strings() []string {
	if h.IsMulti {
		return h.Multi
	}
	if h.Single == "" {
		return nil
	}
	return []string{h.Single}
}

// Core holds the mandatory provenance fields of an AIOSchema manifest.
// All optional pointer fields are nil when absent (JSON null).
type Core struct {
	AssetID              string       `json:"asset_id"`
	SchemaVersion        string       `json:"schema_version"`
	CreationTimestamp    string       `json:"creation_timestamp"`
	HashOriginal         HashOriginal `json:"hash_original"`
	CreatorID            string       `json:"creator_id"`

	// core_fingerprint (v0.5.5+; hash_schema_block accepted as deprecated alias)
	CoreFingerprint     *string      `json:"core_fingerprint,omitempty"`
	HashSchemaBlock     *string      `json:"hash_schema_block,omitempty"` // deprecated alias

	Signature           *string      `json:"signature"`
	ManifestSignature   *string      `json:"manifest_signature"`
	AnchorReference     *string      `json:"anchor_reference"`
	PreviousVersionAnchor *string    `json:"previous_version_anchor"`
}

// EffectiveCoreFingerprint returns the core_fingerprint value, falling back to
// the deprecated hash_schema_block alias if core_fingerprint is absent.
func (c *Core) EffectiveCoreFingerprint() *string {
	if c.CoreFingerprint != nil {
		return c.CoreFingerprint
	}
	return c.HashSchemaBlock
}

// Manifest is the top-level AIOSchema manifest structure.
type Manifest struct {
	Core       Core                   `json:"core"`
	Extensions map[string]interface{} `json:"extensions"`
}

// VerificationResult holds the structured result of a manifest verification (§10).
type VerificationResult struct {
	Success                    bool
	Message                    string
	MatchType                  string // "hard", "soft", or ""
	SignatureVerified          bool
	ManifestSignatureVerified  bool
	AnchorChecked              bool
	AnchorVerified             bool
	Warnings                   []string
}

// AnchorRecord is the minimum record an AnchorResolver must return.
type AnchorRecord struct {
	AssetID         string `json:"asset_id"`
	CoreFingerprint string `json:"core_fingerprint"`
	Timestamp       string `json:"timestamp"`
}

// AnchorResolver resolves an anchor reference string to an AnchorRecord.
// Returns (nil, nil) if the record is not found.
// Returns a non-nil error on service errors.
type AnchorResolver func(anchorRef string) (*AnchorRecord, error)

// VerifyOptions configures optional parameters for VerifyManifest.
type VerifyOptions struct {
	// PublicKeyHex is an Ed25519 public key as a hex string (32 bytes = 64 hex chars).
	// Required to verify core signature or manifest_signature.
	PublicKeyHex string

	// SoftBindingThreshold is the maximum allowed pHash Hamming distance for soft binding.
	// Defaults to SoftBindingThresholdDefault (5) if zero.
	SoftBindingThreshold int

	// VerifyAnchor enables Level 3 anchor verification when true and AnchorResolver is set.
	VerifyAnchor bool

	// Resolver is the AnchorResolver callback for Level 3 verification.
	Resolver AnchorResolver
}
