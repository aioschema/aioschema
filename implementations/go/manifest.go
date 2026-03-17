package aioschema

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// GenerateOptions configures manifest generation.
type GenerateOptions struct {
	// Algorithm is the primary hash algorithm (default: "sha256").
	Algorithm string

	// ExtraAlgorithms adds additional hash algorithms to produce a multi-hash manifest.
	ExtraAlgorithms []string

	// CreatorID sets the creator_id field. If empty, a UUID v7 is generated.
	CreatorID string

	// PrivateKeyHex is the Ed25519 private key as hex (64 bytes = 128 hex chars).
	// When set, the manifest core is signed and creator_id is derived from the public key.
	PrivateKeyHex string

	// Extensions is merged into the manifest extensions block.
	Extensions map[string]interface{}
}

// GenerateManifest creates a new AIOSchema manifest for the given asset bytes.
func GenerateManifest(assetData []byte, opts GenerateOptions) (*Manifest, error) {
	if opts.Algorithm == "" {
		opts.Algorithm = DefaultHashAlgorithm
	}

	// Compute hash_original
	h, err := ComputeHash(assetData, opts.Algorithm)
	if err != nil {
		return nil, fmt.Errorf("compute hash: %w", err)
	}

	var hashOriginal HashOriginal
	if len(opts.ExtraAlgorithms) > 0 {
		hashes := []string{h}
		for _, alg := range opts.ExtraAlgorithms {
			extra, err := ComputeHash(assetData, alg)
			if err != nil {
				return nil, fmt.Errorf("compute extra hash (%s): %w", alg, err)
			}
			hashes = append(hashes, extra)
		}
		hashOriginal = HashOriginal{Multi: hashes, IsMulti: true}
	} else {
		hashOriginal = HashOriginal{Single: h}
	}

	// creator_id
	creatorID := opts.CreatorID
	if creatorID == "" {
		creatorID = newUUIDv7()
	}

	// asset_id (UUID v7)
	assetID := newUUIDv7()

	// creation_timestamp (UTC, Z suffix)
	ts := time.Now().UTC().Format("2006-01-02T15:04:05Z")

	// Build core map for fingerprint calculation
	var hashOriginalRaw interface{}
	if hashOriginal.IsMulti {
		hashOriginalRaw = hashOriginal.Multi
	} else {
		hashOriginalRaw = hashOriginal.Single
	}

	coreMap := map[string]interface{}{
		"asset_id":           assetID,
		"schema_version":     SpecVersion,
		"creation_timestamp": ts,
		"hash_original":      hashOriginalRaw,
		"creator_id":         creatorID,
	}

	// Compute core_fingerprint
	coreBytes, err := canonicalCoreFields(coreMap)
	if err != nil {
		return nil, fmt.Errorf("canonical core fields: %w", err)
	}
	cfp, err := ComputeHash(coreBytes, DefaultHashAlgorithm)
	if err != nil {
		return nil, fmt.Errorf("core fingerprint: %w", err)
	}

	extensions := opts.Extensions
	if extensions == nil {
		extensions = map[string]interface{}{}
	}

	manifest := &Manifest{
		Core: Core{
			AssetID:           assetID,
			SchemaVersion:     SpecVersion,
			CreationTimestamp: ts,
			HashOriginal:      hashOriginal,
			CreatorID:         creatorID,
			CoreFingerprint:   &cfp,
		},
		Extensions: extensions,
	}

	return manifest, nil
}

// LoadManifest reads a sidecar .aios.json file from disk.
func LoadManifest(path string) (*Manifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("parse manifest %s: %w", path, err)
	}
	return &m, nil
}

// SidecarPath returns the sidecar path for an asset path.
func SidecarPath(assetPath string) string {
	return assetPath + SidecarSuffix
}

// ── UUID v7 ───────────────────────────────────────────────────────────────────

var (
	uuidLastMS uint64
	uuidSeq    uint16
)

// newUUIDv7 generates a time-ordered UUID v7 string.
func newUUIDv7() string {
	tsMS := uint64(time.Now().UnixMilli())

	if tsMS == uuidLastMS {
		uuidSeq = (uuidSeq + 1) & 0x0FFF
	} else {
		var b [2]byte
		rand.Read(b[:])
		uuidSeq = binary.BigEndian.Uint16(b[:]) & 0x0FFF
		uuidLastMS = tsMS
	}

	var randB [8]byte
	rand.Read(randB[:])
	randLo := binary.BigEndian.Uint64(randB[:]) & 0x3FFFFFFFFFFFFFFF

	hi := (tsMS << 16) | (0x7 << 12) | uint64(uuidSeq)
	lo := (0b10 << 62) | randLo

	var b [16]byte
	binary.BigEndian.PutUint64(b[0:], hi)
	binary.BigEndian.PutUint64(b[8:], lo)

	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
