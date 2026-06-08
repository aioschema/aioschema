// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ovidiu Ancuta
//
// aioschema/go v0.5.6 | AIOSchema spec v0.5.6
// https://aioschema.org

package aioschema

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
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

	// PrivateKey is an Ed25519 private key (64 bytes). When set, takes precedence over PrivateKeyHex.
	// Both core signature and manifest_signature are generated.
	PrivateKey ed25519.PrivateKey

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

	// Sign if private key provided
	if len(opts.PrivateKey) > 0 {
		if err := SignManifest(manifest, opts.PrivateKey); err != nil {
			return nil, fmt.Errorf("sign manifest: %w", err)
		}
	}

	return manifest, nil
}

// SignManifest signs both the core fields and the full manifest using Ed25519.
// It sets manifest.Core.Signature and manifest.Core.ManifestSignature.
func SignManifest(m *Manifest, privateKey ed25519.PrivateKey) error {
	// Build core map for signing (without signature fields)
	coreMap := map[string]interface{}{
		"asset_id":           m.Core.AssetID,
		"schema_version":     m.Core.SchemaVersion,
		"creation_timestamp": m.Core.CreationTimestamp,
		"hash_original":      m.Core.HashOriginal,
		"creator_id":         m.Core.CreatorID,
	}
	if m.Core.EffectiveCoreFingerprint() != nil {
		coreMap["core_fingerprint"] = *m.Core.EffectiveCoreFingerprint()
	}

	coreBytes, err := canonicalCoreFields(coreMap)
	if err != nil {
		return fmt.Errorf("canonical core fields: %w", err)
	}

	// Core signature
	coreSig := ed25519.Sign(privateKey, coreBytes)
	sigStr := "ed25519-" + hex.EncodeToString(coreSig)
	m.Core.Signature = &sigStr

	// Manifest signature (over full manifest with core_signature set, manifest_signature null)
	fullMap, err := manifestToMap(m)
	if err != nil {
		return fmt.Errorf("manifest to map: %w", err)
	}

	// Ensure manifest_signature is null in the map for signing
	if core, ok := fullMap["core"].(map[string]interface{}); ok {
		core["manifest_signature"] = nil
	}

	mBytes, err := CanonicalJSON(fullMap)
	if err != nil {
		return fmt.Errorf("canonical manifest: %w", err)
	}

	mSig := ed25519.Sign(privateKey, mBytes)
	mSigStr := "ed25519-" + hex.EncodeToString(mSig)
	m.Core.ManifestSignature = &mSigStr

	return nil
}

// CreatorIDFromPublicKey derives an ed25519-fp- creator_id from an Ed25519 public key.
func CreatorIDFromPublicKey(pub ed25519.PublicKey) string {
	h := sha256.Sum256(pub)
	return "ed25519-fp-" + hex.EncodeToString(h[:16])
}

// manifestToMap converts a Manifest to a map[string]interface{} for canonical JSON.
func manifestToMap(m *Manifest) (map[string]interface{}, error) {
	data, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	var result map[string]interface{}
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, err
	}
	return result, nil
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
// -- end aioschema/go v0.5.6 | AIOSchema spec v0.5.6 --
