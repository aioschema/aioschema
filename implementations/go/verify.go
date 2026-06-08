// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ovidiu Ancuta
//
// aioschema/go v0.5.6 | AIOSchema spec v0.5.6
// https://aioschema.org

package aioschema

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
)

// uuidPattern accepts UUID v4 or v7 (and any well-formed UUID as anonymous creator_id).
var uuidPattern = regexp.MustCompile(
	`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`,
)

func toBool(v interface{}) bool {
	if b, ok := v.(bool); ok {
		return b
	}
	return false
}

// VerifyManifest executes the AIOSchema §10 verification procedure.
//
// assetData is the raw bytes of the asset being verified.
// m is the parsed Manifest.
// opts configures optional verification parameters.
func VerifyManifest(assetData []byte, m *Manifest, opts VerifyOptions) (*VerificationResult, error) {
	warns := []string{}

	// Resolve soft binding threshold
	threshold := opts.SoftBindingThreshold
	if threshold <= 0 {
		threshold = SoftBindingThresholdDefault
	}
	if threshold > SoftBindingThresholdMax {
		threshold = SoftBindingThresholdMax
	}

	core := &m.Core

	// §6.3 — Extension size limit
	if m.Extensions != nil {
		extJSON, err := json.Marshal(m.Extensions)
		if err == nil && len(extJSON) > MaxExtensionSizeBytes {
			return fail(fmt.Sprintf(
				"extensions size (%d bytes) exceeds limit of %d bytes (§6.3)",
				len(extJSON), MaxExtensionSizeBytes,
			)), nil
		}
	}

	// §11.1 — ai_declaration constraint validation
	if aiDecl, ok := m.Extensions["ai_declaration"]; ok {
		if decl, ok := aiDecl.(map[string]interface{}); ok {
			if toBool(decl["standard_editing"]) && toBool(decl["disclosure_required"]) {
				return fail(
					"ai_declaration constraint violation: standard_editing is true but " +
						"disclosure_required is also true. Per Article 50.2, standard editing " +
						"does not trigger AI disclosure obligations.",
				), nil
			}
			if toBool(decl["human_reviewed"]) {
				if _, hasArt50 := m.Extensions["compliance_eu_art50"]; !hasArt50 {
					warns = append(warns,
						"ai_declaration.human_reviewed is true but compliance_eu_art50 "+
							"extension is absent (SHOULD be present per §11.1)")
				}
			}
		}
	}

	// §11.3 — public_key fingerprint cross-check
	var embeddedPublicKey []byte
	if pkB64, ok := m.Extensions["public_key"].(string); ok && pkB64 != "" {
		pkBytes, err := base64.StdEncoding.DecodeString(pkB64)
		if err != nil {
			return fail("extensions.public_key is not valid Base64"), nil
		}
		if len(pkBytes) != 32 {
			return fail(fmt.Sprintf(
				"extensions.public_key decoded to %d bytes, expected 32 (Ed25519)",
				len(pkBytes),
			)), nil
		}
		// Fingerprint cross-check
		fpHash := sha256.Sum256(pkBytes)
		fpHex := hex.EncodeToString(fpHash[:16])
		expectedCreatorID := "ed25519-fp-" + fpHex
		if subtle.ConstantTimeCompare([]byte(core.CreatorID), []byte(expectedCreatorID)) != 1 {
			return fail(
				"extensions.public_key fingerprint cross-check failed: "+
					"embedded key does not belong to declared creator_id. "+
					fmt.Sprintf("Expected ed25519-fp derived from key: %s, manifest creator_id: %s", expectedCreatorID, core.CreatorID),
			), nil
		}
		embeddedPublicKey = pkBytes
	}

	// §10 Step 1 — Schema version check
	if !SupportedVersions[core.SchemaVersion] {
		return fail(fmt.Sprintf(
			"unsupported schema_version %q; supported: 0.1 0.2 0.3 0.3.1 0.4 0.5 0.5.1 0.5.5 0.5.6",
			core.SchemaVersion,
		)), nil
	}

	// §10 Step 2 — Required fields presence
	if core.AssetID == "" {
		return fail("missing required field: asset_id"), nil
	}
	if core.SchemaVersion == "" {
		return fail("missing required field: schema_version"), nil
	}
	if core.CreationTimestamp == "" {
		return fail("missing required field: creation_timestamp"), nil
	}
	if core.CreatorID == "" {
		return fail("missing required field: creator_id"), nil
	}
	// hash_original must have at least one value
	if len(core.HashOriginal.Strings()) == 0 {
		return fail("missing required field: hash_original"), nil
	}

	// §10 Step 3 — Timestamp format (strict UTC, Z suffix)
	if !TimestampPattern.MatchString(core.CreationTimestamp) {
		return fail(fmt.Sprintf(
			"creation_timestamp %q is not a valid UTC ISO-8601 timestamp (must end with Z)",
			core.CreationTimestamp,
		)), nil
	}

	// §10 Step 4 — creator_id format
	cid := core.CreatorID
	if !CreatorIDAttributedPattern.MatchString(cid) && !uuidPattern.MatchString(cid) {
		return fail(fmt.Sprintf("creator_id %q has invalid format", cid)), nil
	}

	// §10 Step 5 — hash_original format validation
	for _, h := range core.HashOriginal.Strings() {
		if !HashPattern.MatchString(h) {
			return fail(fmt.Sprintf("hash_original value %q has invalid format", h)), nil
		}
	}

	// §10 Step 6 — Build a raw core map for fingerprint computation.
	// We need the raw map so we can pick exactly CORE_HASH_FIELDS.
	rawCore, err := manifestCoreToMap(core)
	if err != nil {
		return nil, fmt.Errorf("marshal core: %w", err)
	}

	// §10 Step 7 — Content hash verification (hard match)
	hardMatch := false
	supportedFound := false
	for _, h := range core.HashOriginal.Strings() {
		alg, _, err := ParseHashPrefix(h)
		if err != nil {
			warns = append(warns, fmt.Sprintf("skipping malformed hash %q: %v", h, err))
			continue
		}
		supportedFound = true
		computed, err := ComputeHash(assetData, alg)
		if err != nil {
			warns = append(warns, fmt.Sprintf("hash algorithm %q not supported, skipping", alg))
			continue
		}
		if safeEqualString(computed, h) {
			hardMatch = true
			break
		}
	}

	if !supportedFound {
		return fail("no supported hash algorithm found in hash_original; cannot verify content"), nil
	}

	// §10 Step 8 — Soft binding fallback (requires image data; skipped if hard match)
	softMatch := false
	if !hardMatch {
		// Soft binding is implemented in the extensions block.
		// A Go implementation without image processing skips soft binding
		// and reports a warning rather than a hard failure, matching spec intent.
		if sb, ok := m.Extensions["soft_binding"]; ok && sb != nil {
			warns = append(warns, fmt.Sprintf(
				"soft_binding present but not evaluated (image processing not available in this implementation; policy threshold=%d)",
				threshold,
			))
		}
	}

	// §10 Step 9 — Fail if neither hard nor soft match
	if !hardMatch && !softMatch {
		return fail("content mismatch: hash did not match asset. Asset may be tampered or replaced."), nil
	}

	matchType := "hard"
	if softMatch {
		matchType = "soft"
	}

	// §10 Step 10 — core_fingerprint integrity
	cfpVal := core.EffectiveCoreFingerprint()
	if cfpVal == nil || *cfpVal == "" {
		return &VerificationResult{
			Success:   false,
			Message:   "missing required field: core_fingerprint",
			MatchType: matchType,
		}, nil
	}
	cfpAlg, _, err := ParseHashPrefix(*cfpVal)
	if err != nil {
		return &VerificationResult{
			Success:   false,
			Message:   fmt.Sprintf("core_fingerprint has invalid format: %v", err),
			MatchType: matchType,
		}, nil
	}
	coreFieldBytes, err := canonicalCoreFields(rawCore)
	if err != nil {
		return nil, fmt.Errorf("canonical core fields: %w", err)
	}
	computedCFP, err := ComputeHash(coreFieldBytes, cfpAlg)
	if err != nil {
		return nil, fmt.Errorf("compute core_fingerprint: %w", err)
	}
	if !safeEqualString(computedCFP, *cfpVal) {
		return &VerificationResult{
			Success:   false,
			Message:   "manifest integrity check failed: core_fingerprint mismatch. Core metadata may have been tampered.",
			MatchType: matchType,
		}, nil
	}

	// §10 Step 11 — Core signature verification (§11.3: prefer embedded key)
	signatureVerified := false
	if core.Signature != nil {
		sigStr := *core.Signature
		if !SignaturePattern.MatchString(sigStr) {
			return &VerificationResult{
				Success:   false,
				Message:   "signature has invalid format; expected ed25519-<128hex>",
				MatchType: matchType,
			}, nil
		}
		// Resolve verification key: external > embedded > error
		var verifyKey []byte
		if opts.PublicKeyHex != "" {
			var err error
			verifyKey, err = hex.DecodeString(opts.PublicKeyHex)
			if err != nil {
				return nil, fmt.Errorf("decode public key hex: %w", err)
			}
		} else if embeddedPublicKey != nil {
			verifyKey = embeddedPublicKey
		} else {
			return &VerificationResult{
				Success:   false,
				Message:   "manifest is signed but no public key was provided (neither externally nor via extensions.public_key)",
				MatchType: matchType,
			}, nil
		}
		sigBytes, err := hex.DecodeString(sigStr[len("ed25519-"):])
		if err != nil {
			return nil, fmt.Errorf("decode signature hex: %w", err)
		}
		pubKey := ed25519.PublicKey(verifyKey)
		if !ed25519.Verify(pubKey, coreFieldBytes, sigBytes) {
			return &VerificationResult{
				Success:   false,
				Message:   "core signature verification failed: invalid signature or wrong key",
				MatchType: matchType,
			}, nil
		}
		signatureVerified = true
	}

	// §10 Step 12 — Manifest signature verification (§11.3: prefer embedded key)
	manifestSigVerified := false
	if core.ManifestSignature != nil {
		msigStr := *core.ManifestSignature
		if !SignaturePattern.MatchString(msigStr) {
			return &VerificationResult{
				Success:   false,
				Message:   "manifest_signature has invalid format; expected ed25519-<128hex>",
				MatchType: matchType,
			}, nil
		}
		// Resolve verification key: external > embedded > error
		var verifyKey []byte
		if opts.PublicKeyHex != "" {
			var err error
			verifyKey, err = hex.DecodeString(opts.PublicKeyHex)
			if err != nil {
				return nil, fmt.Errorf("decode public key hex: %w", err)
			}
		} else if embeddedPublicKey != nil {
			verifyKey = embeddedPublicKey
		} else {
			return &VerificationResult{
				Success:   false,
				Message:   "manifest_signature present but no public key was provided (neither externally nor via extensions.public_key)",
				MatchType: matchType,
			}, nil
		}
		if err != nil {
			return nil, fmt.Errorf("decode public key hex: %w", err)
		}
		msigBytes, err := hex.DecodeString(msigStr[len("ed25519-"):])
		if err != nil {
			return nil, fmt.Errorf("decode manifest_signature hex: %w", err)
		}

		// Serialize full manifest with manifest_signature nulled (§5.8)
		fullMap, err := manifestToMap(m)
		if err != nil {
			return nil, fmt.Errorf("marshal manifest: %w", err)
		}
		mBytes, err := canonicalManifestBytes(fullMap)
		if err != nil {
			return nil, fmt.Errorf("canonical manifest bytes: %w", err)
		}

		pubKey := ed25519.PublicKey(verifyKey)
		if !ed25519.Verify(pubKey, mBytes, msigBytes) {
			return &VerificationResult{
				Success:   false,
				Message:   "manifest signature verification failed: invalid or extensions tampered",
				MatchType: matchType,
			}, nil
		}
		manifestSigVerified = true
	}

	// §10 Step 13 — Anchor verification
	anchorChecked := false
	anchorVerified := false
	anchor := core.AnchorReference
	if anchor != nil && *anchor != "" {
		if opts.VerifyAnchor && opts.Resolver != nil {
			anchorChecked = true
			record, err := opts.Resolver(*anchor)
			if err != nil {
				warns = append(warns, fmt.Sprintf("anchor verification error: %v", err))
			} else if record == nil {
				warns = append(warns, fmt.Sprintf("anchor record not found: %q", *anchor))
			} else {
				idMatch := safeEqualString(record.AssetID, core.AssetID)
				cfpRecordVal := record.CoreFingerprint
				cfpCoreVal := ""
				if cfpVal != nil {
					cfpCoreVal = *cfpVal
				}
				cfpMatch := safeEqualString(cfpRecordVal, cfpCoreVal)
				if idMatch && cfpMatch {
					anchorVerified = true
				} else {
					warns = append(warns, fmt.Sprintf(
						"anchor record mismatch for %q. Asset may have been re-signed.", *anchor,
					))
				}
			}
		} else {
			warns = append(warns, fmt.Sprintf(
				"anchor_reference present (%q) but not verified. Pass VerifyAnchor=true and Resolver= for Level 3 compliance.",
				*anchor,
			))
		}
	}

	// §10 Step 14 — Build success result
	contentDesc := "bit-exact"
	if softMatch {
		contentDesc = "perceptual (soft)"
	}
	sigDesc := "unsigned"
	if signatureVerified && manifestSigVerified {
		sigDesc = "core + manifest signatures verified"
	} else if signatureVerified {
		sigDesc = "core signature verified"
	}

	return &VerificationResult{
		Success:                   true,
		Message:                   fmt.Sprintf("Verified: %s content match, %s. Provenance intact.", contentDesc, sigDesc),
		MatchType:                 matchType,
		SignatureVerified:         signatureVerified,
		ManifestSignatureVerified: manifestSigVerified,
		AnchorChecked:             anchorChecked,
		AnchorVerified:            anchorVerified,
		Warnings:                  warns,
	}, nil
}

// ── Helper: fail shorthand ────────────────────────────────────────────────────

func fail(msg string) *VerificationResult {
	return &VerificationResult{Success: false, Message: msg}
}

// ── Marshal helpers ───────────────────────────────────────────────────────────

// manifestCoreToMap converts a Core struct to map[string]interface{} via JSON
// round-trip, giving us the raw representation that canonicalCoreFields expects.
func manifestCoreToMap(c *Core) (map[string]interface{}, error) {
	data, err := json.Marshal(c)
	if err != nil {
		return nil, err
	}
	var m map[string]interface{}
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	return m, nil
}

// manifestToMap is in manifest.go
// -- end aioschema/go v0.5.6 | AIOSchema spec v0.5.6 --
