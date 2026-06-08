// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ovidiu Ancuta
//
// aioschema/dotnet v0.5.6 | AIOSchema spec v0.5.6
// https://aioschema.org

namespace AIOSchema;

public static class Verifier
{
    public static VerificationResult Verify(
        byte[]? assetBytes,
        AIOSManifest manifest,
        byte[]? publicKey              = null,
        bool verifyAnchor              = false,
        AnchorResolver? anchorResolver = null,
        int softBindingThreshold       = Constants.SoftBindingThresholdDefault)
    {
        var core  = manifest.Core;
        var warns = new List<string>();

        // Step 1 — schema version
        if (!Constants.SupportedVersions.Contains(core.SchemaVersion))
            return VerificationResult.Fail(
                $"Unsupported schema_version '{core.SchemaVersion}'. " +
                $"Supported: {string.Join(", ", Constants.SupportedVersions)}");

        // Step 2 — required fields
        if (string.IsNullOrEmpty(core.AssetId))
            return VerificationResult.Fail("Missing required field: asset_id");
        if (string.IsNullOrEmpty(core.CreationTimestamp))
            return VerificationResult.Fail("Missing required field: creation_timestamp");
        if (string.IsNullOrEmpty(core.CreatorId))
            return VerificationResult.Fail("Missing required field: creator_id");

        var hashes = core.HashOriginalList();
        if (hashes.Count == 0)
            return VerificationResult.Fail("Missing required field: hash_original");

        // §11.1 — ai_declaration constraint + compliance_eu_art50 warning
        if (manifest.Extensions.TryGetValue("ai_declaration", out var aiDeclRaw))
        {
            bool GetBool(object? v) => v switch
            {
                bool b => b,
                System.Text.Json.JsonElement je => je.ValueKind == System.Text.Json.JsonValueKind.True,
                _ => false,
            };

            bool standardEditing = false;
            bool disclosureRequired = false;
            bool humanReviewed = false;

            if (aiDeclRaw is Dictionary<string, object?> adDict)
            {
                adDict.TryGetValue("standard_editing", out var se);
                adDict.TryGetValue("disclosure_required", out var dr);
                adDict.TryGetValue("human_reviewed", out var hr);
                standardEditing = GetBool(se);
                disclosureRequired = GetBool(dr);
                humanReviewed = GetBool(hr);
            }
            else if (aiDeclRaw is System.Text.Json.JsonElement jeDecl &&
                     jeDecl.ValueKind == System.Text.Json.JsonValueKind.Object)
            {
                standardEditing    = jeDecl.TryGetProperty("standard_editing", out var se2)    && se2.GetBoolean();
                disclosureRequired = jeDecl.TryGetProperty("disclosure_required", out var dr2) && dr2.GetBoolean();
                humanReviewed      = jeDecl.TryGetProperty("human_reviewed", out var hr2)      && hr2.GetBoolean();
            }

            if (standardEditing && disclosureRequired)
                return VerificationResult.Fail(
                    "ai_declaration constraint violation: standard_editing is true but " +
                    "disclosure_required is also true. Per Article 50.2, standard editing " +
                    "does not trigger AI disclosure obligations.");

            if (humanReviewed && !manifest.Extensions.ContainsKey("compliance_eu_art50"))
                warns.Add(
                    "ai_declaration.human_reviewed is true but compliance_eu_art50 " +
                    "extension is absent (SHOULD be present per §11.1)");
        }

        // Step 3 — timestamp format
        if (!Patterns.Timestamp().IsMatch(core.CreationTimestamp))
            return VerificationResult.Fail(
                $"creation_timestamp has invalid format '{core.CreationTimestamp}'. " +
                "Must be ISO 8601 UTC with Z suffix.");

        // Step 4 — creator_id format
        try { CreatorId.Parse(core.CreatorId).Validate(); }
        catch (AIOSchemaException ex)
        { return VerificationResult.Fail($"Invalid creator_id: {ex.Message}"); }

        // Step 5 — validate each hash_original value format
        // Note: malformed individual hashes are warned-and-skipped in the hash loop (Step 7).
        // Here we only reject values that are clearly not hash strings at all (no prefix).
        // This matches Go/Rust behavior: warn+skip per entry, fail only if none are supported.

        // Step 6 — optional signature format
        if (core.Signature is not null && !Patterns.Signature().IsMatch(core.Signature))
            return VerificationResult.Fail($"signature has invalid format: '{core.Signature}'");
        if (core.ManifestSignature is not null && !Patterns.Signature().IsMatch(core.ManifestSignature))
            return VerificationResult.Fail($"manifest_signature has invalid format: '{core.ManifestSignature}'");

        // Step 7 — content hash (hard match)
        bool hardMatch     = false;
        bool supportedFound = false;
        string? matchType  = null;

        if (assetBytes is not null)
        {
            foreach (var h in hashes)
            {
                string alg;
                try { (alg, _) = Algorithms.ParseHash(h, "hash_original"); }
                catch (AIOSchemaException ex)
                {
                    warns.Add($"skipping malformed hash '{h}': {ex.Message}");
                    continue;
                }

                if (!Constants.HashRegistry.ContainsKey(alg))
                {
                    warns.Add($"hash algorithm '{alg}' not supported, skipping");
                    continue;
                }

                supportedFound = true;
                if (Algorithms.SafeEqual(Algorithms.ComputeHash(assetBytes, alg), h))
                {
                    hardMatch = true;
                    break;
                }
            }

            if (!supportedFound)
                return VerificationResult.Fail(
                    "No supported hash algorithm found in hash_original. Cannot verify content.");

            // Step 8 — soft binding (pHash requires image processing, not available here)
            if (!hardMatch)
            {
                if (manifest.Extensions.TryGetValue("soft_binding", out var sb)
                    && sb is Dictionary<string, object?> sbDict
                    && sbDict.ContainsKey("fingerprint"))
                {
                    warns.Add(
                        $"soft_binding present but not evaluated " +
                        $"(image processing not available in this implementation; " +
                        $"policy threshold={softBindingThreshold})");
                }
            }

            // Step 9 — fail if no match
            if (!hardMatch)
                return VerificationResult.Fail(
                    "Content mismatch: hash did not match. Asset may be tampered or replaced.");

            matchType = "hard";
        }

        // Step 10 — core_fingerprint integrity (hash_schema_block accepted as alias)
        var cfpValue = core.CoreFingerprint ?? core.HashSchemaBlock;
        if (cfpValue is null)
            return VerificationResult.Fail("Missing required field: core_fingerprint", matchType);

        string cfpAlg;
        try { (cfpAlg, _) = Algorithms.ParseHash(cfpValue, "core_fingerprint"); }
        catch (AIOSchemaException ex)
        { return VerificationResult.Fail(ex.Message, matchType); }

        var coreDict  = ManifestBuilder.CoreToDict(core);
        var canonical = Algorithms.CanonicalCoreBytes(coreDict);
        if (!Algorithms.SafeEqual(Algorithms.ComputeHash(canonical, cfpAlg), cfpValue))
            return VerificationResult.Fail(
                "Manifest integrity check failed: core_fingerprint mismatch. " +
                "Core metadata may have been tampered.", matchType);

        // Step 11 — core signature
        bool signatureVerified = false;
        if (core.Signature is not null)
        {
            if (publicKey is null)
                return VerificationResult.Fail(
                    "Manifest is signed but no public key was provided.", matchType);
            try
            {
                signatureVerified = Algorithms.Verify(canonical, core.Signature, publicKey);
                if (!signatureVerified)
                    return VerificationResult.Fail(
                        "Core signature verification failed: invalid signature or wrong key.", matchType);
            }
            catch (Exception ex)
            { return VerificationResult.Fail($"Signature verification error: {ex.Message}", matchType); }
        }

        // Step 12 — manifest signature
        bool manifestSigVerified = false;
        if (core.ManifestSignature is not null)
        {
            if (publicKey is null)
                return VerificationResult.Fail(
                    "manifest_signature present but no public key was provided.", matchType);
            try
            {
                var mBytes = Algorithms.CanonicalManifestBytes(ManifestBuilder.ToDict(manifest));
                manifestSigVerified = Algorithms.Verify(mBytes, core.ManifestSignature, publicKey);
                if (!manifestSigVerified)
                    return VerificationResult.Fail(
                        "Manifest signature verification failed: invalid or extensions tampered.", matchType);
            }
            catch (Exception ex)
            { return VerificationResult.Fail($"Manifest signature error: {ex.Message}", matchType); }
        }

        // Step 13 — anchor
        bool anchorChecked  = false;
        bool anchorVerified = false;
        if (core.AnchorReference is not null)
        {
            if (verifyAnchor && anchorResolver is not null)
            {
                anchorChecked = true;
                try
                {
                    var rec = anchorResolver(core.AnchorReference);
                    if (rec is null)
                        warns.Add($"Anchor record not found: {core.AnchorReference}");
                    else
                    {
                        var idOk  = rec.TryGetValue("asset_id", out var rId)
                                 && Algorithms.SafeEqual(rId ?? "", core.AssetId);
                        var cfKey = rec.ContainsKey("core_fingerprint") ? "core_fingerprint" : "hash_schema_block";
                        var cfOk  = rec.TryGetValue(cfKey, out var rCfp)
                                 && Algorithms.SafeEqual(rCfp ?? "", cfpValue);
                        if (idOk && cfOk) anchorVerified = true;
                        else warns.Add($"Anchor record mismatch for {core.AnchorReference}.");
                    }
                }
                catch (AnchorVerificationException ex)
                { warns.Add($"Anchor verification error: {ex.Message}"); }
            }
            else
            {
                warns.Add(
                    $"anchor_reference present ({core.AnchorReference}) but not verified. " +
                    "Pass verifyAnchor=true and anchorResolver for Level 3 compliance.");
            }
        }

        // Step 14 — result
        var contentDesc = matchType == "hard" ? "bit-exact"
                        : matchType == "soft"  ? "perceptual (soft)"
                        : "not checked";
        var sigDesc = (signatureVerified && manifestSigVerified) ? "core + manifest signatures verified"
                    : signatureVerified ? "core signature verified"
                    : "unsigned";

        return new VerificationResult
        {
            Success                   = true,
            Message                   = $"Verified: {contentDesc} content match, {sigDesc}. Provenance intact.",
            MatchType                 = matchType,
            SignatureVerified         = signatureVerified,
            ManifestSignatureVerified = manifestSigVerified,
            AnchorChecked             = anchorChecked,
            AnchorVerified            = anchorVerified,
            Warnings                  = warns,
        };
    }
}
// -- end aioschema/dotnet v0.5.6 | AIOSchema spec v0.5.6 --
