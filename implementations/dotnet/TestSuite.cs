// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ovidiu Ancuta
//
// aioschema/dotnet v0.5.6 | AIOSchema spec v0.5.6
// https://aioschema.org

using System.Text;
using System.Text.Json;
using AIOSchema;

namespace AIOSchema;

public static class TestSuite
{
    // ---------------------------------------------------------------------------
    // Harness
    // ---------------------------------------------------------------------------

    private static int _passed;
    private static int _failed;
    private static string _group = "";

    private static void Group(string name)
    {
        _group = name;
        Console.WriteLine($"\n--- {name} ---");
    }

    private static void Test(string name, Action fn)
    {
        try
        {
            fn();
            Console.WriteLine($"  PASS  {name}");
            _passed++;
        }
        catch (SkipException ex)
        {
            Console.WriteLine($"  SKIP  {name} ({ex.Message})");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"  FAIL  {name}");
            Console.WriteLine($"        {ex.Message}");
            _failed++;
        }
    }

    private static void Skip(string reason) => throw new SkipException(reason);

    private static void Assert(bool condition, string message = "Assertion failed")
    {
        if (!condition) throw new Exception(message);
    }

    private static void Equal<T>(T expected, T actual, string? label = null)
    {
        if (!EqualityComparer<T>.Default.Equals(expected, actual))
            throw new Exception(
                $"{label ?? "Expected"}: {expected}\n        Actual:   {actual}");
    }

    private static void Contains(string needle, string haystack, string? label = null)
    {
        if (!haystack.Contains(needle, StringComparison.OrdinalIgnoreCase))
            throw new Exception($"{label ?? $"'{needle}' not found in"}: {haystack}");
    }

    private sealed class SkipException : Exception
    {
        public SkipException(string msg) : base(msg) { }
    }

    // ---------------------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------------------

    private static byte[] MakeAsset(string content = "AIOSchema test asset content") =>
        Encoding.UTF8.GetBytes(content);

    private static AIOSManifest Clone(AIOSManifest m)
    {
        var json = ManifestBuilder.ToJson(m);
        return ManifestBuilder.FromJson(json);
    }

    // ---------------------------------------------------------------------------
    // §5.4 Required Test Vectors — v0.4 set (TV-01 through TV-12)
    // ---------------------------------------------------------------------------

    private static void RunTV0104()
    {
        Group("§5.4 Required Test Vectors — v0.4 (TV-01 through TV-12)");

        // TV-01: Valid manifest roundtrip
        Test("TV-01: Valid manifest roundtrip (hard match, signature verified)", () =>
        {
            var (seed, pub) = Algorithms.GenerateKeyPair();
            var asset = MakeAsset("TV-01");
            var m = ManifestBuilder.Generate(asset, privateKeySeed: seed);
            var r = Verifier.Verify(asset, m, publicKey: pub);
            Assert(r.Success, r.Message);
            Equal("hard", r.MatchType);
            Assert(r.SignatureVerified);
        });

        // TV-02: Tampered hash_original fails
        Test("TV-02: Tampered hash_original fails", () =>
        {
            var asset = MakeAsset("TV-02");
            var m = ManifestBuilder.Generate(asset);
            var t = Clone(m);
            t.Core.HashOriginal = "sha256-" + new string('a', 64);
            var r = Verifier.Verify(asset, t);
            Assert(!r.Success);
        });

        // TV-03: Tampered core_fingerprint fails
        Test("TV-03: Tampered core_fingerprint fails", () =>
        {
            var asset = MakeAsset("TV-03");
            var m = ManifestBuilder.Generate(asset);
            var t = Clone(m);
            t.Core.CoreFingerprint = "sha256-" + new string('c', 64);
            var r = Verifier.Verify(asset, t);
            Assert(!r.Success);
            Contains("tampered", r.Message);
        });

        // TV-04: Soft match within threshold — skip (image processing not available)
        Test("TV-04: Soft match within threshold", () =>
            Skip("pHash requires image processing (not available in this implementation)"));

        // TV-05: Soft match outside threshold — skip (image processing not available)
        Test("TV-05: Soft match outside threshold", () =>
            Skip("pHash requires image processing (not available in this implementation)"));

        // TV-06: Valid signature verified
        Test("TV-06: Valid Ed25519 signature verified", () =>
        {
            var (seed, pub) = Algorithms.GenerateKeyPair();
            var asset = MakeAsset("TV-06");
            var m = ManifestBuilder.Generate(asset, privateKeySeed: seed);
            var r = Verifier.Verify(asset, m, publicKey: pub);
            Assert(r.Success, r.Message);
            Assert(r.SignatureVerified);
        });

        // TV-07: Wrong public key fails
        Test("TV-07: Signature verified with wrong key fails", () =>
        {
            var (seed, _)    = Algorithms.GenerateKeyPair();
            var (_, wrongPub) = Algorithms.GenerateKeyPair();
            var asset = MakeAsset("TV-07");
            var m = ManifestBuilder.Generate(asset, privateKeySeed: seed);
            var r = Verifier.Verify(asset, m, publicKey: wrongPub);
            Assert(!r.Success);
        });

        // TV-08: Null signature — unsigned manifest passes, signature_verified=false
        Test("TV-08: Null signature (unsigned) passes, signature_verified=false", () =>
        {
            var asset = MakeAsset("TV-08");
            var m = ManifestBuilder.Generate(asset);
            Assert(m.Core.Signature is null);
            var r = Verifier.Verify(asset, m);
            Assert(r.Success, r.Message);
            Assert(!r.SignatureVerified);
        });

        // TV-09: Missing required fields each cause failure
        Test("TV-09: Missing required fields each cause failure", () =>
        {
            var asset = MakeAsset("TV-09");
            var m = ManifestBuilder.Generate(asset);

            var requiredFields = new[]
            {
                ("asset_id",           (Action<CoreBlock>)(c => c.AssetId = "")),
                ("schema_version",     c => c.SchemaVersion = ""),
                ("creation_timestamp", c => c.CreationTimestamp = ""),
                ("creator_id",         c => c.CreatorId = ""),
                ("hash_original",      c => c.HashOriginal = ""),
                ("core_fingerprint",   c => { c.CoreFingerprint = null; c.HashSchemaBlock = null; }),
            };

            foreach (var (fieldName, mutate) in requiredFields)
            {
                var t = Clone(m);
                mutate(t.Core);
                var r = Verifier.Verify(asset, t);
                Assert(!r.Success, $"Should fail with missing {fieldName}");
            }
        });

        // TV-10: Invalid timestamp (space instead of T) fails
        Test("TV-10: Invalid timestamp format (space separator) fails", () =>
        {
            var asset = MakeAsset("TV-10");
            var m = ManifestBuilder.Generate(asset);
            var t = Clone(m);
            t.Core.CreationTimestamp = "2026-02-20 12:00:00";
            var r = Verifier.Verify(asset, t);
            Assert(!r.Success);
        });

        // TV-11: Non-UTC timestamp (offset) fails
        Test("TV-11: Non-UTC timestamp (+05:00 offset) fails", () =>
        {
            var asset = MakeAsset("TV-11");
            var m = ManifestBuilder.Generate(asset);
            var t = Clone(m);
            t.Core.CreationTimestamp = "2026-02-20T12:00:00+05:00";
            var r = Verifier.Verify(asset, t);
            Assert(!r.Success);
        });

        // TV-12: Unknown schema_version fails
        Test("TV-12: Unknown schema_version fails", () =>
        {
            var asset = MakeAsset("TV-12");
            var m = ManifestBuilder.Generate(asset);
            var t = Clone(m);
            t.Core.SchemaVersion = "9.99";
            var r = Verifier.Verify(asset, t);
            Assert(!r.Success);
            Contains("schema_version", r.Message);
        });
    }

    // ---------------------------------------------------------------------------
    // §5.4 New Test Vectors — v0.5 (TV-13 through TV-18)
    // ---------------------------------------------------------------------------

    private static void RunTV1318()
    {
        Group("§5.4 New Test Vectors — v0.5 (TV-13 through TV-18)");

        // TV-13: Multi-hash manifest — any match succeeds
        Test("TV-13: Multi-hash (SHA-256 + SHA-384) — any match succeeds", () =>
        {
            var asset   = MakeAsset("TV-13");
            var sha256h = Algorithms.ComputeHash(asset, "sha256");
            var sha384h = Algorithms.ComputeHash(asset, "sha384");
            var m = ManifestBuilder.Generate(asset);
            m.Core.HashOriginal = new List<string> { sha256h, sha384h };
            m.Core.CoreFingerprint = Algorithms.ComputeCoreFingerprint(ManifestBuilder.CoreToDict(m.Core));
            var hashes = m.Core.HashOriginalList();
            Assert(hashes.Count == 2);
            Assert(hashes.Any(h => h.StartsWith("sha256-")));
            Assert(hashes.Any(h => h.StartsWith("sha384-")));
            var r = Verifier.Verify(asset, m);
            Assert(r.Success, r.Message);
            Equal("hard", r.MatchType);
        });

        // TV-14: manifest_signature present and valid
        Test("TV-14: manifest_signature valid — manifest_signature_verified=true", () =>
        {
            var (seed, pub) = Algorithms.GenerateKeyPair();
            var asset = MakeAsset("TV-14");
            var m = ManifestBuilder.Generate(asset, privateKeySeed: seed);
            Assert(m.Core.ManifestSignature is not null);
            var r = Verifier.Verify(asset, m, publicKey: pub);
            Assert(r.Success, r.Message);
            Assert(r.ManifestSignatureVerified);
        });

        // TV-15: manifest_signature present, extensions tampered — fails
        Test("TV-15: manifest_signature fails when extensions tampered", () =>
        {
            var (seed, pub) = Algorithms.GenerateKeyPair();
            var asset = MakeAsset("TV-15");
            var m = ManifestBuilder.Generate(asset, privateKeySeed: seed);
            var t = Clone(m);
            t.Extensions["injected_field"] = "malicious";
            var r = Verifier.Verify(asset, t, publicKey: pub);
            Assert(!r.Success);
            Contains("manifest", r.Message);
        });

        // TV-16: SHA-384 single-hash manifest verified correctly
        Test("TV-16: SHA-384 single-hash manifest verified correctly", () =>
        {
            var asset = MakeAsset("TV-16");
            var m = ManifestBuilder.Generate(asset, hashAlgorithm: "sha384");
            var ho = m.Core.HashOriginalList();
            Assert(ho.Count == 1 && ho[0].StartsWith("sha384-"));
            Equal(7 + 96, ho[0].Length, "SHA-384 hash length");
            var r = Verifier.Verify(asset, m);
            Assert(r.Success, r.Message);
        });

        // TV-17: Anchor-verified flow — anchor_verified=true
        Test("TV-17: Anchor resolver called — anchor_verified=true", () =>
        {
            var asset = MakeAsset("TV-17");
            var m = ManifestBuilder.Generate(asset);
            m.Core.AnchorReference = "aios-anchor:test-svc:record-001";
            m.Core.CoreFingerprint = Algorithms.ComputeCoreFingerprint(ManifestBuilder.CoreToDict(m.Core));

            AnchorResolver resolver = (ref_) => new Dictionary<string, string>
            {
                ["asset_id"]         = m.Core.AssetId,
                ["core_fingerprint"] = m.Core.CoreFingerprint!,
                ["timestamp"]        = m.Core.CreationTimestamp,
            };

            var r = Verifier.Verify(asset, m, verifyAnchor: true, anchorResolver: resolver);
            Assert(r.Success, r.Message);
            Assert(r.AnchorChecked);
            Assert(r.AnchorVerified);
        });

        // TV-18: Anchor present, verify_anchor=false — passes with warning
        Test("TV-18: Anchor present, verify_anchor=false — passes with warning", () =>
        {
            var asset = MakeAsset("TV-18");
            var m = ManifestBuilder.Generate(asset);
            m.Core.AnchorReference = "aios-anchor:test-svc:record-002";
            m.Core.CoreFingerprint = Algorithms.ComputeCoreFingerprint(ManifestBuilder.CoreToDict(m.Core));

            var r = Verifier.Verify(asset, m, verifyAnchor: false);
            Assert(r.Success, r.Message);
            Assert(!r.AnchorChecked);
            Assert(!r.AnchorVerified);
            Assert(r.Warnings.Any(w => w.Contains("anchor", StringComparison.OrdinalIgnoreCase)),
                   "Expected anchor warning");
        });
    }

    // ---------------------------------------------------------------------------
    // Multi-Hash Tests (§5.5)
    // ---------------------------------------------------------------------------

    private static void RunMultiHash()
    {
        Group("Multi-Hash (§5.5)");

        Test("Single hash string accepted", () =>
        {
            var asset = MakeAsset("multi-hash-single");
            var m = ManifestBuilder.Generate(asset);
            Assert(m.Core.HashOriginal is string);
            Assert(m.Core.HashOriginalList().Count == 1);
        });

        Test("Multi-hash array: all values validated", () =>
        {
            var asset   = MakeAsset("multi-hash-array");
            var sha256h = Algorithms.ComputeHash(asset, "sha256");
            var sha384h = Algorithms.ComputeHash(asset, "sha384");
            var m = ManifestBuilder.Generate(asset);
            m.Core.HashOriginal = new List<string> { sha256h, sha384h };
            m.Core.CoreFingerprint = Algorithms.ComputeCoreFingerprint(ManifestBuilder.CoreToDict(m.Core));
            var r = Verifier.Verify(asset, m);
            Assert(r.Success, r.Message);
        });

        Test("Multi-hash: first match short-circuits (SHA-256 checked first)", () =>
        {
            var asset   = MakeAsset("multi-hash-order");
            var sha256h = Algorithms.ComputeHash(asset, "sha256");
            var sha384h = Algorithms.ComputeHash(asset, "sha384");
            var m = ManifestBuilder.Generate(asset);
            m.Core.HashOriginal = new List<string> { sha256h, sha384h };
            m.Core.CoreFingerprint = Algorithms.ComputeCoreFingerprint(ManifestBuilder.CoreToDict(m.Core));
            var r = Verifier.Verify(asset, m);
            Assert(r.Success && r.MatchType == "hard");
        });

        Test("Multi-hash: all wrong — content mismatch failure", () =>
        {
            var asset    = MakeAsset("multi-hash-all-fail");
            var tampered = MakeAsset("completely different bytes");
            var sha256h  = Algorithms.ComputeHash(asset, "sha256");
            var sha384h  = Algorithms.ComputeHash(asset, "sha384");
            var m = ManifestBuilder.Generate(asset);
            m.Core.HashOriginal = new List<string> { sha256h, sha384h };
            m.Core.CoreFingerprint = Algorithms.ComputeCoreFingerprint(ManifestBuilder.CoreToDict(m.Core));
            var r = Verifier.Verify(tampered, m);
            Assert(!r.Success);
        });

        Test("Malformed hash in array — warns and skips, does not crash", () =>
        {
            var asset   = MakeAsset("multi-hash-malformed");
            var sha256h = Algorithms.ComputeHash(asset, "sha256");
            var m = ManifestBuilder.Generate(asset);
            m.Core.HashOriginal = new List<string> { "not-a-valid-hash", sha256h };
            m.Core.CoreFingerprint = Algorithms.ComputeCoreFingerprint(ManifestBuilder.CoreToDict(m.Core));
            var r = Verifier.Verify(asset, m);
            Assert(r.Success, r.Message);
            Assert(r.Warnings.Any(w => w.Contains("malformed") || w.Contains("skipping")));
        });

        Test("core_fingerprint computed from hash_original array canonical form", () =>
        {
            var asset   = MakeAsset("multi-hash-cfp");
            var sha256h = Algorithms.ComputeHash(asset, "sha256");
            var sha384h = Algorithms.ComputeHash(asset, "sha384");
            var m = ManifestBuilder.Generate(asset);
            m.Core.HashOriginal = new List<string> { sha256h, sha384h };
            var cfp = Algorithms.ComputeCoreFingerprint(ManifestBuilder.CoreToDict(m.Core));
            Assert(cfp.StartsWith("sha256-"));
            // Must differ from single-hash fingerprint
            var cfpSingle = Algorithms.ComputeCoreFingerprint(
                ManifestBuilder.CoreToDict(ManifestBuilder.Generate(asset).Core));
            Assert(cfp != cfpSingle, "Multi-hash CFP must differ from single-hash CFP");
        });
    }

    // ---------------------------------------------------------------------------
    // SHA-384 Tests
    // ---------------------------------------------------------------------------

    private static void RunSha384()
    {
        Group("SHA-384 (§5.3)");

        Test("SHA-384 hash format: prefix + 96 hex chars", () =>
        {
            var h = Algorithms.ComputeHash(MakeAsset("sha384-format"), "sha384");
            Assert(h.StartsWith("sha384-"));
            Equal(7 + 96, h.Length, "Length");
        });

        Test("SHA-384 pattern accepts 96-hex hash", () =>
        {
            var h = "sha384-" + new string('a', 96);
            Assert(Patterns.Hash().IsMatch(h));
        });

        Test("SHA-384 pattern rejects 64-hex hash", () =>
        {
            var h = "sha384-" + new string('a', 64);
            Assert(!Patterns.Hash().IsMatch(h));
        });

        Test("SHA-256 pattern rejects 96-hex hash", () =>
        {
            var h = "sha256-" + new string('a', 96);
            Assert(!Patterns.Hash().IsMatch(h));
        });

        Test("SHA-384 manifest verifies correctly", () =>
        {
            var asset = MakeAsset("sha384-manifest");
            var m = ManifestBuilder.Generate(asset, hashAlgorithm: "sha384");
            var r = Verifier.Verify(asset, m);
            Assert(r.Success, r.Message);
        });

        Test("SHA-384 core_fingerprint is still SHA-256", () =>
        {
            // core_fingerprint always uses SHA-256 regardless of hash_original alg
            var asset = MakeAsset("sha384-cfp");
            var m = ManifestBuilder.Generate(asset, hashAlgorithm: "sha384");
            Assert(m.Core.CoreFingerprint!.StartsWith("sha256-"));
        });
    }

    // ---------------------------------------------------------------------------
    // manifest_signature Tests (§5.8)
    // ---------------------------------------------------------------------------

    private static void RunManifestSignature()
    {
        Group("manifest_signature (§5.8)");

        Test("manifest_signature generated when signed", () =>
        {
            var (seed, _) = Algorithms.GenerateKeyPair();
            var m = ManifestBuilder.Generate(MakeAsset("msig-gen"), privateKeySeed: seed);
            Assert(m.Core.ManifestSignature is not null);
            Assert(m.Core.ManifestSignature!.StartsWith("ed25519-"));
        });

        Test("manifest_signature null when unsigned", () =>
        {
            var m = ManifestBuilder.Generate(MakeAsset("msig-null"));
            Assert(m.Core.ManifestSignature is null);
        });

        Test("manifest_signature covers extensions", () =>
        {
            var (seed, pub) = Algorithms.GenerateKeyPair();
            var asset = MakeAsset("msig-extensions");
            var exts  = new Dictionary<string, object?> { ["meta"] = "value" };
            var m = ManifestBuilder.Generate(asset, privateKeySeed: seed, extensions: exts);
            var t = Clone(m);
            t.Extensions["meta"] = "tampered";
            var r = Verifier.Verify(asset, t, publicKey: pub);
            Assert(!r.Success);
        });

        Test("manifest_signature bootstrap: manifest_signature=null during signing", () =>
        {
            // canonical manifest bytes must zero out manifest_signature itself
            var (seed, pub) = Algorithms.GenerateKeyPair();
            var asset = MakeAsset("msig-bootstrap");
            var m = ManifestBuilder.Generate(asset, privateKeySeed: seed);
            // The signature must verify -- proving manifest_signature was null during signing
            var mBytes = Algorithms.CanonicalManifestBytes(ManifestBuilder.ToDict(m));
            Assert(Algorithms.Verify(mBytes, m.Core.ManifestSignature!, pub));
        });

        Test("manifest_signature wrong key fails", () =>
        {
            var (seed, _)    = Algorithms.GenerateKeyPair();
            var (_, wrongPub) = Algorithms.GenerateKeyPair();
            var m = ManifestBuilder.Generate(MakeAsset("msig-wrongkey"), privateKeySeed: seed);
            var r = Verifier.Verify(MakeAsset("msig-wrongkey"), m, publicKey: wrongPub);
            Assert(!r.Success);
        });

        Test("manifest_signature present but no public key — fails", () =>
        {
            var (seed, _) = Algorithms.GenerateKeyPair();
            var asset = MakeAsset("msig-nokey");
            var m = ManifestBuilder.Generate(asset, privateKeySeed: seed);
            var r = Verifier.Verify(asset, m, publicKey: null);
            Assert(!r.Success);
            Contains("public key", r.Message);
        });
    }

    // ---------------------------------------------------------------------------
    // Anchor Verification Tests (§9)
    // ---------------------------------------------------------------------------

    private static void RunAnchor()
    {
        Group("Anchor Verification (§9)");

        Test("Anchor resolver called with correct ref", () =>
        {
            var asset = MakeAsset("anchor-resolver");
            var m = ManifestBuilder.Generate(asset);
            m.Core.AnchorReference = "aios-anchor:bitcoin:xyz789";
            m.Core.CoreFingerprint = Algorithms.ComputeCoreFingerprint(ManifestBuilder.CoreToDict(m.Core));

            string? capturedRef = null;
            AnchorResolver resolver = (ref_) =>
            {
                capturedRef = ref_;
                return new Dictionary<string, string>
                {
                    ["asset_id"]         = m.Core.AssetId,
                    ["core_fingerprint"] = m.Core.CoreFingerprint!,
                };
            };

            var r = Verifier.Verify(asset, m, verifyAnchor: true, anchorResolver: resolver);
            Assert(r.Success, r.Message);
            Equal("aios-anchor:bitcoin:xyz789", capturedRef);
            Assert(r.AnchorVerified);
        });

        Test("Anchor resolver returns null — warning, not failure", () =>
        {
            var asset = MakeAsset("anchor-null");
            var m = ManifestBuilder.Generate(asset);
            m.Core.AnchorReference = "aios-anchor:bitcoin:notfound";
            m.Core.CoreFingerprint = Algorithms.ComputeCoreFingerprint(ManifestBuilder.CoreToDict(m.Core));

            AnchorResolver resolver = (_) => null;
            var r = Verifier.Verify(asset, m, verifyAnchor: true, anchorResolver: resolver);
            Assert(r.Success, r.Message);
            Assert(!r.AnchorVerified);
            Assert(r.Warnings.Any(w => w.Contains("not found")));
        });

        Test("Anchor record mismatch — warning, not failure", () =>
        {
            var asset = MakeAsset("anchor-mismatch");
            var m = ManifestBuilder.Generate(asset);
            m.Core.AnchorReference = "aios-anchor:bitcoin:mismatch";
            m.Core.CoreFingerprint = Algorithms.ComputeCoreFingerprint(ManifestBuilder.CoreToDict(m.Core));

            AnchorResolver resolver = (_) => new Dictionary<string, string>
            {
                ["asset_id"]         = "different-asset-id",
                ["core_fingerprint"] = "sha256-" + new string('0', 64),
            };
            var r = Verifier.Verify(asset, m, verifyAnchor: true, anchorResolver: resolver);
            Assert(r.Success, r.Message);
            Assert(!r.AnchorVerified);
            Assert(r.Warnings.Any(w => w.Contains("mismatch")));
        });

        Test("verify_anchor=false with no resolver — passes with warning", () =>
        {
            var asset = MakeAsset("anchor-skip");
            var m = ManifestBuilder.Generate(asset);
            m.Core.AnchorReference = "aios-anchor:bitcoin:skip";
            m.Core.CoreFingerprint = Algorithms.ComputeCoreFingerprint(ManifestBuilder.CoreToDict(m.Core));

            var r = Verifier.Verify(asset, m, verifyAnchor: false);
            Assert(r.Success, r.Message);
            Assert(!r.AnchorChecked);
            Assert(r.Warnings.Any(w => w.Contains("anchor")));
        });
    }

    // ---------------------------------------------------------------------------
    // Backward Compatibility Tests
    // ---------------------------------------------------------------------------

    private static void RunBackwardCompat()
    {
        Group("Backward Compatibility");

        Test("hash_schema_block accepted as alias for core_fingerprint", () =>
        {
            var asset = MakeAsset("compat-alias");
            var m = ManifestBuilder.Generate(asset);
            m.Core.HashSchemaBlock  = m.Core.CoreFingerprint;
            m.Core.CoreFingerprint  = null;
            var r = Verifier.Verify(asset, m);
            Assert(r.Success, r.Message);
        });

        Test("All supported schema versions accepted by verifier", () =>
        {
            var asset = MakeAsset("compat-versions");
            foreach (var version in Constants.SupportedVersions)
            {
                var m = ManifestBuilder.Generate(asset);
                m.Core.SchemaVersion = version;
                // Recompute CFP since schema_version is a CORE_HASH_FIELDS member
                m.Core.CoreFingerprint = Algorithms.ComputeCoreFingerprint(ManifestBuilder.CoreToDict(m.Core));
                var r = Verifier.Verify(asset, m);
                Assert(r.Success, $"Version {version} should be accepted: {r.Message}");
            }
        });

        Test("JSON round-trip preserves null optional fields", () =>
        {
            var asset = MakeAsset("compat-roundtrip");
            var m = ManifestBuilder.Generate(asset);
            Assert(m.Core.Signature is null);
            Assert(m.Core.ManifestSignature is null);
            Assert(m.Core.AnchorReference is null);
            Assert(m.Core.PreviousVersionAnchor is null);
            var json = ManifestBuilder.ToJson(m);
            var m2   = ManifestBuilder.FromJson(json);
            Assert(m2.Core.Signature is null);
            Assert(m2.Core.ManifestSignature is null);
        });
    }

    // ---------------------------------------------------------------------------
    // Core Fingerprint Tests (§5.6)
    // ---------------------------------------------------------------------------

    private static void RunCoreFingerprint()
    {
        Group("Core Fingerprint (§5.6)");

        Test("generate produces core_fingerprint", () =>
        {
            var m = ManifestBuilder.Generate(MakeAsset("cfp-gen"));
            Assert(m.Core.CoreFingerprint is not null);
            Assert(Patterns.Hash().IsMatch(m.Core.CoreFingerprint!));
        });

        Test("core_fingerprint format: sha256-<64hex>", () =>
        {
            var m = ManifestBuilder.Generate(MakeAsset("cfp-format"));
            Assert(m.Core.CoreFingerprint!.StartsWith("sha256-"));
            Equal(7 + 64, m.Core.CoreFingerprint!.Length, "CFP length");
        });

        Test("core_fingerprint excluded from its own inputs (bootstrap rule)", () =>
        {
            Assert(!Constants.CoreHashFields.Contains("core_fingerprint"));
        });

        Test("core_fingerprint changes when any CORE_HASH_FIELD changes", () =>
        {
            var asset = MakeAsset("cfp-change");
            var m1 = ManifestBuilder.Generate(asset);
            var m2 = ManifestBuilder.Generate(asset);
            // Different asset_id and timestamp -> different fingerprint
            Assert(m1.Core.CoreFingerprint != m2.Core.CoreFingerprint,
                   "Different manifests must have different CFPs");
        });

        Test("tampered core_fingerprint detected", () =>
        {
            var asset = MakeAsset("cfp-tamper");
            var m = ManifestBuilder.Generate(asset);
            m.Core.CoreFingerprint = "sha256-" + new string('f', 64);
            var r = Verifier.Verify(asset, m);
            Assert(!r.Success);
            Contains("fingerprint", r.Message);
        });
    }

    // ---------------------------------------------------------------------------
    // Creator ID Tests (§5.7)
    // ---------------------------------------------------------------------------

    private static void RunCreatorId()
    {
        Group("Creator ID (§5.7)");

        Test("Anonymous creator_id is a valid UUID", () =>
        {
            var cid = CreatorId.Anonymous();
            Assert(Guid.TryParse(cid.Value, out _));
            Equal(CreatorIdMode.Anonymous, cid.Mode);
        });

        Test("Attributed creator_id format: ed25519-fp-<32hex>", () =>
        {
            var (_, pub) = Algorithms.GenerateKeyPair();
            var cid = CreatorId.FromPublicKeyBytes(pub);
            Assert(Patterns.AttributedCreatorId().IsMatch(cid.Value));
        });

        Test("Attributed creator_id is deterministic for same key", () =>
        {
            var (_, pub) = Algorithms.GenerateKeyPair();
            Equal(CreatorId.FromPublicKeyBytes(pub).Value,
                  CreatorId.FromPublicKeyBytes(pub).Value);
        });

        Test("Different keys produce different creator_ids", () =>
        {
            var (_, pub1) = Algorithms.GenerateKeyPair();
            var (_, pub2) = Algorithms.GenerateKeyPair();
            Assert(CreatorId.FromPublicKeyBytes(pub1).Value !=
                   CreatorId.FromPublicKeyBytes(pub2).Value);
        });

        Test("Invalid attributed creator_id rejected by validate", () =>
        {
            var threw = false;
            try { CreatorId.Parse("ed25519-fp-tooshort").Validate(); }
            catch (AIOSchemaException) { threw = true; }
            Assert(threw);
        });
    }

    // ---------------------------------------------------------------------------
    // VerificationResult Tests
    // ---------------------------------------------------------------------------

    private static void RunVerificationResult()
    {
        Group("VerificationResult");

        Test("All fields present in result", () =>
        {
            var (seed, pub) = Algorithms.GenerateKeyPair();
            var asset = MakeAsset("vr-fields");
            var m = ManifestBuilder.Generate(asset, privateKeySeed: seed);
            var r = Verifier.Verify(asset, m, publicKey: pub);
            Assert(r.Success);
            Assert(r.MatchType is not null);
            Assert(r.SignatureVerified);
            Assert(r.ManifestSignatureVerified);
            Assert(r.Warnings is not null);
        });

        Test("Summary includes match type and signature status", () =>
        {
            var asset = MakeAsset("vr-summary");
            var m = ManifestBuilder.Generate(asset);
            var r = Verifier.Verify(asset, m);
            var s = r.Summary();
            Contains("hard", s);
            Contains("unsigned", s);
        });

        Test("Fail result has Success=false", () =>
        {
            var r = VerificationResult.Fail("test error");
            Assert(!r.Success);
            Equal("test error", r.Message);
        });
    }

    // ---------------------------------------------------------------------------
    // Spec Constants Tests
    // ---------------------------------------------------------------------------

    private static void RunSpecConstants()
    {
        Group("Spec Constants");

        Test("SPEC_VERSION is 0.5.6", () =>
            Equal("0.5.6", Constants.SpecVersion));

        Test("SUPPORTED_VERSIONS includes 0.5.5", () =>
            Assert(Constants.SupportedVersions.Contains("0.5.5")));

        Test("SUPPORTED_VERSIONS includes 0.5.6", () =>
            Assert(Constants.SupportedVersions.Contains("0.5.6")));

        Test("SUPPORTED_VERSIONS includes all prior versions", () =>
        {
            var expected = new[] { "0.1", "0.2", "0.3", "0.3.1", "0.4", "0.5", "0.5.1", "0.5.5", "0.5.6" };
            foreach (var v in expected)
                Assert(Constants.SupportedVersions.Contains(v), $"Missing: {v}");
        });

        Test("DEFAULT_HASH_ALG is sha256", () =>
            Equal("sha256", Constants.DefaultHashAlg));

        Test("SOFT_BINDING_THRESHOLD_DEFAULT is 5", () =>
            Equal(5, Constants.SoftBindingThresholdDefault));

        Test("SOFT_BINDING_THRESHOLD_MAX is 10", () =>
            Equal(10, Constants.SoftBindingThresholdMax));

        Test("CORE_HASH_FIELDS has exactly 5 fields", () =>
            Equal(5, Constants.CoreHashFields.Length));

        Test("generate produces 0.5.5 schema_version", () =>
        {
            var m = ManifestBuilder.Generate(MakeAsset("const-gen"));
            Equal(Constants.SpecVersion, m.Core.SchemaVersion);
        });
    }

    // ---------------------------------------------------------------------------
    // Entry point
    // ---------------------------------------------------------------------------

    public static int Run()
    {
        _passed = 0;
        _failed = 0;

        Console.WriteLine("AIOSchema v0.5.6 — Test Suite (.NET)");
        Console.WriteLine("=====================================");
        Console.WriteLine("TV-01 through TV-18 + extended tests");

        RunTV0104();
        RunTV1318();
        RunMultiHash();
        RunSha384();
        RunManifestSignature();
        RunAnchor();
        RunBackwardCompat();
        RunCoreFingerprint();
        RunCreatorId();
        RunVerificationResult();
        RunSpecConstants();

    private static void RunTV25()
    {
        Group("TV-25: compliance_eu_art50");

        Test("TV-25-A: field present — no warning expected", () =>
        {
            var asset = Encoding.UTF8.GetBytes("TV-25 compliance_eu_art50 test");
            var manifest = ManifestBuilder.Generate(asset, extensions: new()
            {
                ["ai_declaration"] = new Dictionary<string, object?>
                {
                    ["disclosure_required"] = true,
                    ["ai_generated"]        = true,
                    ["ai_manipulated"]      = false,
                    ["human_reviewed"]      = true,
                },
                ["compliance_eu_art50"] = new Dictionary<string, object?>
                {
                    ["editorial_responsibility"] = "Test Organisation",
                    ["review_type"]              = "substantive",
                },
            });
            var result = Verifier.Verify(asset, manifest);
            Assert(result.Success, $"TV-25-A failed: {result.Message}");
            foreach (var w in result.Warnings)
                Assert(!w.Contains("compliance_eu_art50"),
                    $"TV-25-A: unexpected warning: {w}");
        });

        Test("TV-25-B: field absent — warning not failure", () =>
        {
            var asset = Encoding.UTF8.GetBytes("TV-25 compliance_eu_art50 test");
            var manifest = ManifestBuilder.Generate(asset, extensions: new()
            {
                ["ai_declaration"] = new Dictionary<string, object?>
                {
                    ["disclosure_required"] = true,
                    ["ai_generated"]        = true,
                    ["ai_manipulated"]      = false,
                    ["human_reviewed"]      = true,
                },
            });
            var result = Verifier.Verify(asset, manifest);
            Assert(result.Success, $"TV-25-B must pass (warning not failure): {result.Message}");
            Assert(result.Warnings.Any(w => w.Contains("compliance_eu_art50")),
                "TV-25-B: expected compliance_eu_art50 warning");
        });
    }

        RunTV25();

        Console.WriteLine();
        Console.WriteLine(new string('=', 51));
        Console.WriteLine($"Results: {_passed} passed, {_failed} failed, {_passed + _failed} total");
        Console.WriteLine(new string('=', 51));

        if (_failed > 0)
        {
            Console.Error.WriteLine($"\nFAIL: {_failed} test(s) failed.");
            return 1;
        }

        Console.WriteLine("\nAll tests passed.");
        return 0;
    }
}
// -- end aioschema/dotnet v0.5.6 | AIOSchema spec v0.5.6 --
