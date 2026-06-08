// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ovidiu Ancuta
//
// aioschema/dotnet v0.5.6 | AIOSchema spec v0.5.6
// https://aioschema.org

using System.Text;
using System.Text.Json;
using AIOSchema;

// ---------------------------------------------------------------------------
// Entry point — dispatch on args
// ---------------------------------------------------------------------------

if (args.Length > 0 && args[0] == "--test-suite")
{
    Environment.Exit(TestSuite.Run());
}

if (args.Length > 0 && args[0] == "--cross-verify")
{
    var path = args.Length > 1 ? args[1]
             : Environment.GetEnvironmentVariable("AIOSCHEMA_VECTORS")
               ?? "cross_verify_vectors.json";
    Environment.Exit(CrossVerify.Run(path));
}

// ---------------------------------------------------------------------------
// Minimal test harness
// ---------------------------------------------------------------------------

int passed  = 0;
int failed  = 0;
string? currentGroup = null;

void Group(string name)
{
    currentGroup = name;
    Console.WriteLine($"\n--- {name} ---");
}

void Test(string name, Action fn)
{
    try
    {
        fn();
        Console.WriteLine($"  PASS  {name}");
        passed++;
    }
    catch (Exception ex)
    {
        Console.WriteLine($"  FAIL  {name}");
        Console.WriteLine($"        {ex.Message}");
        failed++;
    }
}

void Assert(bool condition, string message = "Assertion failed")
{
    if (!condition) throw new Exception(message);
}

void Equal<T>(T expected, T actual, string? label = null)
{
    if (!EqualityComparer<T>.Default.Equals(expected, actual))
        throw new Exception($"{label ?? "Expected"}: {expected}\n        Actual:   {actual}");
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

Group("Hash computation");

Test("SHA-256 known vector", () =>
{
    var data   = Encoding.UTF8.GetBytes("The quick brown fox jumps over the lazy dog");
    var result = Algorithms.ComputeHash(data, "sha256");
    Equal("sha256-d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592", result);
});

Test("SHA-384 known vector", () =>
{
    var data   = Encoding.UTF8.GetBytes("The quick brown fox jumps over the lazy dog");
    var result = Algorithms.ComputeHash(data, "sha384");
    Equal("sha384-ca737f1014a48f4c0b6dd43cb177b0afd9e5169367544c494011e3317dbf9a509cb1e5dc1e85a941bbee3d7f2afbc9b1", result);
});

Test("SHA3-256 produces correct prefix and length", () =>
{
    var data   = Encoding.UTF8.GetBytes("The quick brown fox jumps over the lazy dog");
    var result = Algorithms.ComputeHash(data, "sha3-256");
    Assert(result.StartsWith("sha3-256-"), "Wrong prefix");
    Equal(9 + 64, result.Length, "Length");
});

Test("SHA-256 empty input", () =>
{
    var result = Algorithms.ComputeHash(Array.Empty<byte>(), "sha256");
    Equal("sha256-e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", result);
});

Test("SHA-256 full byte range 0x00-0xFF", () =>
{
    var data   = Enumerable.Range(0, 256).Select(i => (byte)i).ToArray();
    var result = Algorithms.ComputeHash(data, "sha256");
    Equal("sha256-40aff2e9d2d8922e47afd4648e6967497158785fbd1da870e7110266bf944880", result);
});

Test("Unsupported algorithm throws", () =>
{
    var threw = false;
    try { Algorithms.ComputeHash(new byte[] { 1 }, "md5"); }
    catch (AIOSchemaException) { threw = true; }
    Assert(threw, "Expected AIOSchemaException");
});

Group("Canonical JSON");

Test("Sorts keys alphabetically", () =>
{
    var obj = new Dictionary<string, object?> { ["z"] = "last", ["a"] = "first", ["m"] = "mid" };
    Equal("{\"a\":\"first\",\"m\":\"mid\",\"z\":\"last\"}", Algorithms.CanonicalJson(obj));
});

Test("Core hash fields vector (CV-05)", () =>
{
    var obj = new Dictionary<string, object?>
    {
        ["hash_original"]      = "sha256-abc123",
        ["asset_id"]           = "urn:test:001",
        ["creator_id"]         = "ed25519-fp-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ["schema_version"]     = "0.5.5",
        ["creation_timestamp"] = "2026-02-22T12:00:00Z",
    };
    var expected =
        "{\"asset_id\":\"urn:test:001\",\"creation_timestamp\":\"2026-02-22T12:00:00Z\"," +
        "\"creator_id\":\"ed25519-fp-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"," +
        "\"hash_original\":\"sha256-abc123\",\"schema_version\":\"0.5.5\"}";
    Equal(expected, Algorithms.CanonicalJson(obj));
});

Test("No whitespace in output", () =>
{
    var obj  = new Dictionary<string, object?> { ["k"] = "v" };
    var json = Algorithms.CanonicalJson(obj);
    Assert(!json.Contains(' ') && !json.Contains('\n'), "Whitespace found");
});

Test("Null value serializes as null", () =>
{
    var obj = new Dictionary<string, object?> { ["k"] = null };
    Equal("{\"k\":null}", Algorithms.CanonicalJson(obj));
});

Test("Array preserves order", () =>
{
    var obj = new Dictionary<string, object?> { ["arr"] = new List<object?> { "b", "a" } };
    Equal("{\"arr\":[\"b\",\"a\"]}", Algorithms.CanonicalJson(obj));
});

Test("Nested object keys sorted recursively", () =>
{
    var obj = new Dictionary<string, object?>
    {
        ["outer"] = new Dictionary<string, object?> { ["z"] = (object)1L, ["a"] = (object)2L }
    };
    Equal("{\"outer\":{\"a\":2,\"z\":1}}", Algorithms.CanonicalJson(obj));
});

Group("Core fingerprint");

Test("Known vector (CV-06)", () =>
{
    var fields = new Dictionary<string, object?>
    {
        ["asset_id"]           = "urn:test:001",
        ["schema_version"]     = "0.5.5",
        ["creation_timestamp"] = "2026-02-22T12:00:00Z",
        ["hash_original"]      = "sha256-abc123",
        ["creator_id"]         = "ed25519-fp-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    };
    Equal("sha256-9a3b7c8581d2d6f3b325dd4d13a4f8dd1d11575437894d5b2cfd21dbae5b5ce9",
          Algorithms.ComputeCoreFingerprint(fields));
});

Test("core_fingerprint not in CoreHashFields (bootstrap rule)", () =>
{
    Assert(!Constants.CoreHashFields.Contains("core_fingerprint"),
           "core_fingerprint must not be in CoreHashFields");
});

Group("UUID v7");

Test("Generates valid UUID", () =>
{
    var id = Uuid7.NewString();
    Assert(Guid.TryParse(id, out _), $"Not a valid GUID: {id}");
});

Test("Version nibble is 7", () =>
{
    var id = Uuid7.NewString();
    Equal('7', id[14], "Version nibble");
});

Test("Generates unique values", () =>
{
    var ids = Enumerable.Range(0, 100).Select(_ => Uuid7.NewString()).ToHashSet();
    Equal(100, ids.Count, "Unique count");
});

Group("Creator ID");

Test("Anonymous generates UUID", () =>
{
    var cid = CreatorId.Anonymous();
    Assert(cid.Mode == CreatorIdMode.Anonymous);
    Assert(Guid.TryParse(cid.Value, out _));
});

Test("Attributed from public key bytes", () =>
{
    var (seed, pub) = Algorithms.GenerateKeyPair();
    var cid = CreatorId.FromPublicKeyBytes(pub);
    Assert(cid.Mode == CreatorIdMode.Attributed);
    Assert(cid.Value.StartsWith("ed25519-fp-"));
    Equal(11 + 32, cid.Value.Length, "Length");
});

Test("Attributed creator_id is deterministic", () =>
{
    var (_, pub) = Algorithms.GenerateKeyPair();
    var c1 = CreatorId.FromPublicKeyBytes(pub);
    var c2 = CreatorId.FromPublicKeyBytes(pub);
    Equal(c1.Value, c2.Value);
});

Test("Validate attributed - valid", () =>
{
    CreatorId.Parse("ed25519-fp-" + new string('a', 32)).Validate(); // no throw
});

Test("Validate attributed - too short throws", () =>
{
    var threw = false;
    try { CreatorId.Parse("ed25519-fp-abc").Validate(); }
    catch (AIOSchemaException) { threw = true; }
    Assert(threw);
});

Group("Ed25519 sign/verify");

Test("Sign and verify round-trip", () =>
{
    var (seed, pub) = Algorithms.GenerateKeyPair();
    var msg = Encoding.UTF8.GetBytes("AIOSchema test message");
    var sig = Algorithms.Sign(msg, seed);
    Assert(sig.StartsWith("ed25519-"));
    Equal(8 + 128, sig.Length, "Sig length");
    Assert(Algorithms.Verify(msg, sig, pub));
});

Test("Wrong public key returns false", () =>
{
    var (seed1, _)   = Algorithms.GenerateKeyPair();
    var (_, pub2)    = Algorithms.GenerateKeyPair();
    var msg = Encoding.UTF8.GetBytes("test");
    var sig = Algorithms.Sign(msg, seed1);
    Assert(!Algorithms.Verify(msg, sig, pub2));
});

Test("Tampered message returns false", () =>
{
    var (seed, pub) = Algorithms.GenerateKeyPair();
    var original = Encoding.UTF8.GetBytes("original");
    var tampered = Encoding.UTF8.GetBytes("tampered");
    var sig = Algorithms.Sign(original, seed);
    Assert(!Algorithms.Verify(tampered, sig, pub));
});

Group("Manifest");

var testAsset = Encoding.UTF8.GetBytes("AIOSchema .NET reference implementation test asset");

Test("Generate produces valid manifest", () =>
{
    var m = ManifestBuilder.Generate(testAsset);
    Assert(!string.IsNullOrEmpty(m.Core.AssetId));
    Equal(Constants.SpecVersion, m.Core.SchemaVersion);
    Assert(!string.IsNullOrEmpty(m.Core.CreationTimestamp));
    Assert(m.Core.CoreFingerprint?.StartsWith("sha256-") == true);
    Assert(m.Core.Signature is null);
});

Test("Generate with private key produces signatures", () =>
{
    var (seed, _) = Algorithms.GenerateKeyPair();
    var m = ManifestBuilder.Generate(testAsset, privateKeySeed: seed);
    Assert(m.Core.Signature?.StartsWith("ed25519-") == true);
    Assert(m.Core.ManifestSignature?.StartsWith("ed25519-") == true);
});

Test("Generate SHA-384 hash_original", () =>
{
    var m = ManifestBuilder.Generate(testAsset, hashAlgorithm: "sha384");
    var h = m.Core.HashOriginalList();
    Assert(h.Count == 1 && h[0].StartsWith("sha384-"));
});

Test("JSON round-trip preserves all fields", () =>
{
    var m1   = ManifestBuilder.Generate(testAsset);
    var json = ManifestBuilder.ToJson(m1);
    var m2   = ManifestBuilder.FromJson(json);
    Equal(m1.Core.AssetId, m2.Core.AssetId);
    Equal(m1.Core.CoreFingerprint, m2.Core.CoreFingerprint);
    Equal(m1.Core.CreationTimestamp, m2.Core.CreationTimestamp);
});

Test("ToJson is canonical (no whitespace, sorted keys)", () =>
{
    var m    = ManifestBuilder.Generate(testAsset);
    var json = ManifestBuilder.ToJson(m);
    Assert(!json.Contains("  "), "Indentation found");
    var assetIdx   = json.IndexOf("asset_id");
    var createIdx  = json.IndexOf("creation_timestamp");
    Assert(assetIdx < createIdx, "Keys not sorted");
});

Group("Verification");

Test("Valid unsigned manifest passes", () =>
{
    var m = ManifestBuilder.Generate(testAsset);
    var r = Verifier.Verify(testAsset, m);
    Assert(r.Success, r.Message);
    Equal("hard", r.MatchType);
});

Test("Valid signed manifest passes", () =>
{
    var (seed, pub) = Algorithms.GenerateKeyPair();
    var m = ManifestBuilder.Generate(testAsset, privateKeySeed: seed);
    var r = Verifier.Verify(testAsset, m, publicKey: pub);
    Assert(r.Success, r.Message);
    Assert(r.SignatureVerified);
    Assert(r.ManifestSignatureVerified);
});

Test("Tampered content fails", () =>
{
    var m   = ManifestBuilder.Generate(testAsset);
    var bad = Encoding.UTF8.GetBytes("different content entirely");
    var r   = Verifier.Verify(bad, m);
    Assert(!r.Success);
});

Test("Tampered core_fingerprint fails", () =>
{
    var m = ManifestBuilder.Generate(testAsset);
    m.Core.CoreFingerprint = "sha256-" + new string('0', 64);
    var r = Verifier.Verify(testAsset, m);
    Assert(!r.Success);
});

Test("Unsupported schema version fails", () =>
{
    var m = ManifestBuilder.Generate(testAsset);
    m.Core.SchemaVersion = "99.0";
    var r = Verifier.Verify(testAsset, m);
    Assert(!r.Success);
});

Test("Missing creator_id fails", () =>
{
    var m = ManifestBuilder.Generate(testAsset);
    m.Core.CreatorId = "";
    var r = Verifier.Verify(testAsset, m);
    Assert(!r.Success);
});

Test("Invalid timestamp format fails", () =>
{
    var m = ManifestBuilder.Generate(testAsset);
    m.Core.CreationTimestamp = "2026-02-22 12:00:00";
    var r = Verifier.Verify(testAsset, m);
    Assert(!r.Success);
});

Test("Wrong public key fails", () =>
{
    var (seed, _)   = Algorithms.GenerateKeyPair();
    var (_, wrongPub) = Algorithms.GenerateKeyPair();
    var m = ManifestBuilder.Generate(testAsset, privateKeySeed: seed);
    var r = Verifier.Verify(testAsset, m, publicKey: wrongPub);
    Assert(!r.Success);
});

Test("hash_schema_block alias accepted", () =>
{
    var m = ManifestBuilder.Generate(testAsset);
    m.Core.HashSchemaBlock = m.Core.CoreFingerprint;
    m.Core.CoreFingerprint = null;
    var r = Verifier.Verify(testAsset, m);
    Assert(r.Success, r.Message);
});

Test("Multi-hash: any match suffices", () =>
{
    var m = ManifestBuilder.Generate(testAsset);
    var sha384h = Algorithms.ComputeHash(testAsset, "sha384");
    m.Core.HashOriginal = new List<string>
    {
        (string)m.Core.HashOriginal,
        sha384h,
    };
    m.Core.CoreFingerprint = Algorithms.ComputeCoreFingerprint(ManifestBuilder.CoreToDict(m.Core));
    var r = Verifier.Verify(testAsset, m);
    Assert(r.Success, r.Message);
});

Test("No asset bytes skips content check", () =>
{
    var m = ManifestBuilder.Generate(testAsset);
    var r = Verifier.Verify(null, m);
    Assert(r.Success, r.Message);
    Assert(r.MatchType is null);
});

Test("Anchor resolver is called and verified", () =>
{
    var m = ManifestBuilder.Generate(testAsset);
    m.Core.AnchorReference = "aios-anchor:bitcoin:abc123";
    bool called = false;
    AnchorResolver resolver = (ref_) =>
    {
        called = true;
        return new Dictionary<string, string>
        {
            ["asset_id"]         = m.Core.AssetId,
            ["core_fingerprint"] = m.Core.CoreFingerprint!,
        };
    };
    var r = Verifier.Verify(testAsset, m, verifyAnchor: true, anchorResolver: resolver);
    Assert(r.Success, r.Message);
    Assert(called, "Resolver not called");
    Assert(r.AnchorVerified);
});

// ---------------------------------------------------------------------------
// Cross-verification vectors
// ---------------------------------------------------------------------------

Group("Cross-verification vectors");

var vectorJson = File.ReadAllText("cross_verify_vectors.json");
using var vectorDoc = JsonDocument.Parse(vectorJson);
var vectors = vectorDoc.RootElement.GetProperty("vectors");

JsonElement FindVector(string id)
{
    foreach (var v in vectors.EnumerateArray())
        if (v.GetProperty("id").GetString() == id) return v;
    throw new Exception($"Vector {id} not found");
}

AIOSManifest ParseManifestFromElement(JsonElement el)
{
    var coreEl = el.GetProperty("core");
    var c = new CoreBlock();
    string? GetStr(string k) => coreEl.TryGetProperty(k, out var v) && v.ValueKind != JsonValueKind.Null
        ? v.GetString() : null;

    c.AssetId               = GetStr("asset_id") ?? "";
    c.SchemaVersion         = GetStr("schema_version") ?? "";
    c.CreationTimestamp     = GetStr("creation_timestamp") ?? "";
    c.CreatorId             = GetStr("creator_id") ?? "";
    c.CoreFingerprint       = GetStr("core_fingerprint");
    c.HashSchemaBlock       = GetStr("hash_schema_block");
    c.Signature             = GetStr("signature");
    c.ManifestSignature     = GetStr("manifest_signature");
    c.AnchorReference       = GetStr("anchor_reference");
    c.PreviousVersionAnchor = GetStr("previous_version_anchor");

    if (coreEl.TryGetProperty("hash_original", out var ho))
    {
        if (ho.ValueKind == JsonValueKind.Array)
            c.HashOriginal = ho.EnumerateArray().Select(e => e.GetString()!).ToList<string>();
        else
            c.HashOriginal = ho.GetString()!;
    }

    return new AIOSManifest { Core = c };
}

// CV-01
Test("CV-01: SHA-256 of known content", () =>
{
    var v   = FindVector("CV-01");
    var inp = v.GetProperty("inputs");
    var data = Convert.FromHexString(inp.GetProperty("data_hex").GetString()!);
    var alg  = inp.GetProperty("algorithm").GetString()!;
    Equal(v.GetProperty("expected").GetString()!, Algorithms.ComputeHash(data, alg));
});

// CV-02
Test("CV-02: SHA-384 of known content", () =>
{
    var v   = FindVector("CV-02");
    var inp = v.GetProperty("inputs");
    var data = Convert.FromHexString(inp.GetProperty("data_hex").GetString()!);
    var alg  = inp.GetProperty("algorithm").GetString()!;
    Equal(v.GetProperty("expected").GetString()!, Algorithms.ComputeHash(data, alg));
});

// CV-03
Test("CV-03: SHA-256 of empty bytes", () =>
{
    var v = FindVector("CV-03");
    Equal(v.GetProperty("expected").GetString()!, Algorithms.ComputeHash(Array.Empty<byte>(), "sha256"));
});

// CV-04
Test("CV-04: SHA-256 full byte range", () =>
{
    var v    = FindVector("CV-04");
    var data = Convert.FromHexString(v.GetProperty("inputs").GetProperty("data_hex").GetString()!);
    Equal(v.GetProperty("expected").GetString()!, Algorithms.ComputeHash(data, "sha256"));
});

// CV-05
Test("CV-05: Canonical JSON of core hash fields", () =>
{
    var v   = FindVector("CV-05");
    var obj = v.GetProperty("inputs").GetProperty("object");
    var dict = new Dictionary<string, object?>
    {
        ["hash_original"]      = obj.GetProperty("hash_original").GetString()!,
        ["asset_id"]           = obj.GetProperty("asset_id").GetString()!,
        ["creator_id"]         = obj.GetProperty("creator_id").GetString()!,
        ["schema_version"]     = obj.GetProperty("schema_version").GetString()!,
        ["creation_timestamp"] = obj.GetProperty("creation_timestamp").GetString()!,
    };
    Equal(v.GetProperty("expected").GetString()!, Algorithms.CanonicalJson(dict));
});

// CV-06
Test("CV-06: core_fingerprint of known fields", () =>
{
    var v  = FindVector("CV-06");
    var cf = v.GetProperty("inputs").GetProperty("core_fields");
    var fields = new Dictionary<string, object?>
    {
        ["asset_id"]           = cf.GetProperty("asset_id").GetString()!,
        ["schema_version"]     = cf.GetProperty("schema_version").GetString()!,
        ["creation_timestamp"] = cf.GetProperty("creation_timestamp").GetString()!,
        ["hash_original"]      = cf.GetProperty("hash_original").GetString()!,
        ["creator_id"]         = cf.GetProperty("creator_id").GetString()!,
    };
    Equal(v.GetProperty("expected").GetString()!, Algorithms.ComputeCoreFingerprint(fields));
});

// CV-07 through CV-14: manifest verification
var verifyVectors = new[]
{
    ("CV-07", true),
    ("CV-08", false),
    ("CV-09", false),
    ("CV-10", true),
    ("CV-11", true),
    ("CV-12", false),
    ("CV-13", false),
    ("CV-14", false),
};

foreach (var (id, expectedSuccess) in verifyVectors)
{
    var capturedId      = id;
    var capturedExpect  = expectedSuccess;
    Test($"{capturedId}: manifest verification (expected={capturedExpect})", () =>
    {
        var v        = FindVector(capturedId);
        var inputs   = v.GetProperty("inputs");
        var assetHex = inputs.GetProperty("asset_hex").GetString()!;
        var asset    = Convert.FromHexString(assetHex);
        var manifest = ParseManifestFromElement(inputs.GetProperty("manifest"));
        var result   = Verifier.Verify(asset, manifest);
        Equal(capturedExpect, result.Success,
              $"{capturedId}: expected success={capturedExpect}, got={result.Success}. Msg: {result.Message}");
    });
}

// ---------------------------------------------------------------------------
// Summary
// ---------------------------------------------------------------------------

Console.WriteLine();
Console.WriteLine(new string('=', 50));
Console.WriteLine($"Results: {passed} passed, {failed} failed, {passed + failed} total");
Console.WriteLine(new string('=', 50));

if (failed > 0)
{
    Console.Error.WriteLine($"FAIL: {failed} test(s) failed");
    Environment.Exit(1);
}

Console.WriteLine("All tests passed.");
// -- end aioschema/dotnet v0.5.6 | AIOSchema spec v0.5.6 --
