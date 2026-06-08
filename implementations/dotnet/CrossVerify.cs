// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ovidiu Ancuta
//
// aioschema/dotnet v0.5.6 | AIOSchema spec v0.5.6
// https://aioschema.org

using System.Text;
using System.Text.Json;
using AIOSchema;

namespace AIOSchema;

public static class CrossVerify
{
    public static int Run(string vectorsPath)
    {
        if (!File.Exists(vectorsPath))
        {
            Console.Error.WriteLine($"cross_verify_vectors.json not found at: {vectorsPath}");
            Console.Error.WriteLine("Set AIOSCHEMA_VECTORS env var or pass path as argument.");
            return 1;
        }

        Console.WriteLine("AIOSchema v0.5.6 — Cross-Verification Suite (.NET)");
        Console.WriteLine("===================================================");
        Console.WriteLine($"Vectors: {vectorsPath}");
        Console.WriteLine();

        using var doc     = JsonDocument.Parse(File.ReadAllText(vectorsPath));
        var specVersion   = doc.RootElement.GetProperty("spec_version").GetString();
        var vectors       = doc.RootElement.GetProperty("vectors");
        Console.WriteLine($"Spec version: {specVersion}");
        Console.WriteLine();

        int passed = 0;
        int failed = 0;

        foreach (var v in vectors.EnumerateArray())
        {
            var id     = v.GetProperty("id").GetString()!;
            var name   = v.GetProperty("name").GetString()!;
            var inputs = v.GetProperty("inputs");

            try
            {
                RunVector(id, name, inputs, v, ref passed, ref failed);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"  FAIL  {id}: {name}");
                Console.WriteLine($"        Exception: {ex.Message}");
                failed++;
            }
        }

        Console.WriteLine();
        Console.WriteLine(new string('=', 51));
        Console.WriteLine($"Results: {passed} passed, {failed} failed, {passed + failed} total");
        Console.WriteLine(new string('=', 51));

        if (failed > 0)
        {
            Console.Error.WriteLine($"\nFAIL: {failed} cross-verification vector(s) failed.");
            return 1;
        }

        Console.WriteLine("\nAll cross-verification vectors passed.");
        Console.WriteLine(".NET implementation is interoperable with Python / TypeScript / Node.js / Go / Rust.");
        return 0;
    }

    private static void RunVector(
        string id, string name, JsonElement inputs, JsonElement v,
        ref int passed, ref int failed)
    {
        // CV-01 to CV-04: hash computation
        if (inputs.TryGetProperty("data_hex", out var dataHexEl) &&
            inputs.TryGetProperty("algorithm", out var algEl))
        {
            var data     = Convert.FromHexString(dataHexEl.GetString()!);
            var alg      = algEl.GetString()!;
            var expected = v.GetProperty("expected").GetString()!;
            var result   = Algorithms.ComputeHash(data, alg);

            if (result == expected)
            {
                Console.WriteLine($"  PASS  {id}: {name}");
                passed++;
            }
            else
            {
                Console.WriteLine($"  FAIL  {id}: {name}");
                Console.WriteLine($"        expected: {expected}");
                Console.WriteLine($"        got:      {result}");
                failed++;
            }
            return;
        }

        // CV-05: canonical JSON
        if (inputs.TryGetProperty("object", out var objEl))
        {
            var expected = v.GetProperty("expected").GetString()!;
            var dict     = JsonElementToDict(objEl);
            var result   = Algorithms.CanonicalJson(dict);

            if (result == expected)
            {
                Console.WriteLine($"  PASS  {id}: {name}");
                passed++;
            }
            else
            {
                Console.WriteLine($"  FAIL  {id}: {name}");
                Console.WriteLine($"        expected: {expected}");
                Console.WriteLine($"        got:      {result}");
                failed++;
            }
            return;
        }

        // CV-06: core_fingerprint
        if (inputs.TryGetProperty("core_fields", out var cfEl))
        {
            var expected = v.GetProperty("expected").GetString()!;
            var fields   = new Dictionary<string, object?>();
            foreach (var key in Constants.CoreHashFields)
                if (cfEl.TryGetProperty(key, out var val))
                    fields[key] = val.GetString();

            var canonical = Algorithms.CanonicalBytes(fields);
            var result    = Algorithms.ComputeHash(canonical, "sha256");

            if (result == expected)
            {
                Console.WriteLine($"  PASS  {id}: {name}");
                passed++;
            }
            else
            {
                Console.WriteLine($"  FAIL  {id}: {name}");
                Console.WriteLine($"        expected: {expected}");
                Console.WriteLine($"        got:      {result}");
                failed++;
            }
            return;
        }

        // CV-07 to CV-14: manifest verification
        if (inputs.TryGetProperty("asset_hex", out var assetHexEl) &&
            inputs.TryGetProperty("manifest", out var manifestEl))
        {
            var assetBytes       = Convert.FromHexString(assetHexEl.GetString()!);
            var manifest         = ParseManifest(manifestEl);
            var result           = Verifier.Verify(assetBytes, manifest);
            var expectedSuccess  = v.GetProperty("expected").GetProperty("success").GetBoolean();

            bool ok = result.Success == expectedSuccess;
            // If expected has match_type, check it too
            if (ok && v.GetProperty("expected").TryGetProperty("match_type", out var mtEl))
                ok = result.MatchType == mtEl.GetString();

            if (ok)
            {
                Console.WriteLine($"  PASS  {id}: {name}");
                if (result.Warnings.Count > 0)
                    foreach (var w in result.Warnings)
                        Console.WriteLine($"        warn: {w}");
                passed++;
            }
            else
            {
                Console.WriteLine($"  FAIL  {id}: {name}");
                Console.WriteLine($"        expected success={expectedSuccess}, got={result.Success}");
                Console.WriteLine($"        message: {result.Message}");
                failed++;
            }
            return;
        }

        // Unknown vector shape
        Console.WriteLine($"  SKIP  {id}: {name} (unrecognized input shape)");
    }

    // ---------------------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------------------

    private static AIOSManifest ParseManifest(JsonElement el)
    {
        var coreEl = el.GetProperty("core");
        var c      = new CoreBlock();

        string? GetStr(string k) =>
            coreEl.TryGetProperty(k, out var v) && v.ValueKind != JsonValueKind.Null
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

        var ext = new Dictionary<string, object?>();
        if (el.TryGetProperty("extensions", out var extEl) && extEl.ValueKind == JsonValueKind.Object)
            foreach (var p in extEl.EnumerateObject())
                ext[p.Name] = JsonToObject(p.Value);

        return new AIOSManifest { Core = c, Extensions = ext };
    }

    private static Dictionary<string, object?> JsonElementToDict(JsonElement el)
    {
        var d = new Dictionary<string, object?>();
        foreach (var p in el.EnumerateObject())
            d[p.Name] = JsonToObject(p.Value);
        return d;
    }

    private static object? JsonToObject(JsonElement je) => je.ValueKind switch
    {
        JsonValueKind.Null   => null,
        JsonValueKind.True   => true,
        JsonValueKind.False  => false,
        JsonValueKind.String => je.GetString(),
        JsonValueKind.Number => je.TryGetInt64(out var l) ? (object)l : je.GetDouble(),
        JsonValueKind.Array  => je.EnumerateArray().Select(e => JsonToObject(e)).ToList<object?>(),
        JsonValueKind.Object => JsonElementToDict(je),
        _ => null,
    };
}
// -- end aioschema/dotnet v0.5.6 | AIOSchema spec v0.5.6 --
