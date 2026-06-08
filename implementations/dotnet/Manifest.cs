// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ovidiu Ancuta
//
// aioschema/dotnet v0.5.6 | AIOSchema spec v0.5.6
// https://aioschema.org

using System.Security.Cryptography;
using System.Text.Json;

namespace AIOSchema;

public static class ManifestBuilder
{
    // ---------------------------------------------------------------------------
    // Generate
    // ---------------------------------------------------------------------------

    public static AIOSManifest Generate(
        byte[] assetBytes,
        string? creatorIdValue               = null,
        byte[]? privateKeySeed               = null,
        string hashAlgorithm                 = Constants.DefaultHashAlg,
        Dictionary<string, object?>? extensions = null)
    {
        var hashOriginal = Algorithms.ComputeHash(assetBytes, hashAlgorithm);

        CreatorId creator;
        if (creatorIdValue is not null)
            creator = CreatorId.Parse(creatorIdValue);
        else if (privateKeySeed is not null)
            creator = CreatorId.FromPublicKeyBytes(Ed25519.PublicKeyFromSeed(privateKeySeed));
        else
            creator = CreatorId.Anonymous();

        creator.Validate();

        var core = new CoreBlock
        {
            AssetId           = Uuid7.NewString(),
            SchemaVersion     = Constants.SpecVersion,
            CreationTimestamp = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ"),
            HashOriginal      = hashOriginal,
            CreatorId         = creator.Value,
        };

        core.CoreFingerprint = Algorithms.ComputeCoreFingerprint(CoreToDict(core));

        var manifest = new AIOSManifest
        {
            Core       = core,
            Extensions = extensions ?? new Dictionary<string, object?>(),
        };

        if (privateKeySeed is not null)
        {
            var coreBytes = Algorithms.CanonicalCoreBytes(CoreToDict(core));
            core.Signature = Algorithms.Sign(coreBytes, privateKeySeed);

            var manifestBytes = Algorithms.CanonicalManifestBytes(ToDict(manifest));
            core.ManifestSignature = Algorithms.Sign(manifestBytes, privateKeySeed);
        }

        return manifest;
    }

    // ---------------------------------------------------------------------------
    // Serialization
    // ---------------------------------------------------------------------------

    public static string ToJson(AIOSManifest manifest) =>
        Algorithms.CanonicalJson(ToDict(manifest));

    public static AIOSManifest FromJson(string json)
    {
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;

        if (!root.TryGetProperty("core", out var coreEl))
            throw new AIOSchemaException("Manifest JSON missing 'core' block");

        var core = ParseCore(coreEl);
        var ext  = new Dictionary<string, object?>();

        if (root.TryGetProperty("extensions", out var extEl) && extEl.ValueKind == JsonValueKind.Object)
            foreach (var p in extEl.EnumerateObject())
                ext[p.Name] = JsonToObject(p.Value);

        return new AIOSManifest { Core = core, Extensions = ext };
    }

    // ---------------------------------------------------------------------------
    // Sidecar
    // ---------------------------------------------------------------------------

    public static string SidecarPath(string assetPath) => assetPath + Constants.SidecarSuffix;

    public static void SaveSidecar(AIOSManifest manifest, string assetPath) =>
        File.WriteAllText(SidecarPath(assetPath), ToJson(manifest));

    public static AIOSManifest LoadSidecar(string assetPath) =>
        FromJson(File.ReadAllText(SidecarPath(assetPath)));

    // ---------------------------------------------------------------------------
    // Internal helpers
    // ---------------------------------------------------------------------------

    internal static Dictionary<string, object?> ToDict(AIOSManifest m) => new()
    {
        ["core"]       = CoreToDict(m.Core),
        ["extensions"] = m.Extensions,
    };

    internal static Dictionary<string, object?> CoreToDict(CoreBlock c)
    {
        var d = new Dictionary<string, object?>
        {
            ["asset_id"]                = c.AssetId,
            ["schema_version"]          = c.SchemaVersion,
            ["creation_timestamp"]      = c.CreationTimestamp,
            ["hash_original"]           = c.HashOriginal,
            ["creator_id"]              = c.CreatorId,
            ["core_fingerprint"]        = c.CoreFingerprint,
            ["signature"]               = c.Signature,
            ["manifest_signature"]      = c.ManifestSignature,
            ["anchor_reference"]        = c.AnchorReference,
            ["previous_version_anchor"] = c.PreviousVersionAnchor,
        };
        if (c.HashSchemaBlock is not null)
            d["hash_schema_block"] = c.HashSchemaBlock;
        return d;
    }

    private static CoreBlock ParseCore(JsonElement el)
    {
        var c = new CoreBlock();
        string? Get(string k) => el.TryGetProperty(k, out var v) && v.ValueKind != JsonValueKind.Null ? v.GetString() : null;

        c.AssetId               = Get("asset_id") ?? "";
        c.SchemaVersion         = Get("schema_version") ?? "";
        c.CreationTimestamp     = Get("creation_timestamp") ?? "";
        c.CreatorId             = Get("creator_id") ?? "";
        c.CoreFingerprint       = Get("core_fingerprint");
        c.HashSchemaBlock       = Get("hash_schema_block");
        c.Signature             = Get("signature");
        c.ManifestSignature     = Get("manifest_signature");
        c.AnchorReference       = Get("anchor_reference");
        c.PreviousVersionAnchor = Get("previous_version_anchor");

        if (el.TryGetProperty("hash_original", out var ho))
        {
            if (ho.ValueKind == JsonValueKind.Array)
                c.HashOriginal = ho.EnumerateArray().Select(e => e.GetString()!).ToList<string>();
            else
                c.HashOriginal = ho.GetString() ?? "";
        }

        return c;
    }

    private static object? JsonToObject(JsonElement je) => je.ValueKind switch
    {
        JsonValueKind.Null   => null,
        JsonValueKind.True   => true,
        JsonValueKind.False  => false,
        JsonValueKind.String => je.GetString(),
        JsonValueKind.Number => je.TryGetInt64(out var l) ? (object)l : je.GetDouble(),
        JsonValueKind.Array  => je.EnumerateArray().Select(e => JsonToObject(e)).ToList<object?>(),
        JsonValueKind.Object =>
            je.EnumerateObject().ToDictionary(p => p.Name, p => (object?)JsonToObject(p.Value)),
        _ => null,
    };
}
// -- end aioschema/dotnet v0.5.6 | AIOSchema spec v0.5.6 --
