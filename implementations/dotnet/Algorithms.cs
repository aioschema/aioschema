// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ovidiu Ancuta
//
// aioschema/dotnet v0.5.6 | AIOSchema spec v0.5.6
// https://aioschema.org

using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace AIOSchema;

public static class Algorithms
{
    // ---------------------------------------------------------------------------
    // Hash computation (§5.3)
    // ---------------------------------------------------------------------------

    public static string ComputeHash(byte[] data, string algorithm = Constants.DefaultHashAlg)
    {
        if (!Constants.HashRegistry.ContainsKey(algorithm))
            throw new AIOSchemaException(
                $"Unsupported algorithm '{algorithm}'. Supported: {string.Join(", ", Constants.HashRegistry.Keys)}");

        byte[] digest = algorithm switch
        {
            "sha256"   => SHA256.HashData(data),
            "sha384"   => SHA384.HashData(data),
            "sha3-256" => SHA3_256.HashData(data),
            _          => throw new AIOSchemaException($"Unhandled: {algorithm}")
        };

        return $"{algorithm}-{Convert.ToHexString(digest).ToLowerInvariant()}";
    }

    public static (string Algorithm, string HexDigest) ParseHash(string value, string fieldName)
    {
        if (!Patterns.Hash().IsMatch(value))
            throw new AIOSchemaException(
                $"{fieldName} has invalid format '{value}'. " +
                "Expected: (sha256|sha3-256)-<64hex> or sha384-<96hex>");

        string alg = value.StartsWith("sha3-256-", StringComparison.Ordinal) ? "sha3-256"
                   : value.StartsWith("sha384-",   StringComparison.Ordinal) ? "sha384"
                   : "sha256";

        return (alg, value[(alg.Length + 1)..]);
    }

    public static bool SafeEqual(string a, string b) =>
        CryptographicOperations.FixedTimeEquals(
            Encoding.UTF8.GetBytes(a),
            Encoding.UTF8.GetBytes(b));

    // ---------------------------------------------------------------------------
    // Canonical JSON (§6)
    // ---------------------------------------------------------------------------

    public static byte[] CanonicalBytes(object? value) =>
        Encoding.UTF8.GetBytes(CanonicalJson(value));

    public static string CanonicalJson(object? value) =>
        Serialize(Normalize(value));

    private static string Serialize(object? value) => value switch
    {
        null                                   => "null",
        bool b                                 => b ? "true" : "false",
        string s                               => JsonEncode(s),
        int i                                  => i.ToString(),
        long l                                 => l.ToString(),
        double d                               => d.ToString("G"),
        SortedDictionary<string, object?> dict => SerializeObject(dict),
        List<object?> list                     => SerializeArray(list),
        _ => throw new AIOSchemaException($"Cannot serialize type {value.GetType().Name}")
    };

    private static string SerializeObject(SortedDictionary<string, object?> dict)
    {
        var parts = dict.Select(kv => $"{JsonEncode(kv.Key)}:{Serialize(kv.Value)}");
        return $"{{{string.Join(",", parts)}}}";
    }

    private static string SerializeArray(List<object?> list) =>
        $"[{string.Join(",", list.Select(Serialize))}]";

    private static object? Normalize(object? value) => value switch
    {
        null                                    => null,
        bool or int or long or double or string => value,
        Dictionary<string, object?> d           => NormalizeDict(d),
        SortedDictionary<string, object?> d     => NormalizeSorted(d),
        List<string> ls                         => ls.Select(s => (object?)s).ToList(),
        System.Collections.IEnumerable en when value is not string =>
            en.Cast<object?>().Select(Normalize).ToList(),
        JsonElement je                          => Normalize(FromJsonElement(je)),
        _ => value,
    };

    private static SortedDictionary<string, object?> NormalizeDict(Dictionary<string, object?> d)
    {
        var s = new SortedDictionary<string, object?>(StringComparer.Ordinal);
        foreach (var kv in d) s[kv.Key] = Normalize(kv.Value);
        return s;
    }

    private static SortedDictionary<string, object?> NormalizeSorted(SortedDictionary<string, object?> d)
    {
        var s = new SortedDictionary<string, object?>(StringComparer.Ordinal);
        foreach (var kv in d) s[kv.Key] = Normalize(kv.Value);
        return s;
    }

    private static object? FromJsonElement(JsonElement je) => je.ValueKind switch
    {
        JsonValueKind.Null   => null,
        JsonValueKind.True   => true,
        JsonValueKind.False  => false,
        JsonValueKind.String => je.GetString(),
        JsonValueKind.Number => je.TryGetInt64(out var l) ? (object)l : je.GetDouble(),
        JsonValueKind.Array  => je.EnumerateArray().Select(e => FromJsonElement(e)).ToList<object?>(),
        JsonValueKind.Object =>
            je.EnumerateObject().ToDictionary(p => p.Name, p => (object?)FromJsonElement(p.Value)),
        _ => null,
    };

    private static string JsonEncode(string s)
    {
        var sb = new StringBuilder(s.Length + 2);
        sb.Append('"');
        foreach (var c in s)
        {
            switch (c)
            {
                case '"':  sb.Append("\\\""); break;
                case '\\': sb.Append("\\\\"); break;
                case '\b': sb.Append("\\b");  break;
                case '\f': sb.Append("\\f");  break;
                case '\n': sb.Append("\\n");  break;
                case '\r': sb.Append("\\r");  break;
                case '\t': sb.Append("\\t");  break;
                default:
                    if (c < 0x20) sb.Append($"\\u{(int)c:x4}");
                    else sb.Append(c);
                    break;
            }
        }
        sb.Append('"');
        return sb.ToString();
    }

    // ---------------------------------------------------------------------------
    // Core fingerprint (§5.6)
    // ---------------------------------------------------------------------------

    public static string ComputeCoreFingerprint(Dictionary<string, object?> coreFields)
    {
        var subset = new Dictionary<string, object?>();
        foreach (var key in Constants.CoreHashFields)
            if (coreFields.TryGetValue(key, out var val))
                subset[key] = val;
        return ComputeHash(CanonicalBytes(subset), "sha256");
    }

    public static byte[] CanonicalCoreBytes(Dictionary<string, object?> coreFields)
    {
        var subset = new Dictionary<string, object?>();
        foreach (var key in Constants.CoreHashFields)
            if (coreFields.TryGetValue(key, out var val))
                subset[key] = val;
        return CanonicalBytes(subset);
    }

    public static byte[] CanonicalManifestBytes(Dictionary<string, object?> manifest)
    {
        var m = DeepClone(manifest);
        if (m.TryGetValue("core", out var co) && co is Dictionary<string, object?> core)
            core["manifest_signature"] = null;
        return CanonicalBytes(m);
    }

    private static Dictionary<string, object?> DeepClone(Dictionary<string, object?> d)
    {
        var r = new Dictionary<string, object?>(d.Count);
        foreach (var kv in d)
            r[kv.Key] = kv.Value switch
            {
                Dictionary<string, object?> inner => DeepClone(inner),
                List<object?> list => list.Select(v => v is Dictionary<string, object?> id ? (object?)DeepClone(id) : v).ToList(),
                _ => kv.Value,
            };
        return r;
    }

    // ---------------------------------------------------------------------------
    // Ed25519 -- pure managed implementation (§5.5 / §5.8)
    // Private key = 32-byte seed. Public key = 32 bytes.
    // No external dependencies. Validated against OpenSSL/Python cryptography lib.
    // ---------------------------------------------------------------------------

    public static (byte[] Seed, byte[] PublicKey) GenerateKeyPair() =>
        Ed25519.GenerateKeyPair();

    public static string Sign(byte[] message, byte[] seed)
    {
        var sig = Ed25519.Sign(message, seed);
        return $"ed25519-{Convert.ToHexString(sig).ToLowerInvariant()}";
    }

    public static bool Verify(byte[] message, string sigStr, byte[] publicKey)
    {
        if (!Patterns.Signature().IsMatch(sigStr))
            throw new AIOSchemaException($"Invalid signature format: {sigStr}");
        var sigBytes = Convert.FromHexString(sigStr["ed25519-".Length..]);
        return Ed25519.Verify(message, sigBytes, publicKey);
    }
}
// -- end aioschema/dotnet v0.5.6 | AIOSchema spec v0.5.6 --
