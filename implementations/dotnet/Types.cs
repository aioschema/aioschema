// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ovidiu Ancuta
//
// aioschema/dotnet v0.5.6 | AIOSchema spec v0.5.6
// https://aioschema.org

using System.Security.Cryptography;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace AIOSchema;

// ---------------------------------------------------------------------------
// Spec constants
// ---------------------------------------------------------------------------

public static class Constants
{
    public const string SpecVersion = "0.5.6";

    public static readonly IReadOnlySet<string> SupportedVersions = new HashSet<string>
    {
        "0.1", "0.2", "0.3", "0.3.1", "0.4", "0.5", "0.5.1", "0.5.5", "0.5.6"
    };

    // Fields used to compute core_fingerprint (bootstrap: must NOT include core_fingerprint itself)
    public static readonly string[] CoreHashFields =
    {
        "asset_id",
        "schema_version",
        "creation_timestamp",
        "hash_original",
        "creator_id",
    };

    // Hash algorithm registry: token -> hex digest length
    public static readonly IReadOnlyDictionary<string, int> HashRegistry =
        new Dictionary<string, int>
        {
            ["sha256"]   = 64,
            ["sha3-256"] = 64,
            ["sha384"]   = 96,
        };

    public const string DefaultHashAlg = "sha256";

    public const int SoftBindingThresholdDefault = 5;
    public const int SoftBindingThresholdMax     = 10;

    public const string SidecarSuffix = ".aios.json";
}

// ---------------------------------------------------------------------------
// Validation patterns
// ---------------------------------------------------------------------------

public static partial class Patterns
{
    [GeneratedRegex(@"^(sha256|sha3-256)-[0-9a-f]{64}$|^sha384-[0-9a-f]{96}$")]
    public static partial Regex Hash();

    [GeneratedRegex(@"^ed25519-[0-9a-f]{128}$")]
    public static partial Regex Signature();

    [GeneratedRegex(@"^aios-anchor:[a-z0-9_-]+:[a-zA-Z0-9_-]+$")]
    public static partial Regex Anchor();

    [GeneratedRegex(@"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")]
    public static partial Regex Timestamp();

    [GeneratedRegex(@"^ed25519-fp-[0-9a-f]{32}$")]
    public static partial Regex AttributedCreatorId();
}

// ---------------------------------------------------------------------------
// Creator ID (§5.7)
// ---------------------------------------------------------------------------

public enum CreatorIdMode { Anonymous, Attributed }

public sealed class CreatorId
{
    public string Value        { get; }
    public CreatorIdMode Mode  { get; }

    private CreatorId(string value, CreatorIdMode mode) { Value = value; Mode = mode; }

    public static CreatorId Anonymous() =>
        new(Uuid7.NewString(), CreatorIdMode.Anonymous);

    public static CreatorId FromPublicKeyBytes(byte[] publicKeyRaw)
    {
        var hash  = SHA256.HashData(publicKeyRaw);
        var hexFp = Convert.ToHexString(hash).ToLowerInvariant()[..32];
        return new($"ed25519-fp-{hexFp}", CreatorIdMode.Attributed);
    }

    public static CreatorId Parse(string value) =>
        value.StartsWith("ed25519-fp-", StringComparison.Ordinal)
            ? new(value, CreatorIdMode.Attributed)
            : new(value, CreatorIdMode.Anonymous);

    public void Validate()
    {
        if (Mode == CreatorIdMode.Attributed)
        {
            if (!Patterns.AttributedCreatorId().IsMatch(Value))
                throw new AIOSchemaException(
                    $"Attributed creator_id must match 'ed25519-fp-<32hex>', got: {Value}");
        }
        else
        {
            if (!Guid.TryParse(Value, out _))
                throw new AIOSchemaException($"Invalid anonymous creator_id (not a UUID): {Value}");
        }
    }

    public override string ToString() => Value;
}

// ---------------------------------------------------------------------------
// Verification result (§10 step 14)
// ---------------------------------------------------------------------------

public sealed class VerificationResult
{
    public bool    Success                   { get; init; }
    public string  Message                   { get; init; } = "";
    public string? MatchType                 { get; init; }
    public bool    SignatureVerified         { get; init; }
    public bool    ManifestSignatureVerified { get; init; }
    public bool    AnchorChecked            { get; init; }
    public bool    AnchorVerified           { get; init; }
    public IReadOnlyList<string> Warnings   { get; init; } = Array.Empty<string>();

    public static VerificationResult Fail(string message, string? matchType = null) =>
        new() { Success = false, Message = message, MatchType = matchType };

    public string Summary()
    {
        var lines = new List<string>
        {
            $"{(Success ? "PASS" : "FAIL")}: {Message}",
        };
        if (MatchType is not null) lines.Add($"  Content match     : {MatchType}");
        lines.Add($"  Signature         : {(SignatureVerified ? "verified" : "not present / not checked")}");
        lines.Add($"  Manifest sig      : {(ManifestSignatureVerified ? "verified" : "not present / not checked")}");
        var anchor = AnchorVerified ? "verified" : AnchorChecked ? "checked (no match)" : "not checked";
        lines.Add($"  Anchor            : {anchor}");
        foreach (var w in Warnings) lines.Add($"  WARNING: {w}");
        return string.Join(Environment.NewLine, lines);
    }
}

// ---------------------------------------------------------------------------
// Core block (§5)
// ---------------------------------------------------------------------------

public sealed class CoreBlock
{
    public string  AssetId               { get; set; } = "";
    public string  SchemaVersion         { get; set; } = Constants.SpecVersion;
    public string  CreationTimestamp     { get; set; } = "";
    public object  HashOriginal          { get; set; } = "";  // string or List<string>
    public string  CreatorId             { get; set; } = "";
    public string? CoreFingerprint       { get; set; }
    public string? HashSchemaBlock       { get; set; }        // deprecated alias
    public string? Signature             { get; set; }
    public string? ManifestSignature     { get; set; }
    public string? AnchorReference       { get; set; }
    public string? PreviousVersionAnchor { get; set; }

    public IReadOnlyList<string> HashOriginalList() => HashOriginal switch
    {
        string s                 => new[] { s },
        List<string> l           => l,
        IEnumerable<string> en   => en.ToList(),
        JsonElement { ValueKind: JsonValueKind.Array }  je =>
            je.EnumerateArray().Select(e => e.GetString()!).ToList(),
        JsonElement { ValueKind: JsonValueKind.String } je =>
            new[] { je.GetString()! },
        _ => Array.Empty<string>(),
    };
}

// ---------------------------------------------------------------------------
// Manifest (§4)
// ---------------------------------------------------------------------------

public sealed class AIOSManifest
{
    public CoreBlock                     Core       { get; set; } = new();
    public Dictionary<string, object?>   Extensions { get; set; } = new();
}

// ---------------------------------------------------------------------------
// Anchor resolver (§9.2)
// ---------------------------------------------------------------------------

public delegate Dictionary<string, string>? AnchorResolver(string anchorRef);

// ---------------------------------------------------------------------------
// Exceptions
// ---------------------------------------------------------------------------

public sealed class AIOSchemaException : Exception
{
    public AIOSchemaException(string message) : base(message) { }
}

public sealed class AnchorVerificationException : Exception
{
    public AnchorVerificationException(string message) : base(message) { }
}
// -- end aioschema/dotnet v0.5.6 | AIOSchema spec v0.5.6 --
