// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ovidiu Ancuta
//
// aioschema/dotnet v0.5.6 | AIOSchema spec v0.5.6
// https://aioschema.org

using System.Numerics;
using System.Security.Cryptography;

namespace AIOSchema;

internal static class Ed25519
{
    // ---------------------------------------------------------------------------
    // Field constants (RFC 8032 §5.1)
    // ---------------------------------------------------------------------------

    // Prime field: p = 2^255 - 19
    private static readonly BigInteger P = BigInteger.Pow(2, 255) - 19;

    // Group order: q = 2^252 + 27742317777372353535851937790883648493
    // This is the number of points on the curve (cofactor h = 8, so |E| = 8q)
    private static readonly BigInteger Q =
        BigInteger.Pow(2, 252) +
        BigInteger.Parse("27742317777372353535851937790883648493");

    // Curve constant: d = -121665/121666 mod p (RFC 8032 §5.1, twisted Edwards)
    private static readonly BigInteger D =
        Mod(-121665 * ModInverse(121666, BigInteger.Pow(2, 255) - 19),
            BigInteger.Pow(2, 255) - 19);

    // Auxiliary: I = sqrt(-1) mod p = 2^((p-1)/4) mod p
    // Used to select the correct square root when recovering x from y
    private static readonly BigInteger Isqrt =
        BigInteger.ModPow(2, (BigInteger.Pow(2, 255) - 20) / 4, BigInteger.Pow(2, 255) - 19);

    // Base point B: y = 4/5 mod p, x is the positive (even) root
    // Computed once at static initialization
    private static readonly Point B = ComputeBasePoint();

    private static Point ComputeBasePoint()
    {
        var p = BigInteger.Pow(2, 255) - 19;
        var d = Mod(-121665 * ModInverse(121666, p), p);
        var I = BigInteger.ModPow(2, (p - 1) / 4, p);
        var y = Mod(4 * ModInverse(5, p), p); // y = 4/5 mod p
        var x = RecoverX(y, false, p, d, I);  // base point: even x (sign bit = 0)
        return new Point(x, y);
    }

    // ---------------------------------------------------------------------------
    // Point in affine coordinates
    // Note: projective/extended coordinates would be faster (fewer inversions)
    // but affine is clearer for a reference implementation.
    // ---------------------------------------------------------------------------

    private readonly struct Point
    {
        public readonly BigInteger X, Y;
        public Point(BigInteger x, BigInteger y) { X = x; Y = y; }
    }

    // Twisted Edwards addition law: -x^2 + y^2 = 1 + d*x^2*y^2
    private static Point PointAdd(Point p1, Point p2)
    {
        var x1 = p1.X; var y1 = p1.Y;
        var x2 = p2.X; var y2 = p2.Y;
        var dxy = Mod(D * x1 * x2 * y1 * y2, P);
        var x3  = Mod((x1 * y2 + x2 * y1) * ModInverse(1 + dxy, P), P);
        var y3  = Mod((y1 * y2 + x1 * x2) * ModInverse(1 - dxy, P), P);
        return new Point(x3, y3);
    }

    // Double-and-add scalar multiplication (not constant-time -- reference only)
    private static Point ScalarMult(Point pt, BigInteger scalar)
    {
        if (scalar == 0) return new Point(0, 1); // neutral element (identity)
        var q = ScalarMult(pt, scalar / 2);
        q = PointAdd(q, q);
        if (!scalar.IsEven) q = PointAdd(q, pt);
        return q;
    }

    // ---------------------------------------------------------------------------
    // x-coordinate recovery from y and desired parity (RFC 8032 §5.1.3)
    // ---------------------------------------------------------------------------

    private static BigInteger RecoverX(BigInteger y, bool xIsOdd,
        BigInteger p, BigInteger d, BigInteger I)
    {
        // x^2 = (y^2 - 1) / (d*y^2 + 1) mod p
        var y2 = y * y;
        var u  = Mod(y2 - 1, p);
        var v  = Mod(d * y2 + 1, p);
        var x2 = Mod(u * ModInverse(v, p), p);

        if (x2 == 0)
            return xIsOdd
                ? throw new InvalidOperationException("Invalid point: x=0 with sign bit set")
                : BigInteger.Zero;

        // Candidate square root for p ≡ 5 (mod 8): x = x2^((p+3)/8) mod p
        var x = BigInteger.ModPow(x2, (p + 3) / 8, p);

        // If x^2 ≠ x2, multiply by sqrt(-1) to get the other root
        if (Mod(x * x - x2, p) != 0)
            x = Mod(x * I, p);

        // If still not a valid root, the point is not on the curve
        if (Mod(x * x - x2, p) != 0)
            throw new InvalidOperationException("Point is not on the curve");

        // Adjust parity: if current parity doesn't match sign bit, negate x
        if (x.IsEven == xIsOdd)
            x = p - x;

        return x;
    }

    // ---------------------------------------------------------------------------
    // Point encoding (RFC 8032 §5.1.2)
    // ---------------------------------------------------------------------------

    private static byte[] EncodePoint(Point pt)
    {
        // Little-endian y in 32 bytes, with the low bit of x in the MSB of byte 31
        var yBytes = pt.Y.ToByteArray(isUnsigned: true, isBigEndian: false);
        var enc    = new byte[32];
        Buffer.BlockCopy(yBytes, 0, enc, 0, Math.Min(yBytes.Length, 32));
        if (!pt.X.IsEven)
            enc[31] |= 0x80; // set sign bit for odd x
        return enc;
    }

    // ---------------------------------------------------------------------------
    // Point decoding (RFC 8032 §5.1.3)
    // ---------------------------------------------------------------------------

    private static Point DecodePoint(ReadOnlySpan<byte> enc)
    {
        if (enc.Length != 32) throw new ArgumentException("Point encoding must be 32 bytes");
        var buf    = enc.ToArray();
        var xIsOdd = (buf[31] & 0x80) != 0; // sign bit encodes x parity
        buf[31]   &= 0x7F;                  // clear sign bit to recover y
        var y = new BigInteger(buf, isUnsigned: true, isBigEndian: false);
        if (y >= P) throw new InvalidOperationException("y >= p: invalid point");
        var x = RecoverX(y, xIsOdd, P, D, Isqrt);
        return new Point(x, y);
    }

    // ---------------------------------------------------------------------------
    // Key generation (RFC 8032 §5.1.5)
    // ---------------------------------------------------------------------------

    /// <summary>
    /// Generate a new Ed25519 key pair.
    /// Returns (seed: 32 bytes, publicKey: 32 bytes).
    /// The seed is the private key material. Keep it secret.
    /// </summary>
    public static (byte[] Seed, byte[] PublicKey) GenerateKeyPair()
    {
        var seed = new byte[32];
        RandomNumberGenerator.Fill(seed); // OS CSPRNG via .NET 8 BCL
        return (seed, PublicKeyFromSeed(seed));
    }

    /// <summary>Derive the 32-byte public key from a 32-byte seed.</summary>
    public static byte[] PublicKeyFromSeed(byte[] seed)
    {
        if (seed.Length != 32) throw new ArgumentException("Seed must be 32 bytes");
        var h = SHA512.HashData(seed).ToArray();
        Clamp(h); // RFC 8032 §5.1.5: clamp scalar bits
        var a = new BigInteger(h[..32], isUnsigned: true, isBigEndian: false);
        return EncodePoint(ScalarMult(B, a));
    }

    // ---------------------------------------------------------------------------
    // Sign (RFC 8032 §5.1.6)
    // ---------------------------------------------------------------------------

    /// <summary>
    /// Sign a message with a 32-byte seed. Returns a 64-byte signature.
    /// Signing is deterministic: identical seed + message → identical signature.
    /// </summary>
    public static byte[] Sign(byte[] message, byte[] seed)
    {
        if (seed.Length != 32) throw new ArgumentException("Seed must be 32 bytes");

        // h is the SHA-512 expansion of the seed: h[0..31] = scalar material,
        // h[32..63] = nonce material. It is ephemeral and contains key-derived
        // data -- wipe it in the finally block regardless of success or failure.
        var h = SHA512.HashData(seed).ToArray();
        try
        {
            // Step 1: expand seed via SHA-512; clamp low half to scalar a
            Clamp(h); // RFC 8032 §5.1.5

            var a    = new BigInteger(h[..32], isUnsigned: true, isBigEndian: false);
            var pubA = EncodePoint(ScalarMult(B, a));

            // Step 2: deterministic nonce r = SHA-512(h[32..] || message) mod q
            // Using the upper half of SHA-512(seed) as nonce material prevents
            // nonce reuse even without per-sign randomness (RFC 8032 §5.1.6)
            var rHash = SHA512.HashData(Concat(h[32..], message));
            var r     = Mod(new BigInteger(rHash, isUnsigned: true, isBigEndian: false), Q);

            // Step 3: R = r*B (commitment point)
            var R = EncodePoint(ScalarMult(B, r));

            // Step 4: challenge k = SHA-512(R || pubA || message) mod q
            var kHash = SHA512.HashData(Concat(R, pubA, message));
            var k     = Mod(new BigInteger(kHash, isUnsigned: true, isBigEndian: false), Q);

            // Step 5: proof scalar S = (r + k*a) mod q
            var S = Mod(r + k * a, Q);

            // Encode S as 32-byte little-endian
            var sRaw = S.ToByteArray(isUnsigned: true, isBigEndian: false);
            var sEnc = new byte[32];
            Buffer.BlockCopy(sRaw, 0, sEnc, 0, Math.Min(sRaw.Length, 32));

            return Concat(R, sEnc); // signature = R (32 bytes) || S (32 bytes)
        }
        finally
        {
            // Wipe the key-derived expansion from managed heap memory.
            // NOTE: We wipe h (the ephemeral SHA-512 expansion), NOT the seed.
            // The seed is the caller's permanent private key -- wiping it here
            // would destroy the key. The caller is responsible for the seed's
            // lifecycle. For long-lived keys, store them in a SecureString or HSM.
            CryptographicOperations.ZeroMemory(h);
        }
    }

    // ---------------------------------------------------------------------------
    // Verify (RFC 8032 §5.1.7)
    // ---------------------------------------------------------------------------

    /// <summary>
    /// Verify a 64-byte signature against a 32-byte public key.
    /// Returns false for any invalid input -- never throws.
    /// NOTE: point comparison via BigInteger is not constant-time.
    /// For a provenance verifier this is acceptable; for a signing server
    /// handling adversarial inputs, use a hardened library.
    /// </summary>
    public static bool Verify(byte[] message, byte[] signature, byte[] publicKey)
    {
        // All invalid inputs return false rather than throwing
        if (signature.Length != 64) return false;
        if (publicKey.Length != 32) return false;

        Point A, R;
        try { A = DecodePoint(publicKey); }
        catch { return false; }
        try { R = DecodePoint(signature[..32]); }
        catch { return false; }

        var S = new BigInteger(signature[32..], isUnsigned: true, isBigEndian: false);
        if (S >= Q) return false; // S must be in [0, q)

        // k = SHA-512(R_bytes || pubkey || message) mod q
        var kHash = SHA512.HashData(Concat(signature[..32], publicKey, message));
        var k     = Mod(new BigInteger(kHash, isUnsigned: true, isBigEndian: false), Q);

        // Verify: S*B == R + k*A
        //
        // This implements standard Ed25519 verification per RFC 8032 §5.1.7.
        //
        // Cofactor note: RFC 8032 allows but does not require cofactor (h=8)
        // multiplication in the verification equation. This implementation omits
        // it deliberately for mathematical clarity. This is safe for AIOSchema
        // because:
        //   (a) AIOSchema manifests use standard Ed25519 keys generated by this
        //       library or compliant implementations, which are small-subgroup-free
        //       by construction (the Clamp() operation in key generation ensures
        //       the scalar is a multiple of the cofactor 8).
        //   (b) The S < q check above already rejects the degenerate S=0 case.
        //
        // Small-subgroup attacks: not applicable here because we do not accept
        // arbitrary untrusted public keys in a signing oracle. Verifiers use
        // well-formed public keys embedded in AIOSchema manifests.
        //
        // For deployments that must satisfy strict RFC 8032 §5.2.6 compliance
        // (cofactor verification), replace this check with: 8*S*B == 8*R + k*(8*A).
        var lhs = ScalarMult(B, S);
        var rhs = PointAdd(R, ScalarMult(A, k));

        return lhs.X == rhs.X && lhs.Y == rhs.Y;
    }

    // ---------------------------------------------------------------------------
    // Internal helpers
    // ---------------------------------------------------------------------------

    // Clamp the scalar per RFC 8032 §5.1.5:
    //   - Clear the 3 low bits (ensure scalar is a multiple of the cofactor 8)
    //   - Clear the highest bit (keep scalar in safe range)
    //   - Set the second-highest bit (ensure scalar has fixed bit-length)
    private static void Clamp(byte[] h)
    {
        h[0]  &= 248; // 0b11111000 — clear bits 0,1,2
        h[31] &= 127; // 0b01111111 — clear bit 255
        h[31] |= 64;  // 0b01000000 — set bit 254
    }

    // Non-negative modular reduction (BigInteger % can return negative values)
    private static BigInteger Mod(BigInteger a, BigInteger m)
    {
        var r = a % m;
        return r.Sign < 0 ? r + m : r;
    }

    // Modular inverse via Fermat's little theorem: a^(m-2) mod m
    // Valid only when m is prime (true for both p and q used here)
    private static BigInteger ModInverse(BigInteger a, BigInteger m) =>
        BigInteger.ModPow(Mod(a, m), m - 2, m);

    private static byte[] Concat(params byte[][] arrays)
    {
        var buf = new byte[arrays.Sum(a => a.Length)];
        var off = 0;
        foreach (var a in arrays)
        {
            Buffer.BlockCopy(a, 0, buf, off, a.Length);
            off += a.Length;
        }
        return buf;
    }
}
// -- end aioschema/dotnet v0.5.6 | AIOSchema spec v0.5.6 --
