// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ovidiu Ancuta
//
// aioschema/dotnet v0.5.6 | AIOSchema spec v0.5.6
// https://aioschema.org

namespace AIOSchema;

internal static class Uuid7
{
    private static long   _lastMs;
    private static ushort _seq;
    private static readonly object _lock = new();

    public static string NewString()
    {
        Span<byte> b = stackalloc byte[16];
        lock (_lock)
        {
            var ms = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            if (ms == _lastMs)
            {
                _seq = (ushort)((_seq + 1) & 0x0FFF);
            }
            else
            {
                Span<byte> seed = stackalloc byte[2];
                System.Security.Cryptography.RandomNumberGenerator.Fill(seed);
                _seq   = (ushort)(((seed[0] << 8) | seed[1]) & 0x0FFF);
                _lastMs = ms;
            }

            // 48-bit timestamp
            b[0] = (byte)(ms >> 40);
            b[1] = (byte)(ms >> 32);
            b[2] = (byte)(ms >> 24);
            b[3] = (byte)(ms >> 16);
            b[4] = (byte)(ms >>  8);
            b[5] = (byte)(ms);

            // Version 7 + 12-bit seq
            b[6] = (byte)(0x70 | (_seq >> 8));
            b[7] = (byte)(_seq & 0xFF);

            // Variant + 62 random bits
            Span<byte> rand = stackalloc byte[8];
            System.Security.Cryptography.RandomNumberGenerator.Fill(rand);
            rand[0] = (byte)(0x80 | (rand[0] & 0x3F));
            rand.CopyTo(b[8..]);
        }

        return new Guid(b, bigEndian: true).ToString("D");
    }
}
// -- end aioschema/dotnet v0.5.6 | AIOSchema spec v0.5.6 --
