
using BenchmarkDotNet.Attributes;
using CryptoEx.Ed.EdDH;
using CryptoEx.Utils;
using System.Security.Cryptography;

namespace CryptoEx.Benchmark.Basic;

[MemoryDiagnoser]
public class EdDHTests
{
    [Benchmark]
    public void GetBytes_X25519_SHA256()
    {
        // Create some Keys
        using (EdDH alice = EdDH.Create()) 
        using (EdDH bob = EdDH.Create())
        {
            Span<byte> aliceBuffer = stackalloc byte[32];
            Span<byte> BobBuffer = stackalloc byte[32];

            // Generate
            _ = alice.GenerateBytes(bob, SHA256.Create(), aliceBuffer);
            _ = bob.GenerateBytes(alice, SHA256.Create(), BobBuffer);
        }
    }

    [Benchmark]
    public void GetBytes_X25519_SHA512()
    {
        // Create some Keys
        using (EdDH alice = EdDH.Create())
        using (EdDH bob = EdDH.Create()) {
            Span<byte> aliceBuffer = stackalloc byte[64];
            Span<byte> BobBuffer = stackalloc byte[64];

            // Generate
            _ = alice.GenerateBytes(bob, SHA512.Create(), aliceBuffer);
            _ = bob.GenerateBytes(alice, SHA512.Create(), BobBuffer);
        }
    }

    [Benchmark]
    public void GetBytes_X448_SHA256()
    {
        // Create some Keys
        using (EdDH alice = EdDH.Create(Ed.EdAlgorithm.X448))
        using (EdDH bob = EdDH.Create(Ed.EdAlgorithm.X448)) {
            Span<byte> aliceBuffer = stackalloc byte[32];
            Span<byte> BobBuffer = stackalloc byte[32];

            // Generate
            _ = alice.GenerateBytes(bob, SHA256.Create(), aliceBuffer);
            _ = bob.GenerateBytes(alice, SHA256.Create(), BobBuffer);
        }
    }

    [Benchmark]
    public void GetBytes_X448_SHA512()
    {
        // Create some Keys
        using (EdDH alice = EdDH.Create(Ed.EdAlgorithm.X448))
        using (EdDH bob = EdDH.Create(Ed.EdAlgorithm.X448)) {
            Span<byte> aliceBuffer = stackalloc byte[64];
            Span<byte> BobBuffer = stackalloc byte[64];

            // Generate
            _ = alice.GenerateBytes(bob, SHA512.Create(), aliceBuffer);
            _ = bob.GenerateBytes(alice, SHA512.Create(), BobBuffer);
        }
    }

    [Benchmark]
    public void GetBytes_KDM_X25519_SHA256()
    {
        // Create some Keys
        using (EdDH alice = EdDH.Create())
        using (EdDH bob = EdDH.Create()) {
            Span<byte> aliceBuffer = stackalloc byte[44];
            Span<byte> BobBuffer = stackalloc byte[44];

            // Generate
            _ = alice.GenerateBytesKDM(bob, SHA256.Create(), Array.Empty<byte>(), aliceBuffer);
            _ = bob.GenerateBytesKDM(alice, SHA256.Create(), Array.Empty<byte>(), BobBuffer);
        }
    }

    [Benchmark]
    public void GetBytes_KDM_X25519_SHA512()
    {
        // Create some Keys
        using (EdDH alice = EdDH.Create())
        using (EdDH bob = EdDH.Create()) {
            Span<byte> aliceBuffer = stackalloc byte[76];
            Span<byte> BobBuffer = stackalloc byte[76];

            // Generate
            _ = alice.GenerateBytesKDM(bob, SHA512.Create(), Array.Empty<byte>(), aliceBuffer);
            _ = bob.GenerateBytesKDM(alice, SHA512.Create(), Array.Empty<byte>(), BobBuffer);
        }
    }

    [Benchmark]
    public void GetBytes_KDM_X448_SHA256()
    {
        // Create some Keys
        using (EdDH alice = EdDH.Create(Ed.EdAlgorithm.X448))
        using (EdDH bob = EdDH.Create(Ed.EdAlgorithm.X448)) {
            Span<byte> aliceBuffer = stackalloc byte[44];
            Span<byte> BobBuffer = stackalloc byte[44];

            // Generate
            _ = alice.GenerateBytesKDM(bob, SHA256.Create(), Array.Empty<byte>(), aliceBuffer);
            _ = bob.GenerateBytesKDM(alice, SHA256.Create(), Array.Empty<byte>(), BobBuffer);
        }
    }

    [Benchmark]
    public void GetBytes_KDM_X448_SHA512()
    {
        // Create some Keys
        using (EdDH alice = EdDH.Create(Ed.EdAlgorithm.X448))
        using (EdDH bob = EdDH.Create(Ed.EdAlgorithm.X448)) {
            Span<byte> aliceBuffer = stackalloc byte[76];
            Span<byte> BobBuffer = stackalloc byte[76];

            // Generate
            _ = alice.GenerateBytesKDM(bob, SHA512.Create(), Array.Empty<byte>(), aliceBuffer);
            _ = bob.GenerateBytesKDM(alice, SHA512.Create(), Array.Empty<byte>(), BobBuffer);
        }
    }
}
