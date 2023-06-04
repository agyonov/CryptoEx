
using System.Security.Cryptography;

namespace CryptoEx.EdDSA;

public record class EDParameters
{
    /// <summary>
    /// Curve - Ed25519 or Ed448
    /// </summary>
    public Oid Crv { get; set; } = default!;

    /// <summary>
    /// Public part, X coordinate on curve
    /// </summary>
    public byte[] X { get; set; } = Array.Empty<byte>();

    /// <summary>
    /// Private key Ed
    /// </summary>
    public byte[]? D { get; set; }
}
