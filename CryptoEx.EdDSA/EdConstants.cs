using System.Security.Cryptography;


namespace CryptoEx.Ed;
/// <summary>
/// Enum for Ed Algorithms
/// </summary>
public enum EdAlgorithm
{
    Ed25519, // Signature Ed25519
    Ed448, // Signature Ed448
    X25519, // Key exchange Curve25519
    X448 // Key exchange Curve448
}

/// <summary>
/// Some constants of EdDSA and EdDH
/// </summary>
public static class EdConstants
{
    public const string X25519_Oid = "1.3.101.110";

    public const string X448_Oid = "1.3.101.111";

    public const string Ed25519_Oid = "1.3.101.112";

    public const string Ed448_Oid = "1.3.101.113";

    // X25519 OID
    public static readonly Oid OidX25519 = new(X25519_Oid);

    // X448 OID
    public static readonly Oid OidX448 = new(X448_Oid);

    // Ed25519 OID
    public static readonly Oid OidEd25519 = new(Ed25519_Oid);

    // Ed448 OID
    public static readonly Oid OidEd448 = new(Ed448_Oid);
}
