using System.Security.Cryptography;


namespace CryptoEx.Ed;
/// <summary>
/// Internal enum for Ed Algorithms
/// </summary>
internal enum EdAlgorithm
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
    // Ed25519 OID
    public static readonly Oid OidEd25519 = new Oid("1.3.101.112");

    // Ed448 OID
    public static readonly Oid OidEd448 = new Oid("1.3.101.113");
}
