
using System.Security.Cryptography.X509Certificates;

namespace CryptoEx.Ed.EdDsa;

/// <summary>
/// A record to hold a X509Certificate2 and a EdDsa private key
/// </summary>
/// <param name="Certificate">The certificate</param>
/// <param name="PrivateKey">The private key</param>
public record class X509Certificate2Ed(X509Certificate2 Certificate, EdDsa? PrivateKey);

