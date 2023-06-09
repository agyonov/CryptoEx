using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Pkcs;
using System.Security.Cryptography.X509Certificates;

namespace CryptoEx.Ed.EdDsa;

/// <summary>
/// Extentions for EdDSA and X509Certificate2
/// </summary>
public static class EdDsaExtentions
{
    /// <summary>
    /// Extention for X509Certificate2 to get EdDSA private key
    /// </summary>
    /// <param name="cert">The certificate with a private key</param>
    /// <returns>The EdDsa Algorithm</returns>
    public static EdDsa? GetEdDsaPrivateKey(this X509Certificate2Ed cert)
    {
        return cert.PrivateKey as EdDsa;
    }

    /// <summary>
    /// Extention for X509Certificate2 to get EdDSA public key
    /// </summary>
    /// <param name="cert">The certificate with a public key</param>
    /// <returns>The EdDsa Algorithm</returns>
    public static EdDsa? GetEdDsaPublicKey(this X509Certificate2 cert)
    {
        // Create parameters
        EDParameters eDParameters = new();

        // Check OID
        switch (cert.PublicKey.Oid.Value) {
            case EdConstants.Ed25519_Oid:
                eDParameters.X = cert.PublicKey.EncodedKeyValue.RawData;
                eDParameters.Crv = EdConstants.OidEd25519;
                return EdDsa.Create(eDParameters);
            case EdConstants.Ed448_Oid:
                eDParameters.X = cert.PublicKey.EncodedKeyValue.RawData;
                eDParameters.Crv = EdConstants.OidEd448; ;
                return EdDsa.Create(eDParameters);
            default:
                return null;
        }
    }
}
