using System.Security.Cryptography.X509Certificates;

namespace CryptoEx.Ed.EdDH;

/// <summary>
/// Extentions for EdDH and X509Certificate2
/// </summary>
public static class EdDHExtentions
{
    /// <summary>
    /// Extention for X509Certificate2 to get EdDH private key
    /// </summary>
    /// <param name="cert">The certificate with a private key</param>
    /// <returns>The EdDH Algorithm</returns>
    public static EdDH? GetEdDHPrivateKey(this X509Certificate2Ed cert)
    {
        return cert.PrivateKey as EdDH;
    }

    /// <summary>
    /// Extention for X509Certificate2 to get EdDH public key
    /// </summary>
    /// <param name="cert">The certificate with a public key</param>
    /// <returns>The EdDH Algorithm</returns>
    public static EdDH? GetEdDHPublicKey(this X509Certificate2 cert)
    {
        // Create parameters
        EDParameters eDParameters = new();

        // Check OID
        switch (cert.PublicKey.Oid.Value) {
            case EdConstants.X25519_Oid:
                eDParameters.X = cert.PublicKey.EncodedKeyValue.RawData;
                eDParameters.Crv = EdConstants.OidX25519;
                return EdDH.Create(eDParameters);
            case EdConstants.X448_Oid:
                eDParameters.X = cert.PublicKey.EncodedKeyValue.RawData;
                eDParameters.Crv = EdConstants.OidX448;
                return EdDH.Create(eDParameters);
            default:
                return null;
        }
    }
}
