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
        return cert.PrivateKey;
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

    /// <summary>
    /// Try to get a certificate from a stream.
    /// Read only the public key.
    /// </summary>
    /// <param name="stream">The stream with certificate</param>
    /// <returns>X509Certificate2 with public key</returns>
    public static X509Certificate2? LoadEdCertificateFromCrt(this Stream stream)
    {
        try {
            // Get reader
            using (BinaryReader reader = new(stream)) {
                // Get certificate
                byte[] data = reader.ReadBytes((int)stream.Length);
                // Return certificate
                return new X509Certificate2(data);
            }
        } catch {
            // Ignore
            return null;
        }
    }

    /// <summary>
    /// Try to get a certificate from a stream.
    /// The PFX, P12. The read of certificate and the private key.
    /// </summary>
    /// <param name="stream">The stream with certifacte and key - a PFX</param>
    /// <param name="password">The password for the PFX/P12 - may be empty string</param>
    /// <returns>X509Certificate2 with private key</returns>
    public static X509Certificate2Ed[] LoadEdCertificatesFromPfx(this Stream stream, string password)
    {
        // Result
        List<X509Certificate2Ed> res = new();

        try {
            // Create store
            Pkcs12Store store = new Pkcs12StoreBuilder().Build();

            // Load store
            store.Load(stream, password.ToArray());

            // Cycle all aliases
            foreach (var alias in store.Aliases) {
                // Get certificate and key
                X509CertificateEntry cert = store.GetCertificate(alias);
                AsymmetricKeyEntry? key = store.GetKey(alias);
                X509Certificate2 cert2 = new(cert.Certificate.GetEncoded());
                EdDsa? edDsa = null;

                // Check key
                if (key != null && key.Key.IsPrivate) {
                    // Ckeck key type
                    Ed25519PrivateKeyParameters? edKey = key.Key as Ed25519PrivateKeyParameters;
                    if (edKey != null) {
                        // Create some EdDsa private key
                        EDParameters edParams = new();
                        edParams.D = edKey.GetEncoded();
                        edParams.X = edKey.GeneratePublicKey().GetEncoded();
                        edParams.Crv = EdConstants.OidEd25519;

                        // Create Key
                        edDsa = EdDsa.Create(edParams);
                    } else {
                        Ed448PrivateKeyParameters? ed448Key = key.Key as Ed448PrivateKeyParameters;
                        if (ed448Key != null) {
                            // Create some EdDsa private key
                            EDParameters edParams = new();
                            edParams.D = ed448Key.GetEncoded();
                            edParams.X = ed448Key.GeneratePublicKey().GetEncoded();
                            edParams.Crv = EdConstants.OidEd448;

                            // Create Key
                            edDsa = EdDsa.Create(edParams);

                        }
                    }

                    // Create certificate
                    if (cert2 != null) {
                        res.Add(new X509Certificate2Ed(cert2, edDsa));
                    }
                }
            }

            // Return
            return res.ToArray();
        } catch {
            // Ignore
            return Array.Empty<X509Certificate2Ed>();
        }
    }
}
