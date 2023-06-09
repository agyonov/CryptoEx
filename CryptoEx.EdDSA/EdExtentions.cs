using CryptoEx.Ed.EdDsa;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math.EC.Rfc8032;
using Org.BouncyCastle.Pkcs;
using System.Security.Cryptography.X509Certificates;

namespace CryptoEx.Ed;
public static class EdExtentions
{
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
                EDAlgorithm? ed = null;

                // Check key
                if (key != null && key.Key.IsPrivate) {
                    EDParameters edParams = new();

                    // Ckeck key type
                    switch (key.Key) {
                        case Ed25519PrivateKeyParameters ed25519:
                            // Create some EdDsa private key
                            edParams.D = ed25519.GetEncoded();
                            edParams.X = ed25519.GeneratePublicKey().GetEncoded();
                            edParams.Crv = EdConstants.OidEd25519;

                            // Create Key
                            ed = EdDsa.EdDsa.Create(edParams);
                            break;
                        case Ed448PrivateKeyParameters ed448:
                            // Create some EdDsa private key
                            edParams.D = ed448.GetEncoded();
                            edParams.X = ed448.GeneratePublicKey().GetEncoded();
                            edParams.Crv = EdConstants.OidEd448;

                            // Create Key
                            ed = EdDsa.EdDsa.Create(edParams);
                            break;
                        case X25519PrivateKeyParameters x25519:
                            // Create some EdDH private key
                            edParams.D = x25519.GetEncoded();
                            edParams.X = x25519.GeneratePublicKey().GetEncoded();
                            edParams.Crv = EdConstants.OidX25519;

                            // Create Key
                            ed = EdDH.EdDH.Create(edParams);
                            break;
                        case X448PrivateKeyParameters x448:
                            // Create some EdDH private key
                            edParams.D = x448.GetEncoded();
                            edParams.X = x448.GeneratePublicKey().GetEncoded();
                            edParams.Crv = EdConstants.OidX448;

                            // Create Key
                            ed = EdDH.EdDH.Create(edParams);
                            break;
                    }

                    // Create certificate
                    if (cert2 != null) {
                        res.Add(new X509Certificate2Ed(cert2, ed));
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
