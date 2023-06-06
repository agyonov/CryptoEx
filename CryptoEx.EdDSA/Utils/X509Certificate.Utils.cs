using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Pkcs;
using System.Security.Cryptography.X509Certificates;

namespace CryptoEx.Ed.Utils;

public static class X509CertificateUtils
{
    /// <summary>
    /// Try to get a certificate from a stream.
    /// Read only the public key.
    /// </summary>
    /// <param name="stream">The stream with certificate</param>
    /// <returns>X509Certificate2 with public key</returns>
    public static X509Certificate2? GetEdCertificate(Stream stream)
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
    public static X509Certificate2?[] GetEdCertificates(Stream stream, string password)
    {
        // Result
        List<X509Certificate2?> res = new();

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
#pragma warning disable SYSLIB0028 // Type or member is obsolete
                        cert2.PrivateKey = EdDsa.EdDsa.Create(edParams);
#pragma warning restore SYSLIB0028 // Type or member is obsolete
                    } else {
                        Ed448PrivateKeyParameters? ed448Key = key.Key as Ed448PrivateKeyParameters;
                        if (ed448Key != null) {
                            // Create some EdDsa private key
                            EDParameters edParams = new();
                            edParams.D = ed448Key.GetEncoded();
                            edParams.X = ed448Key.GeneratePublicKey().GetEncoded();
                            edParams.Crv = EdConstants.OidEd448;

                            // Create Key
#pragma warning disable SYSLIB0028 // Type or member is obsolete
                            cert2.PrivateKey = EdDsa.EdDsa.Create(edParams);
#pragma warning restore SYSLIB0028 // Type or member is obsolete
                        }
                    }

                    // Create certificate
#pragma warning disable SYSLIB0028 // Type or member is obsolete
                    if (cert2.PrivateKey != null) {
                        res.Add(cert2);
                    }
#pragma warning restore SYSLIB0028 // Type or member is obsolete
                }
            }

            // Return
            return res.ToArray();
        } catch {
            // Ignore
            return Array.Empty<X509Certificate2?>();
        }
    }
}
