
using CryptoEx.Ed.EdDsa;
using CryptoEx.JWS.ETSI;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace CryptoEx.Ed.JWS.ETSI;
public class ETSISignerEd : ETSISigner
{
    /// <summary>
    /// A constructor without a private key, used for verification
    /// </summary>
    public ETSISignerEd() : base()
    {
        // Set the crypto operations
        cryptoOperations = new JWSSignerEd.CryptoOperationsEd();
    }

    /// <summary>
    /// A constructiror with an private key - EdDSA, used for signing
    /// </summary>
    /// <param name="signer">The private key</param>
    /// <exception cref="ArgumentException">Invalid private key type</exception>
    public ETSISignerEd(EdDsa.EdDsa privateKey) : base(privateKey)
    {
        // Set the crypto operations
        cryptoOperations = new JWSSignerEd.CryptoOperationsEd();
        SetNewSigningKey(privateKey);
    }

    /// <summary>
    /// Tryies to retrieve the public key from the certificate
    /// </summary>
    /// <param name="x5c">The certificate</param>
    /// <returns>The public key</returns>
    protected override AsymmetricAlgorithm? GetPublicKeyFromCertificate(string? x5c)
    {
        if (x5c != null) {
            // Get the public key
            try {
                X509Certificate2 cert = X509CertificateLoader.LoadCertificate(Convert.FromBase64String(x5c));
                EdDsa.EdDsa? edDsa = cert.GetEdDsaPublicKey();
                if (edDsa != null) {
                    return edDsa;
                }
            } catch { }
        }

        // General return
        return base.GetPublicKeyFromCertificate(x5c);
    }
}
