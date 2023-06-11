
using CryptoEx.Ed.EdDsa;
using CryptoEx.JWS;
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
    }

    /// <summary>
    /// Change the signing key. This is useful for example when you want to sign with a new key.
    /// When you want to add a new signature, you set it with this method and then can use 'Sign' method to actually sign with
    /// the newly stetted key.
    /// </summary>
    /// <param name="signer">The private key</param>
    /// <param name="hashAlgorithm">Hash algorithm, mainly for RSA</param>
    /// <param name="useRSAPSS">In case of RSA, whether to use RSA-PSS</param>
    /// <exception cref="ArgumentException">Invalid private key type</exception>
    public override void SetNewSigningKey(AsymmetricAlgorithm signer, HashAlgorithmName? hashAlgorithm = null, bool useRSAPSS = false)
    {
        // Check if the key is not EdDsa
        if (signer is not EdDsa.EdDsa) {
            // If it is not, call parent
            base.SetNewSigningKey(signer, hashAlgorithm, useRSAPSS);
        }

        // Store
        _signer = signer;
        _signerHmac = null;
        _algorithmNameJws = JWSConstants.EdDSA;
        _algorithmName = hashAlgorithm != null ? hashAlgorithm.Value : HashAlgorithmName.SHA512;
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
                X509Certificate2 cert = new(Convert.FromBase64String(x5c));
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
