
using CryptoEx.Ed.EdDsa;
using CryptoEx.JWS;
using CryptoEx.JWS.ETSI;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace CryptoEx.Ed.JWS.ETSI;
public class ETSISignerEd : ETSISigner
{
    /// <summary>
    /// A constructor without a private key, used for verification
    /// </summary>
    public ETSISignerEd() : base()
    {
    }

    /// <summary>
    /// A constructiror with an private key - EdDSA, used for signing
    /// </summary>
    /// <param name="signer">The private key</param>
    /// <exception cref="ArgumentException">Invalid private key type</exception>
    public ETSISignerEd(EdDsa.EdDsa privateKey) : base(privateKey)
    {
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

    /// <summary>
    /// Do the actual signing
    /// </summary>
    /// <param name="calc">The signature input</param>
    /// <param name="PSSRSA">Is PSS for RSA</param>
    protected override void DoSignDetached(string calc, bool PSSRSA = false)
    {
        // Get the key
        EdDsa.EdDsa? edDsa = _signer as EdDsa.EdDsa;

        // Check
        if (edDsa == null) {
            // call parent
            base.DoSignDetached(calc, PSSRSA);
        } else {
            // Sign
            _signatures.Add(edDsa.Sign(Encoding.ASCII.GetBytes(calc)));
        }
    }

    /// <summary>
    /// Do asymetric sign
    /// </summary>
    /// <param name="PSSRSA">True to use PSSRSA</param>
    protected override void DoAsymetricSign(bool PSSRSA = false)
    {
        // Get the key
        EdDsa.EdDsa? edDsa = _signer as EdDsa.EdDsa;

        // Check
        if (edDsa == null) {
            // call parent
            base.DoAsymetricSign(PSSRSA);
        } else {
            // Sign
            _signatures.Add(edDsa.Sign(Encoding.ASCII.GetBytes($"{_header}.{_payload}")));
        }
    }

    /// <summary>
    /// Do verify the JWS
    /// </summary>
    /// <typeparam name="T">The type of the Header</typeparam>
    /// <param name="key">The Key</param>
    /// <param name="header">The header value</param>
    /// <param name="protectedS">Protected part of the payload</param>
    /// <param name="signature">The signatures</param>
    /// <returns>True / false if it is valid / invalid</returns>
    protected override bool DoVerify<T>(object key, T header, string protectedS, byte[] signature)
    {
        // Get the key
        EdDsa.EdDsa? edDsa = key as EdDsa.EdDsa;

        // Check
        if (edDsa == null) {
            // call parent
            return base.DoVerify(key, header, protectedS, signature);
        } else {
            // Sign
            return edDsa.Verify(Encoding.ASCII.GetBytes($"{protectedS}.{_payload}"), signature);
        }
    }
}
