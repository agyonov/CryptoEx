using CryptoEx.JWS;
using System.Security.Cryptography;

namespace CryptoEx.Ed.JWS;
public class JWSSignerEd : JWSSigner
{
    /// <summary>
    /// A constructor without a private key, used for verification
    /// </summary>
    public JWSSignerEd() : base()
    {
        // Set the crypto operations
        cryptoOperations = new CryptoOperationsEd();
    }

    /// <summary>
    /// A constructiror with an private key - EcDsa, used for signing
    /// </summary>
    /// <param name="signer">The private key</param>
    /// <exception cref="ArgumentException">Invalid private key type</exception>
    public JWSSignerEd(EdDsa.EdDsa privateKey) : base(privateKey)
    {
        // Set the crypto operations
        cryptoOperations = new CryptoOperationsEd();
        SetNewSigningKey(privateKey);
    }

    /// <summary>
    /// Do asymetric sign and verify in extensible way
    /// </summary>
    public class CryptoOperationsEd : CryptoOperations
    {
        /// <summary>
        /// Do asymetric sign
        /// </summary>
        /// <param name="signer">The signer - private key</param>
        /// <param name="data">Data to sign</param>
        /// <param name="hashName">Hash name to use</param>
        /// <param name="PSSRSA">For RSA - to use PSS or not</param>
        /// <returns>The signature</returns>
        public override byte[] DoAsymetricSign(AsymmetricAlgorithm signer, byte[] data, HashAlgorithmName hashName, bool PSSRSA = false)
        {
            // Get the key
            EdDsa.EdDsa? edDsa = signer as EdDsa.EdDsa;

            // Check
            if (edDsa == null) {
                // call parent
                return base.DoAsymetricSign(signer, data, hashName, PSSRSA);
            } else {
                // Sign
                return edDsa.Sign(data);
            }
        }

        /// <summary>
        /// Do verify the JWS
        /// </summary>
        /// <typeparam name="T">The type of the Header</typeparam>
        /// <param name="key">The Key</param>
        /// <param name="header">The header value</param>
        /// <param name="data">The data to verify</param>
        /// <param name="signature">The signatures</param>
        /// <returns>True / false if it is valid / invalid</returns>
        public override bool DoVerify<T>(object key, T header, byte[] data, byte[] signature)
        {
            // Get the key
            EdDsa.EdDsa? edDsa = key as EdDsa.EdDsa;

            // Check
            if (edDsa == null) {
                // call parent
                return base.DoVerify(key, header, data, signature);
            } else {
                // Sign
                return edDsa.Verify(data, signature);
            }
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
        public override (string, HashAlgorithmName) SetNewSigningKey(AsymmetricAlgorithm signer, HashAlgorithmName? hashAlgorithm = null, bool useRSAPSS = false)
        {
            // Check if the key is not EdDsa
            if (signer is not EdDsa.EdDsa) {
                // If it is not, call parent
                return base.SetNewSigningKey(signer, hashAlgorithm, useRSAPSS);
            }

            // return the algorithm
            return (JWSConstants.EdDSA, hashAlgorithm != null ? hashAlgorithm.Value : HashAlgorithmName.SHA512);
        }
    }
}
