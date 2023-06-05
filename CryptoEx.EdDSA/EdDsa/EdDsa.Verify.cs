using CryptoEx.Ed;
using Org.BouncyCastle.Math.EC.Rfc8032;
using System.Security.Cryptography;

namespace CryptoEx.EdDSA;

/// <summary>
/// Digital signatures over the Edwards-curve Digital Signature Algorithm (EdDSA)
/// </summary>
public partial class EdDsa : EDAlgorithm
{
    /// <summary>
    /// Verify data in standard way
    /// Prefered
    /// </summary>
    /// <param name="data">The data</param>
    /// <param name="signature">The signature</param>
    /// <returns>True / false - if valid signature or not valid signature</returns>
    public virtual bool Verify(byte[] data, byte[] signature)
    {
        // result
        bool result;

        // What is the curve
        switch (_EdAlgorithm) {
            case EdAlgorithm.Ed25519:
                // Check verifier
                if (_PublicKey25519 == null) {
                    throw new CryptographicException("No public key");
                }

                // Veryfy
                result = _PublicKey25519.Verify(algorithm: _Context.Length > 0 ? Ed25519.Algorithm.Ed25519ctx : Ed25519.Algorithm.Ed25519,
                                                 ctx: _Context, msg: data, msgOff: 0, msgLen: data.Length, sig: signature, sigOff: 0);
                break;
            case EdAlgorithm.Ed448:
                // Check verifier
                if (_PublicKey448 == null) {
                    throw new CryptographicException("No public key");
                }

                // Veryfy
                result = _PublicKey448.Verify(algorithm: Ed448.Algorithm.Ed448, ctx: _Context, msg: data,
                                                msgOff: 0, msgLen: data.Length, sig: signature, sigOff: 0);
                break;
            default:
                throw new CryptographicException("Unknown algorithm");
        }

        // Return
        return result;
    }

    /// <summary>
    /// Verify data in prehashed way
    /// For legacy protocols. Not recomded to use as by RFC 8032
    /// </summary>
    /// <param name="data">The data</param>
    /// <param name="signature">The signature</param>
    /// <returns>True / false - if valid signature or not valid signature</returns>
    public virtual bool VerifyPh(byte[] data, byte[] signature)
    {
        // result
        bool result;

        // What is the curve
        switch (_EdAlgorithm) {
            case EdAlgorithm.Ed25519:
                // Check verifier
                if (_PublicKey25519 == null) {
                    throw new CryptographicException("No public key");
                }

                // Veryfy
                result = _PublicKey25519.Verify(algorithm: Ed25519.Algorithm.Ed25519ph,
                                                 ctx: _Context, msg: data, msgOff: 0, msgLen: data.Length, sig: signature, sigOff: 0);
                break;
            case EdAlgorithm.Ed448:
                // Check verifier
                if (_PublicKey448 == null) {
                    throw new CryptographicException("No public key");
                }

                // Veryfy
                result = _PublicKey448.Verify(algorithm: Ed448.Algorithm.Ed448ph, ctx: _Context, msg: data,
                                                msgOff: 0, msgLen: data.Length, sig: signature, sigOff: 0);
                break;
            default:
                throw new CryptographicException("Unknown algorithm");
        }

        // Return
        return result;
    }
}
