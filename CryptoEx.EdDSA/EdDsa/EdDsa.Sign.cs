using CryptoEx.Ed;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math.EC.Rfc8032;
using System.Security.Cryptography;

namespace CryptoEx.EdDSA;

/// <summary>
/// Digital signatures over the Edwards-curve Digital Signature Algorithm (EdDSA)
/// </summary>
public partial class EdDsa : EDAlgorithm
{
    /// <summary>
    /// Sign data in standard way
    /// Recomended
    /// </summary>
    /// <param name="data">The data to sign</param>
    /// <returns>The signature</returns>
    public virtual byte[] Sign(byte[] data)
    {
        byte[] signature;

        // What is the curve
        switch (_EdAlgorithm) {
            case EdAlgorithm.Ed25519:
                // Check signer
                if (_PrivateKey25519 == null) {
                    throw new CryptographicException("No private key");
                }

                // Sign
                signature = new byte[Ed25519PrivateKeyParameters.SignatureSize];
                _PrivateKey25519.Sign(algorithm: _Context.Length > 0 ? Ed25519.Algorithm.Ed25519ctx : Ed25519.Algorithm.Ed25519,
                                     ctx: _Context, msg: data, msgOff: 0, msgLen: data.Length, sig: signature, sigOff: 0);

                break;
            case EdAlgorithm.Ed448:
                // Check signer
                signature = new byte[Ed448PrivateKeyParameters.SignatureSize];
                if (_PrivateKey448 == null) {
                    throw new CryptographicException("No private key");
                }

                // Sign
                _PrivateKey448.Sign(algorithm: Ed448.Algorithm.Ed448, ctx: _Context, msg: data,
                                       msgOff: 0, msgLen: data.Length, sig: signature, sigOff: 0);
                break;
            default:
                throw new CryptographicException("Unknown algorithm");
        }

        // Sign
        return signature;
    }

    /// <summary>
    /// Sign data in prehash way
    /// For legacy protocols. Not recomded to use as by RFC 8032
    /// </summary>
    /// <param name="data">The data to sign</param>
    /// <returns>The signature</returns>
    public virtual byte[] SignPh(byte[] data)
    {
        byte[] signature;

        // What is the curve
        switch (_EdAlgorithm) {
            case EdAlgorithm.Ed25519:
                // Check signer
                if (_PrivateKey25519 == null) {
                    throw new CryptographicException("No private key");
                }

                // Sign
                signature = new byte[Ed25519PrivateKeyParameters.SignatureSize];
                _PrivateKey25519.Sign(algorithm: Ed25519.Algorithm.Ed25519ph, ctx: _Context, msg: data,
                    msgOff: 0, msgLen: data.Length, sig: signature, sigOff: 0);

                break;
            case EdAlgorithm.Ed448:
                // Check signer
                signature = new byte[Ed448PrivateKeyParameters.SignatureSize];
                if (_PrivateKey448 == null) {
                    throw new CryptographicException("No private key");
                }

                // Sign
                _PrivateKey448.Sign(algorithm: Ed448.Algorithm.Ed448ph, ctx: _Context, msg: data,
                                       msgOff: 0, msgLen: data.Length, sig: signature, sigOff: 0);
                break;
            default:
                throw new CryptographicException("Unknown algorithm");
        }

        // Sign
        return signature;
    }
}
