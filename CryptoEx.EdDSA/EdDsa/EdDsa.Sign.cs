using CryptoEx.Ed;
using Org.BouncyCastle.Crypto.Parameters;
using System.Security.Cryptography;

namespace CryptoEx.EdDSA;

/// <summary>
/// Digital signatures over the Edwards-curve Digital Signature Algorithm (EdDSA)
/// </summary>
public partial class EdDsa : EDAlgorithm
{

    /// <summary>
    /// Sign data
    /// </summary>
    public byte[] Sign(ReadOnlySpan<byte> data)
    {
        // Check if we have a signer
        if (_Signer == null) {
            return Array.Empty<byte>();
        }

        // What is the curve
        switch (_EdAlgorithm) {
            case EdAlgorithm.Ed25519:
                // Check signer
                if (_PrivateKey25519 == null) { 
                    throw new CryptographicException("No private key");
                } 
                _Signer.Init(true, _PrivateKey25519);
                break;
            case EdAlgorithm.Ed448:
                // Check signer
                if (_PrivateKey448 == null) {
                    throw new CryptographicException("No private key");
                } 
                _Signer.Init(true, _PrivateKey448);
                break;
        }

        // Sign
        _Signer.BlockUpdate(data);
        return _Signer.GenerateSignature();
    }


}
