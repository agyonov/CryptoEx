using CryptoEx.Ed;
using Org.BouncyCastle.Crypto.Parameters;

namespace CryptoEx.EdDSA;

/// <summary>
/// Digital signatures over the Edwards-curve Digital Signature Algorithm (EdDSA)
/// </summary>
public partial class EdDsa : EDAlgorithm
{
    /// <summary>
    /// Verify signature
    /// </summary>
    public bool Verify(ReadOnlySpan<byte> data, byte[] signature)
    {
        // Check if we have a signer
        if (_Signer == null) {
            return false;
        }

        // What is the curve
        switch (_EdAlgorithm) {
            case EdAlgorithm.Ed25519:
                // Init signer
                _Signer.Init(false, _PublicKey25519);
                break;
            case EdAlgorithm.Ed448:
                // Init signer
                _Signer.Init(false, _PublicKey448);
                break;
        }

        // Sign
        _Signer.BlockUpdate(data);
        return _Signer.VerifySignature(signature);
    }
}
