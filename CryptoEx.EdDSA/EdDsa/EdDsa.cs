

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
    /// When overridden in a derived class, exports the parameters for the algorithm.
    /// </summary>
    /// <param name="includePrivateParameters">
    ///   <see langword="true" /> to include private parameters, otherwise, <see langword="false" />.
    /// </param>
    /// <returns>The exported parameters.</returns>
    public override EDParameters ExportParameters(bool includePrivateParameters)
    {
        // create return
        EDParameters eDParameters = new();

        // Check what is it
        switch (_EdAlgorithm) {
            case EdAlgorithm.Ed25519:
                eDParameters.Crv = new Oid(EdConstants.Ed25519_Oid);
                eDParameters.X = _PublicKey25519 != null ? _PublicKey25519.GetEncoded() : Array.Empty<byte>();
                if (includePrivateParameters) {
                    eDParameters.D = _PrivateKey25519 != null ? _PrivateKey25519.GetEncoded() : Array.Empty<byte>();
                }
                break;
            case EdAlgorithm.Ed448:
                eDParameters.Crv = new Oid(EdConstants.Ed448_Oid);
                eDParameters.X = _PublicKey448 != null ? _PublicKey448.GetEncoded() : Array.Empty<byte>();
                if (includePrivateParameters) {
                    eDParameters.D = _PrivateKey448 != null ? _PrivateKey448.GetEncoded() : Array.Empty<byte>();
                }
                break;
            default:
                throw new NotSupportedException($"Curve {_EdAlgorithm} not supported for Dsa");
        }

        // Clear some
        ClearData();

        // Return
        return eDParameters;
    }

    /// <summary>
    /// When overridden in a derived class, imports the specified <see cref="ECParameters" />.
    /// </summary>
    /// <param name="parameters">The curve parameters.</param>
    public override void ImportParameters(EDParameters parameters)
    {
        // Clear some
        ClearData();

        // Import crypto parameters
        switch (parameters.Crv.Value) {
            // Case Ed25519
            case EdConstants.Ed25519_Oid:
                _PublicKey25519 = new Ed25519PublicKeyParameters(parameters.X);
                _PrivateKey25519 = parameters.D != null ? new Ed25519PrivateKeyParameters(parameters.D) : null;
                break;
            // Case Ed448
            case EdConstants.Ed448_Oid:
                _PrivateKey448 = parameters.D != null ? new Ed448PrivateKeyParameters(parameters.D) : null;
                _PublicKey448 = new Ed448PublicKeyParameters(parameters.X);
                break;
            default:
                throw new NotSupportedException($"Curve {parameters.Crv.Value} not supported for Dsa");
        }
    }

    /// <summary>
    /// Get what is it
    /// </summary>
    protected EdAlgorithm _EdAlgorithm
    {
        // Get what is it
        get {
            if (_PublicKey25519 != null) {
                return EdAlgorithm.Ed25519;
            } else if (_PublicKey448 != null) {
                return EdAlgorithm.Ed448;
            } else {
                throw new NotSupportedException("No EdDSA algorithm found");
            }
        }
    }

    /// <summary>
    /// Free data
    /// </summary>
    /// <param name="disposing">Who is calling</param>
    protected override void Dispose(bool disposing)
    {
        // Clear some
        if (disposing) {
            ClearData();
        }
    }

    /// <summary>
    /// Free data
    /// </summary>
    private void ClearData()
    {
        _PublicKey25519 = null;
        _PrivateKey25519 = null;
        _PrivateKey448 = null;
        _PublicKey448 = null;
    }
}
