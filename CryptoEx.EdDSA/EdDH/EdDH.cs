using Org.BouncyCastle.Crypto.Parameters;
using System.Security.Cryptography;

namespace CryptoEx.Ed.EdDH;

/// <summary>
/// Key exchanges over the Edwards-curve Digital Signature Algorithm (EdDSA)
/// </summary>
public partial class EdDH : EDAlgorithm
{
    // Key sizes
    private const int KeySize25519 = 256;
    private const int KeySize448 = 448;

    // Ed25519 key pair
    private X25519PrivateKeyParameters? _PrivateKey25519 = null;
    private X25519PublicKeyParameters? _PublicKey25519 = null;

    // Ed448 key pair
    private X448PrivateKeyParameters? _PrivateKey448 = null;
    private X448PublicKeyParameters? _PublicKey448 = null;

    /// <summary>
    /// Stop public to be able to create directly this class.
    /// Mainly to confoirm to the .NET way - look at EDDiffieHellman
    /// </summary>
    protected internal EdDH()
    {
    }

    /// <summary>
    /// Create EdDH
    /// Generate a new key pair 
    /// </summary>
    /// <param name="alg">Algorithm to use. By default it is X25519. Can also be X448</param>
    /// <returns>The EdDH that can be used to exchange keys</returns>
    public static EdDH Create(EdAlgorithm alg = EdAlgorithm.X25519)
    {
        // Create some
        EdDH res = new EdDH();

        // See what we have
        if (alg == EdAlgorithm.X25519) {
            // Generate a new key pair
            Span<byte> key = stackalloc byte[KeySize25519 / 8];
            RandomNumberGenerator.Fill(key);
            res._PrivateKey25519 = new X25519PrivateKeyParameters(key);
            res._PublicKey25519 = res._PrivateKey25519.GeneratePublicKey();
        } else if (alg == EdAlgorithm.X448) {
            // Generate a new key pair
            Span<byte> key = stackalloc byte[KeySize448 / 8];
            RandomNumberGenerator.Fill(key);
            res._PrivateKey448 = new X448PrivateKeyParameters(key);
            res._PublicKey448 = res._PrivateKey448.GeneratePublicKey();
        } else {
            throw new NotSupportedException($"Curve {alg} not supported for EdDH");
        }

        // return
        return res;
    }

    /// <summary>
    ///  Create EdDH from parameters
    /// </summary>
    /// <param name="parameters">The parameters</param>
    /// <returns>The EdDH Algorythm</returns>
    public static EdDH Create(EDParameters parameters)
    {
        // Create some
        EdDH res = new EdDH();

        res.ImportParameters(parameters);

        // return
        return res;
    }

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
            case EdAlgorithm.X25519:
                eDParameters.Crv = new Oid(EdConstants.X25519_Oid);
                eDParameters.X = _PublicKey25519 != null ? _PublicKey25519.GetEncoded() : Array.Empty<byte>();
                if (includePrivateParameters) {
                    eDParameters.D = _PrivateKey25519 != null ? _PrivateKey25519.GetEncoded() : null;
                } else {
                    eDParameters.D = null;
                }
                break;
            case EdAlgorithm.X448:
                eDParameters.Crv = new Oid(EdConstants.X448_Oid);
                eDParameters.X = _PublicKey448 != null ? _PublicKey448.GetEncoded() : Array.Empty<byte>();
                if (includePrivateParameters) {
                    eDParameters.D = _PrivateKey448 != null ? _PrivateKey448.GetEncoded() : null;
                } else {
                    eDParameters.D = null;
                }
                break;
            default:
                throw new NotSupportedException($"Curve {_EdAlgorithm} not supported for Key Exchange Exchange");
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
            // Case X25519
            case EdConstants.X25519_Oid:
                _PrivateKey25519 = parameters.D != null ? new X25519PrivateKeyParameters(parameters.D) : null;
                if (parameters.X.Length > 0) {
                    _PublicKey25519 = new X25519PublicKeyParameters(parameters.X);
                } else if (_PrivateKey25519 != null) {
                    _PublicKey25519 = _PrivateKey25519.GeneratePublicKey();
                }
                break;
            // Case X448
            case EdConstants.X448_Oid:
                _PrivateKey448 = parameters.D != null ? new X448PrivateKeyParameters(parameters.D) : null;
                if (parameters.X.Length > 0) {
                    _PublicKey448 = new X448PublicKeyParameters(parameters.X);
                } else if (_PrivateKey448 != null) {
                    _PublicKey448 = _PrivateKey448.GeneratePublicKey();
                }
                break;
            default:
                throw new NotSupportedException($"Curve {parameters.Crv.Value} not supported for Key exchange");
        }
    }

    /// <summary>
    /// Gets the name of the key exchange algorithm
    /// </summary>
    public override string? KeyExchangeAlgorithm =>
        _EdAlgorithm switch
        {
            EdAlgorithm.X25519 => EdConstants.X25519_Oid,
            EdAlgorithm.X448 => EdConstants.X448_Oid,
            _ => throw new NotSupportedException($"Curve {_EdAlgorithm} not supported for Key Exchange")
        };

    /// <summary>
    /// Gets or sets the size, in bits, of the key modulus used by the asymmetric algorithm
    /// </summary>
    public override int KeySize
    {
        get => _EdAlgorithm switch
        {
            EdAlgorithm.X25519 => KeySize25519,
            EdAlgorithm.X448 => KeySize448,
            _ => throw new NotSupportedException($"Curve {_EdAlgorithm} not supported for Key Exchange")
        };
        set =>
            throw new Exception("EdDH has a fixed key size.");
    }

    /// <summary>
    /// Gets the key sizes that are supported by the asymmetric algorithm.
    /// </summary>
    public override KeySizes[] LegalKeySizes =>
        _EdAlgorithm switch
        {
            EdAlgorithm.X25519 => new KeySizes[] { new KeySizes(KeySize25519, KeySize25519, 0) },
            EdAlgorithm.X448 => new KeySizes[] { new KeySizes(KeySize448, KeySize448, 0) },
            _ => throw new NotSupportedException($"Curve {_EdAlgorithm} not supported for Key Exchange")
        };

    /// <summary>
    /// The name of the signature algorithm
    /// </summary>
    public override string SignatureAlgorithm =>
        throw new NotImplementedException("EdDH is for key exchange, not for signatures");

    /// <summary>
    /// Get what is it
    /// </summary>
    protected EdAlgorithm _EdAlgorithm
    {
        // Get what is it
        get {
            if (_PublicKey25519 != null) {
                return EdAlgorithm.X25519;
            } else if (_PublicKey448 != null) {
                return EdAlgorithm.X448;
            } else {
                throw new NotSupportedException("No EdDH algorithm found");
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
