

using CryptoEx.Ed;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using System.Security.Cryptography;

namespace CryptoEx.EdDSA;

/// <summary>
/// Digital signatures over the Edwards-curve Digital Signature Algorithm (EdDSA)
/// </summary>
public partial class EdDsa : EDAlgorithm
{
    // Key sizes
    private const int KeySize25519 = 256;
    private const int KeySize448 = 456;

    // Ed25519 key pair
    private Ed25519PrivateKeyParameters? _PrivateKey25519 = null;
    private Ed25519PublicKeyParameters? _PublicKey25519 = null;

    // Ed448 key pair
    private Ed448PrivateKeyParameters? _PrivateKey448 = null;
    private Ed448PublicKeyParameters? _PublicKey448 = null;

    // Some signer from BouncyCastle
    private ISigner? _Signer = null;

    /// <summary>
    /// Stop public to be able to create directly this class.
    /// Mainly to confoirm to the .NET way - look at ECDsa
    /// </summary>
    protected internal EdDsa()
    {
    }

    /// <summary>
    /// Create Signer / Verifier
    /// Generate a new key pair 
    /// </summary>
    /// <param name="alg">Algorithm to use. By default it is Ed25519. Can also be Ed448</param>
    /// <returns>The EdDsa tah can be used to sign / verify data</returns>
    public static EdDsa Create(EdAlgorithm alg = EdAlgorithm.Ed25519)
    {
        // Create some
        EdDsa res = new EdDsa();

        // See what we have
        if (alg == EdAlgorithm.Ed25519) {
            // Generate a new key pair
            Span<byte> key = stackalloc byte[KeySize25519 / 8];
            RandomNumberGenerator.Fill(key);
            res._PrivateKey25519 = new Ed25519PrivateKeyParameters(key);
            res._PublicKey25519 = res._PrivateKey25519.GeneratePublicKey();

            // Create the signer
            res._Signer = new Ed25519Signer();
        } else if (alg == EdAlgorithm.Ed448) {
            // Generate a new key pair
            Span<byte> key = stackalloc byte[KeySize448 / 8];
            RandomNumberGenerator.Fill(key);
            res._PrivateKey448 = new Ed448PrivateKeyParameters(key);
            res._PublicKey448 = res._PrivateKey448.GeneratePublicKey();

            // Create the signer
            res._Signer = new Ed448Signer(Array.Empty<byte>());
        } else {
            throw new NotSupportedException($"Curve {alg} not supported for EdDsa");
        }

        // return
        return res;
    }

    /// <summary>
    ///  Create EdDsa from parameters
    /// </summary>
    /// <param name="parameters">The parameters</param>
    /// <returns>The EdDsa Algorythm</returns>
    public static EdDsa Create(EDParameters parameters)
    {
        // Create some
        EdDsa res = new EdDsa();

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
    /// Gets the name of the key exchange algorithm
    /// </summary>
    public override string? KeyExchangeAlgorithm =>
        throw new NotImplementedException("EdDsa is for signatures, not for key exchange");

    /// <summary>
    /// Gets or sets the size, in bits, of the key modulus used by the asymmetric algorithm
    /// </summary>
    public override int KeySize
    {
        get => _EdAlgorithm switch
        {
            EdAlgorithm.Ed25519 => KeySize25519,
            EdAlgorithm.Ed448 => KeySize448,
            _ => throw new NotSupportedException($"Curve {_EdAlgorithm} not supported for Dsa")
        };
        set =>
            throw new Exception("EdDsa has a fixed key size.");
    }

    /// <summary>
    /// Gets the key sizes that are supported by the asymmetric algorithm.
    /// </summary>
    public override KeySizes[] LegalKeySizes =>
        _EdAlgorithm switch
        {
            EdAlgorithm.Ed25519 => new KeySizes[] { new KeySizes(KeySize25519, KeySize25519, 0) },
            EdAlgorithm.Ed448 => new KeySizes[] { new KeySizes(KeySize448, KeySize448, 0) },
            _ => throw new NotSupportedException($"Curve {_EdAlgorithm} not supported for Dsa")
        };

    /// <summary>
    /// The name of the signature algorithm
    /// </summary>
    public override string SignatureAlgorithm =>
         _EdAlgorithm switch
         {
             EdAlgorithm.Ed25519 => EdConstants.Ed25519_Oid,
             EdAlgorithm.Ed448 => EdConstants.Ed448_Oid,
             _ => throw new NotSupportedException($"Curve {_EdAlgorithm} not supported for Dsa")
         };


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
        _Signer = null;
    }
}
