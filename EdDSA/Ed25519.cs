using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using System.Security.Cryptography;

namespace EdDSA;

public class Ed25519 : ECAlgorithm
{
    /// <summary>
    /// key modulus used by the asymmetric algorithm
    /// </summary>
    private const int curve25519KeyModulusSize = 255;

    /// <summary>
    /// The private key
    /// </summary>
    private Ed25519PrivateKeyParameters? privateKey = null;

    /// <summary>
    /// The public key
    /// </summary>
    private Ed25519PublicKeyParameters publicKey;

    /// <summary>
    /// Signer from BC
    /// </summary>
    private ISigner sign;

    /// <summary>
    /// Constructor to create a new key pair
    /// </summary>
    public Ed25519() : base()
    {

    }

    /// <summary>
    /// Gets or sets the size, in bits, of the key modulus used by the asymmetric algorithm.
    /// </summary>
    public override int KeySize {
        get => curve25519KeyModulusSize;
        set {
            // Do nothing key size is fxed
        }
    }

    /// <summary>
    /// Gets the key sizes (of the private key) that are supported by the asymmetric algorithm.
    /// </summary>
    public override KeySizes[] LegalKeySizes => new KeySizes[] { new KeySizes(Ed25519PrivateKeyParameters.KeySize, Ed25519PrivateKeyParameters.KeySize, 0) };

}
