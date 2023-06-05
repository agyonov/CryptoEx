using CryptoEx.Ed;
using Org.BouncyCastle.Crypto.Parameters;

namespace CryptoEx.EdDSA;

/// <summary>
/// Digital signatures over the Edwards-curve Digital Signature Algorithm (EdDSA)
/// </summary>
public partial class EdDsa : EDAlgorithm
{
    private const int KeySize448 = 456;

    private Ed448PrivateKeyParameters? _PrivateKey448 = null;

    private Ed448PublicKeyParameters? _PublicKey448 = null;
}
