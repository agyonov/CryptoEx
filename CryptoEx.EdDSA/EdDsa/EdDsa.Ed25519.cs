using CryptoEx.Ed;
using Org.BouncyCastle.Crypto.Parameters;

namespace CryptoEx.EdDSA;

public partial class EdDsa : EDAlgorithm
{

    private const int KeySize25519 = 256;

    private Ed25519PrivateKeyParameters? _PrivateKey25519 = null;

    private Ed25519PublicKeyParameters? _PublicKey25519 = null;

    
}
