using CryptoEx.Ed;
using Org.BouncyCastle.Crypto.Parameters;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CryptoEx.EdDSA;

public partial class EdDsa : EDAlgorithm
{
    private const int KeySize448 = 456;

    private Ed448PrivateKeyParameters? _PrivateKey448 = null;

    private Ed448PublicKeyParameters? _PublicKey448 = null;
}
