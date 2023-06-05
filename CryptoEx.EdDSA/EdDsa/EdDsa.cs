

using CryptoEx.Ed;

namespace CryptoEx.EdDSA;

public partial class EdDsa : EDAlgorithm
{

    public override EDParameters ExportParameters(bool includePrivateParameters)
    {
        throw new NotImplementedException();
    }

    public override void ImportParameters(EDParameters parameters)
    {
        throw new NotImplementedException();
    }
}
