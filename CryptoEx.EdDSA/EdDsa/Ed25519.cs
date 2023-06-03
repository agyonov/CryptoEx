
namespace CryptoEx.EdDSA;

public class Ed25519 : EdDsa
{
    protected override void Dispose(bool disposing)
    {
        base.Dispose(disposing);
    }

    override public EDParameters ExportParameters(bool includePrivateParameters)
    {
        throw new NotImplementedException();
    }

}
