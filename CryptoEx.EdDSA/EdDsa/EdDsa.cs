using System.Security.Cryptography;

namespace CryptoEx.EdDSA;
public abstract class EdDsa : AsymmetricAlgorithm
{
    protected override void Dispose(bool disposing)
    {
        // call parent
        base.Dispose(disposing);
    }

    /// <summary>
    /// When overridden in a derived class, exports the parameters for the algorithm.
    /// If the curve has a name, the Curve property will contain named curve parameters otherwise it will contain explicit parameters.
    /// </summary>
    /// <param name="includePrivateParameters">
    ///   <see langword="true" /> to include private parameters, otherwise, <see langword="false" />.
    /// </param>
    /// <returns>The exported parameters.</returns>
    public abstract EDParameters ExportParameters(bool includePrivateParameters);

    public override byte[] ExportEncryptedPkcs8PrivateKey(ReadOnlySpan<char> password, PbeParameters pbeParameters)
    {
        return base.ExportEncryptedPkcs8PrivateKey(password, pbeParameters);
    }
}
