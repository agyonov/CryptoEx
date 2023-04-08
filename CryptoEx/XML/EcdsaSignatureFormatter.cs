using System.Security.Cryptography;

namespace CryptoEx.XML;

/// <summary>
/// Class to sign / create the XML signature using ECDSA
/// </summary>
public class EcdsaSignatureFormatter : AsymmetricSignatureFormatter
{
    private ECDsa? key;

    public EcdsaSignatureFormatter(ECDsa key) => this.key = key;

    public override void SetKey(AsymmetricAlgorithm key) => this.key = key as ECDsa;

    public override void SetHashAlgorithm(string strName) { }

    public override byte[] CreateSignature(byte[] rgbHash) => key?.SignHash(rgbHash) ?? Array.Empty<byte>();
}
