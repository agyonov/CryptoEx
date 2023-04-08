using System.Security.Cryptography;

namespace CryptoEx.XML;

/// <summary>
/// Class to verify the XML signature using ECDSA
/// </summary>
public class EcdsaSignatureDeformatter : AsymmetricSignatureDeformatter
{
    private ECDsa? key;

    public EcdsaSignatureDeformatter(ECDsa key) => this.key = key;

    public override void SetKey(AsymmetricAlgorithm key) => this.key = key as ECDsa;

    public override void SetHashAlgorithm(string strName) { }

    public override bool VerifySignature(byte[] rgbHash, byte[] rgbSignature) => key?.VerifyHash(rgbHash, rgbSignature) ?? false;
}
