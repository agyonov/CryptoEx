using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;

namespace CryptoEx.XML;

/// <summary>
/// XML Signiture description for EcdsaSha256
/// </summary>
public class EcdsaSha256SignatureDescription : SignatureDescription
{
    public EcdsaSha256SignatureDescription()
    {
        KeyAlgorithm = typeof(ECDsa).AssemblyQualifiedName;
    }

    [RequiresUnreferencedCode("Base method requires unreferenced code")]
    public override HashAlgorithm CreateDigest() => SHA256.Create();

    [RequiresUnreferencedCode("Base method requires unreferenced code")]
    public override AsymmetricSignatureFormatter CreateFormatter(AsymmetricAlgorithm key)
    {
        if (!(key is ECDsa ecdsa) || ecdsa.KeySize != 256) throw new InvalidOperationException("Requires EC key over P-256");
        return new EcdsaSignatureFormatter(ecdsa);
    }

    [RequiresUnreferencedCode("Base method requires unreferenced code")]
    public override AsymmetricSignatureDeformatter CreateDeformatter(AsymmetricAlgorithm key)
    {
        if (!(key is ECDsa ecdsa) || ecdsa.KeySize != 256) throw new InvalidOperationException("Requires EC key  over P-384");
        return new EcdsaSignatureDeformatter(ecdsa);
    }
}

/// <summary>
/// XML Signiture description for EcdsaSha384
/// </summary>
public class EcdsaSha384SignatureDescription : SignatureDescription
{
    public EcdsaSha384SignatureDescription()
    {
        KeyAlgorithm = typeof(ECDsa).AssemblyQualifiedName;
    }

    [RequiresUnreferencedCode("Base method requires unreferenced code")]
    public override HashAlgorithm CreateDigest() => SHA384.Create();

    [RequiresUnreferencedCode("Base method requires unreferenced code")]
    public override AsymmetricSignatureFormatter CreateFormatter(AsymmetricAlgorithm key)
    {
        if (!(key is ECDsa ecdsa) || ecdsa.KeySize != 384) throw new InvalidOperationException("Requires EC key over P-384");
        return new EcdsaSignatureFormatter(ecdsa);
    }

    [RequiresUnreferencedCode("Base method requires unreferenced code")]
    public override AsymmetricSignatureDeformatter CreateDeformatter(AsymmetricAlgorithm key)
    {
        if (!(key is ECDsa ecdsa) || ecdsa.KeySize != 384) throw new InvalidOperationException("Requires EC key over P-384");
        return new EcdsaSignatureDeformatter(ecdsa);
    }
}

/// <summary>
/// XML Signiture description for EcdsaSha512
/// </summary>
public class EcdsaSha512SignatureDescription : SignatureDescription
{
    public EcdsaSha512SignatureDescription()
    {
        KeyAlgorithm = typeof(ECDsa).AssemblyQualifiedName;
    }

    [RequiresUnreferencedCode("Base method requires unreferenced code")]
    public override HashAlgorithm CreateDigest() => SHA512.Create();

    [RequiresUnreferencedCode("Base method requires unreferenced code")]
    public override AsymmetricSignatureFormatter CreateFormatter(AsymmetricAlgorithm key)
    {
        if (!(key is ECDsa ecdsa) || ecdsa.KeySize != 521) throw new InvalidOperationException("Requires EC key over P-521");
        return new EcdsaSignatureFormatter(ecdsa);
    }

    [RequiresUnreferencedCode("Base method requires unreferenced code")]
    public override AsymmetricSignatureDeformatter CreateDeformatter(AsymmetricAlgorithm key)
    {
        if (!(key is ECDsa ecdsa) || ecdsa.KeySize != 521) throw new InvalidOperationException("Requires EC key over P-521");
        return new EcdsaSignatureDeformatter(ecdsa);
    }
}
