using EdDSA.Utils;

namespace EdDSA.Tests;

public class TestPEMEncDecod
{
    // Private keys from RFC 8410 document
    public const string pemOne =
@"-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEINTuctv5E1hK1bbY8fdp+K06/nwoy/HU++CXqI9EdVhC
-----END PRIVATE KEY-----";
    public const string pemOneWithPub =
@"-----BEGIN PRIVATE KEY-----
MHICAQEwBQYDK2VwBCIEINTuctv5E1hK1bbY8fdp+K06/nwoy/HU++CXqI9EdVhC
oB8wHQYKKoZIhvcNAQkJFDEPDA1DdXJkbGUgQ2hhaXJzgSEAGb9ECWmEzf6FQbrB
Z9w7lshQhqowtrbLDFw4rXAxZuE=
-----END PRIVATE KEY-----";
    public const string thePrKeyOne = "D4EE72DBF913584AD5B6D8F1F769F8AD3AFE7C28CBF1D4FBE097A88F44755842";

    [Theory(DisplayName = "Test private Ed25519 key read from PEM from RFC 8410")]
    [InlineData(pemOne)]
    [InlineData(pemOneWithPub)]
    public void TestReadPrivateKeyEd25519_RFC(string pem)
    {
        Span<byte> prKey = stackalloc byte[32];
        bool res = PemEd.TryReadEd25519PrivateKey(pem, prKey);
        Assert.True(res, "Not valid Ed25519PrivateKey encoded in PEM");
        Assert.Equal(thePrKeyOne, BitConverter.ToString(prKey.ToArray()).Replace("-", "").ToUpper());
    }

    // private key from OpenSSL
    public const string pemOpenSSL = @"-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIPkoRs4hG3UT5f/emUfAjinONvJI3SOArEUdZ6mVA2Pi
-----END PRIVATE KEY-----";
    public const string thePrKeyOpenSSL = "F92846CE211B7513E5FFDE9947C08E29CE36F248DD2380AC451D67A9950363E2";

    [Fact(DisplayName = "Test private Ed25519 key read from PEM from OpenSSL")]
    public void TestReadPrivateKeyEd25519_OpenSSL()
    {
        Span<byte> prKey = stackalloc byte[32];
        bool res = PemEd.TryReadEd25519PrivateKey(pemOpenSSL, prKey);
        Assert.True(res, "Not valid Ed25519PrivateKey encoded in PEM");
        Assert.Equal(thePrKeyOpenSSL, BitConverter.ToString(prKey.ToArray()).Replace("-", "").ToUpper());
    }


    // public key from OpenSSL
    public const string pemPubOpenSSL = @"-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAYB9j6C7v99UHOnUiLPvepXHTALVTJNWlpRrV0xqe1Zo=
-----END PUBLIC KEY-----";
    public const string thePubKeyOpenSSL = "601F63E82EEFF7D5073A75222CFBDEA571D300B55324D5A5A51AD5D31A9ED59A";

    [Fact(DisplayName = "Test public Ed25519 key read from PEM from OpenSSL")]
    public void TestReadPublicKeyEd25519_OpenSSL()
    {
        Span<byte> pubKey = stackalloc byte[32];
        bool res = PemEd.TryReadEd25519PublicKey(pemPubOpenSSL, pubKey);
        Assert.True(res, "Not valid Ed25519PublicKey encoded in PEM");
        Assert.Equal(thePubKeyOpenSSL, BitConverter.ToString(pubKey.ToArray()).Replace("-", "").ToUpper());
    }


    // private key from OpenSSL ED448
    public const string pem448OpenSSL = @"-----BEGIN PRIVATE KEY-----
MEcCAQAwBQYDK2VxBDsEOZdokyyjkd8Yrn/bDqDXAsA4X9eztBe68+Y0LT5Mq4DQ
zKdppo+EnMKTi7RKJCae8T6/6it3nLY07A==
-----END PRIVATE KEY-----";
    public const string thePrKey448OpenSSL = "9768932CA391DF18AE7FDB0EA0D702C0385FD7B3B417BAF3E6342D3E4CAB80D0CCA769A68F849CC2938BB44A24269EF13EBFEA2B779CB634EC";

    [Fact(DisplayName = "Test private Ed448 key read from PEM from OpenSSL")]
    public void TestReadPrivateKeyEd448_OpenSSL()
    {
        Span<byte> prKey = stackalloc byte[57];
        bool res = PemEd.TryReadEd4489PrivateKey(pem448OpenSSL, prKey);
        Assert.True(res, "Not valid Ed448PrivateKey encoded in PEM");
        Assert.Equal(thePrKey448OpenSSL, BitConverter.ToString(prKey.ToArray()).Replace("-", "").ToUpper());
    }

    // public key from OpenSSL ED448
    public const string pem448PubOpenSSL = @"-----BEGIN PUBLIC KEY-----
MEMwBQYDK2VxAzoA2VP5XGb1GIycuVbcZatr7bnm9zhNEeAvC+FSWOPrvT2R6Ibz
GE/AQbi/fJdyNpe9quTAVILPhQkA
-----END PUBLIC KEY-----";
    public const string thePub448KeyOpenSSL = "D953F95C66F5188C9CB956DC65AB6BEDB9E6F7384D11E02F0BE15258E3EBBD3D91E886F3184FC041B8BF7C97723697BDAAE4C05482CF850900";

    [Fact(DisplayName = "Test public Ed448 key read from PEM from OpenSSL")]
    public void TestReadPublicKeyEd448_OpenSSL()
    {
        Span<byte> pubKey = stackalloc byte[57];
        bool res = PemEd.TryReadEd4489PublicKey(pem448PubOpenSSL, pubKey);
        Assert.True(res, "Not valid Ed448PublicKey encoded in PEM");
        Assert.Equal(thePub448KeyOpenSSL, BitConverter.ToString(pubKey.ToArray()).Replace("-", "").ToUpper());
    }

    [Fact(DisplayName = "Test private Ed25519 key write to PEM from OpenSSL")]
    public void TestWritePrivateKeyEd25519_OpenSSL()
    {
        byte[] prKey = PemEd.HexToByte(thePrKeyOpenSSL);
        string resKey = PemEd.WriteEd25519PrivateKey(prKey);
        Assert.Equal(pemOpenSSL, resKey);
    }

    [Fact(DisplayName = "Test public Ed25519 key write to PEM from OpenSSL")]
    public void TestWritePublicKeyEd25519_OpenSSL()
    {
        byte[] pubKey = PemEd.HexToByte(thePubKeyOpenSSL);
        string resKey = PemEd.WriteEd25519PublicKey(pubKey);
        Assert.Equal(pemPubOpenSSL, resKey);
    }
}