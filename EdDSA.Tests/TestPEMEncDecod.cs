using EdDSA.Utils;
using Xunit;
using static System.Runtime.InteropServices.JavaScript.JSType;

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
        bool res = PemEncodeDecode.TryReadEd25519PrivateKey(pem, prKey);
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
        bool res = PemEncodeDecode.TryReadEd25519PrivateKey(pemOpenSSL, prKey);
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
        bool res = PemEncodeDecode.TryReadEd25519PublicKey(pemPubOpenSSL, pubKey);
        Assert.True(res, "Not valid Ed25519PublicKey encoded in PEM");
        Assert.Equal(thePubKeyOpenSSL, BitConverter.ToString(pubKey.ToArray()).Replace("-", "").ToUpper());
    }
}