

using CryptoEx.JWS;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;
using System.Text;
using CryptoEx.Ed;
using CryptoEx.JWK;
using System.Text.Json;
using CryptoEx.JWS.ETSI;
using System.Globalization;

namespace CryptoEx.Tests;
public  class TestJWSAdditianalHeader
{
    // Some test data for JADES
    public static string message = """
    {
        "Разрешение": 2413413241243,
        "Име Латиница": "John Doe",
        "Име": "Джон Доу",
        "ЕГН/ЛНЧ": "1234567890",
        "Оръжия": [
            {
                "Сериен №": "98965049Ф769",
                "Модел": "AK-47"
            },
            {
                "Сериен №": "8984-3245",
                "Модел": "Барета"
            }
        ]
    }
    """;

    [Fact(DisplayName = "Test JOSE ECDSA with alternative headers only")]
    public void Test_JOSE_ECDSA_Enveloped_Alternative()
    {
        // Try get certificate
        X509Certificate2? cert = GetCertificate(CertType.EC);
        if (cert == null) {
            Assert.Fail("NO ECDsa certificate available");
        }

        // Get ECDSA private key
        ECDsa? ecKey = cert.GetECDsaPrivateKey();
        if (ecKey != null) {
            // Create signer 
            JWSSigner signer = new JWSSigner(ecKey);

            // Get payload 
            signer.AttachSignersOthersProperties(Jku: "htts://acme.com/getJKU",
                JwKey: ecKey.GetJwk(),
                Kid: cert.SerialNumber,
                X5u: "htts://acme.com/getX5U");
            signer.Sign(Encoding.UTF8.GetBytes(message), "text/json");

            // Encode - produce JWS
            var jSign = signer.Encode();

            // Decode & verify
            var headers = signer.Decode<JWSHeader>(jSign, out byte[] payload);

            Assert.False(headers.Count != 1);
            Assert.Equal(cert.SerialNumber, headers[0].Kid);
            Assert.Equal("htts://acme.com/getJKU", headers[0].Jku);
            Assert.Equal("htts://acme.com/getX5U", headers[0].X5u);
            Assert.NotNull(headers[0].Jwk?.GetECDsaPublicKey());
            Assert.True(signer.Verify<JWSHeader>(new AsymmetricAlgorithm[] { headers[0].Jwk?.GetECDsaPublicKey()! }, null));
        } else {
            Assert.Fail("NO ECDsa certificate available");
        }
    }

    [Fact(DisplayName = "Test JOSE ECDSA with BOTH alternative headers And Certificate")]
    public void Test_JOSE_ECDSA_Enveloped_Alternative_And_Cert()
    {
        // Try get certificate
        X509Certificate2? cert = GetCertificate(CertType.EC);
        if (cert == null) {
            Assert.Fail("NO ECDsa certificate available");
        }

        // Get ECDSA private key
        ECDsa? ecKey = cert.GetECDsaPrivateKey();
        if (ecKey != null) {
            // Create signer 
            JWSSigner signer = new JWSSigner(ecKey);

            // Get payload 
            signer.AttachSignersOthersProperties(Jku: "htts://acme.com/getJKU",
                JwKey: ecKey.GetJwk(),
                Kid: cert.SerialNumber,
                X5u: "htts://acme.com/getX5U");
            signer.AttachSignersCertificate(cert);
            signer.Sign(Encoding.UTF8.GetBytes(message), "text/json");

            // Encode - produce JWS
            var jSign = signer.Encode();

            // Decode & verify
            var headers = signer.Decode<JWSHeader>(jSign, out byte[] payload);

            Assert.False(headers.Count != 1);
            var pubCertEnc = headers[0].X5c?.FirstOrDefault();
            Assert.False(string.IsNullOrEmpty(pubCertEnc));
            var pubCert = new X509Certificate2(Convert.FromBase64String(pubCertEnc));
            Assert.NotNull(pubCert.GetECDsaPublicKey());
            Assert.True(signer.Verify<JWSHeader>(new AsymmetricAlgorithm[] { pubCert.GetECDsaPublicKey()! }, null));

            Assert.Equal(cert.SerialNumber, headers[0].Kid);
            Assert.Equal("htts://acme.com/getJKU", headers[0].Jku);
            Assert.Equal("htts://acme.com/getX5U", headers[0].X5u);

            // Decode & verify - two
            headers = signer.Decode<JWSHeader>(jSign, out payload);

            Assert.False(headers.Count != 1);
            Assert.NotNull(headers[0].Jwk?.GetECDsaPublicKey());
            Assert.True(signer.Verify<JWSHeader>(new AsymmetricAlgorithm[] { headers[0].Jwk?.GetECDsaPublicKey()! }, null));
        } else {
            Assert.Fail("NO ECDsa certificate available");
        }
    }

    [Fact(DisplayName = "Test JOSE ECDSA with b64:false")]
    public void Test_JOSE_ECDSA_EnvelopedB64_false()
    {
        // Try get certificate
        X509Certificate2? cert = GetCertificate(CertType.EC);
        if (cert == null) {
            Assert.Fail("NO ECDsa certificate available");
        }

        // Get ECDSA private key
        ECDsa? ecKey = cert.GetECDsaPrivateKey();
        if (ecKey != null) {
            // Create signer 
            JWSSigner signer = new JWSSigner(ecKey);

            // Get payload 
            signer.AttachSignersCertificate(cert);
            signer.Sign(Encoding.UTF8.GetBytes(message), mimeType: "text/json", b64: false);

            // Encode - produce JWS
            var jSign = signer.Encode();

            // Decode & verify
            var headers = signer.Decode<JWSHeader>(jSign, out byte[] payload);

            Assert.False(headers.Count != 1);
            var pubCertEnc = headers[0].X5c?.FirstOrDefault();
            Assert.False(string.IsNullOrEmpty(pubCertEnc));
            var pubCert = new X509Certificate2(Convert.FromBase64String(pubCertEnc));
            Assert.NotNull(pubCert.GetECDsaPublicKey());
            Assert.True(signer.Verify<JWSHeader>(new AsymmetricAlgorithm[] { pubCert.GetECDsaPublicKey()! }, JWSSigner.B64Resolutor));
        } else {
            Assert.Fail("NO ECDsa certificate available");
        }
    }

    [Fact(DisplayName = "Test JOSE ECDSA with b64:true")]
    public void Test_JOSE_ECDSA_EnvelopedB64_True()
    {
        // Try get certificate
        X509Certificate2? cert = GetCertificate(CertType.EC);
        if (cert == null) {
            Assert.Fail("NO ECDsa certificate available");
        }

        // Get ECDSA private key
        ECDsa? ecKey = cert.GetECDsaPrivateKey();
        if (ecKey != null) {
            // Create signer 
            JWSSigner signer = new JWSSigner(ecKey);

            // Get payload 
            signer.AttachSignersCertificate(cert);
            signer.Sign(Encoding.UTF8.GetBytes(message), mimeType: "text/json", b64: true);

            // Encode - produce JWS
            var jSign = signer.Encode();

            // Decode & verify
            var headers = signer.Decode<JWSHeader>(jSign, out byte[] payload);

            Assert.False(headers.Count != 1);
            var pubCertEnc = headers[0].X5c?.FirstOrDefault();
            Assert.False(string.IsNullOrEmpty(pubCertEnc));
            var pubCert = new X509Certificate2(Convert.FromBase64String(pubCertEnc));
            Assert.NotNull(pubCert.GetECDsaPublicKey());
            Assert.True(signer.Verify<JWSHeader>(new AsymmetricAlgorithm[] { pubCert.GetECDsaPublicKey()! }, JWSSigner.B64Resolutor));
        } else {
            Assert.Fail("NO ECDsa certificate available");
        }
    }

    private static X509Certificate2? GetCertificate(CertType certType)
    {
        // Check what we need
        switch (certType) {
            case CertType.RSA:
                return new X509Certificate2(@"source\cerRSA.pfx", "pass.123");
            case CertType.EC:
                return new X509Certificate2(@"source\cerECC.pfx", "pass.123");
            case CertType.Ed:
                using (FileStream fs = new(@"source\cert.pfx", FileMode.Open, FileAccess.Read, FileShare.Read)) {
                    X509Certificate2Ed[] arrCerts = fs.LoadEdCertificatesFromPfx("pass.123");
                    if (arrCerts.Length > 0) {
                        return arrCerts[0].Certificate;
                    } else {
                        return null;
                    }
                }
            default:
                return null;
        }
    }
}
