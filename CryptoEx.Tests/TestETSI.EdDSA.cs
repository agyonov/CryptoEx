
using CryptoEx.Ed;
using CryptoEx.Ed.EdDsa;
using CryptoEx.Ed.JWS;
using CryptoEx.Ed.JWS.ETSI;
using CryptoEx.JWS;
using CryptoEx.JWS.ETSI;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace CryptoEx.Tests;
public class TestETSIEdDSA
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

    public static string testFile = """
    This is a test
    This is a test again
    """;

    [Fact(DisplayName = "Test JOSE EdDSA 25519 with enveloped data")]
    public void Test_JOSE_EdDsa_Enveloped()
    {
        // EdDSA key
        AsymmetricAlgorithm? privateKey = null;

        // Try get certificate
        X509Certificate2? cert = GetCertificate(out privateKey);
        if (cert == null) {
            Assert.Fail("NO EdDSA certificate available");
        }

        // Check EdDSA key
        if (privateKey != null && privateKey is EdDsa) {
            // Create signer 
            JWSSigner signer = new JWSSignerEd((EdDsa)privateKey);

            // Get payload 
            signer.AttachSignersCertificate(cert);
            signer.Sign(Encoding.UTF8.GetBytes(message), "text/json");

            // Encode - produce JWS
            var jSign = signer.Encode();

            // Decode & verify
            var headers = signer.Decode<JWSHeader>(jSign, out byte[] _);
            Assert.False(headers.Count != 1);
            var pubCertEnc = headers[0].X5c?.FirstOrDefault();
            Assert.False(string.IsNullOrEmpty(pubCertEnc));
            var pubCert = new X509Certificate2(Convert.FromBase64String(pubCertEnc));
            Assert.NotNull(pubCert.GetEdDsaPublicKey());
            Assert.True(signer.Verify<JWSHeader>(new AsymmetricAlgorithm[] { pubCert.GetEdDsaPublicKey()! }, null));
        } else {
            Assert.Fail("NO EdDSA private key available");
        }
    }

    [Fact(DisplayName = "Test ETSI EdDSA 25519 with enveloped data")]
    public void Test_ETSI_EdDsa_Enveloped()
    {
        // EdDSA key
        AsymmetricAlgorithm? privateKey = null;

        // Try get certificate
        X509Certificate2? cert = GetCertificate(out privateKey);
        if (cert == null) {
            Assert.Fail("NO EdDSA certificate available");
        }

        if (privateKey != null && privateKey is EdDsa) {
            // Create signer 
            ETSISigner signer = new ETSISignerEd((EdDsa)privateKey);

            // Get payload 
            signer.AttachSignersCertificate(cert);
            signer.Sign(Encoding.UTF8.GetBytes(message), "text/json", JWSConstants.JOSE);

            // Encode - produce JWS
            var jSign = signer.Encode(JWSEncodeTypeEnum.Compact);

            // Decode & verify
            Assert.True(signer.Verify(jSign, out byte[] _, out ETSIContextInfo _));
        } else {
            Assert.Fail("NO RSA certificate available");
        }
    }

    [Fact(DisplayName = "Test ETSI EdDSA 25519 with detached data")]
    public void Test_ETSI_EdDsa_Detached()
    {
        // EdDSA key
        AsymmetricAlgorithm? privateKey = null;

        // Try get certificate
        X509Certificate2? cert = GetCertificate(out privateKey);
        if (cert == null) {
            Assert.Fail("NO EdDSA certificate available");
        }

        if (privateKey != null && privateKey is EdDsa) {
            // Get payload 
            using (MemoryStream ms = new(Encoding.UTF8.GetBytes(testFile.Trim())))
            using (MemoryStream msCheck = new(Encoding.UTF8.GetBytes(testFile.Trim()), false)) {
                // Create signer 
                ETSISigner signer = new ETSISignerEd((EdDsa)privateKey);

                // Sign
                signer.AttachSignersCertificate(cert);
                signer.SignDetached(ms, mimeTypeAttachement: "text/plain", typHeaderparameter: JWSConstants.JOSE_JSON);

                // Encode - produce JWS
                var jSign = signer.Encode(JWSEncodeTypeEnum.Flattened);

                // Decode & verify
                Assert.True(signer.VerifyDetached(msCheck, jSign, out byte[] payload, out ETSIContextInfo cInfo));
            }
        } else {
            Assert.Fail("NO RSA certificate available");
        }
    }

    [Fact(DisplayName = "Test ETSI EdDSA 25519 Timestamp with enveloped data")]
    public async Task Test_ETSI_EdDsa_Timestamp_Enveloped()
    {
        // EdDSA key
        AsymmetricAlgorithm? privateKey = null;

        // Try get certificate
        X509Certificate2? cert = GetCertificate(out privateKey);
        if (cert == null) {
            Assert.Fail("NO EdDSA certificate available");
        }

        if (privateKey != null && privateKey is EdDsa) {
            // Create signer 
            ETSISigner signer = new ETSISignerEd((EdDsa)privateKey);

            // Get payload 
            signer.AttachSignersCertificate(cert);
            signer.Sign(Encoding.UTF8.GetBytes(message), "text/json", JWSConstants.JOSE_JSON);
            await signer.AddTimestampAsync(CreateRfc3161RequestAsync);

            // Encode - produce JWS
            var jSign = signer.Encode(JWSEncodeTypeEnum.Full);

            // Decode & verify
            Assert.True(signer.Verify(jSign, out byte[] payload, out ETSIContextInfo cInfo));
        } else {
            Assert.Fail("NO RSA certificate available");
        }
    }

    [Fact(DisplayName = "Test ETSI EdDSA 25519 Timestamp with detached data")]
    public async Task Test_ETSI_EdDsa_Timestamp_Detached()
    {
        // EdDSA key
        AsymmetricAlgorithm? privateKey = null;

        // Try get certificate
        X509Certificate2? cert = GetCertificate(out privateKey);
        if (cert == null) {
            Assert.Fail("NO EdDSA certificate available");
        }

        if (privateKey != null && privateKey is EdDsa) {
            // Get payload 
            using (MemoryStream ms = new(Encoding.UTF8.GetBytes(testFile.Trim())))
            using (MemoryStream msCheck = new(Encoding.UTF8.GetBytes(testFile.Trim()), false)) {
                // Create signer 
                ETSISigner signer = new ETSISignerEd((EdDsa)privateKey);

                // Sign 
                signer.AttachSignersCertificate(cert);
                signer.SignDetached(ms, message, "text/plain", "text/json", JWSConstants.JOSE_JSON);
                await signer.AddTimestampAsync(CreateRfc3161RequestAsync);

                // Encode - produce JWS
                var jSign = signer.Encode(JWSEncodeTypeEnum.Full);

                // Decode & verify
                Assert.True(signer.VerifyDetached(msCheck, jSign, out byte[] payload, out ETSIContextInfo cInfo));
            }
        } else {
            Assert.Fail("NO RSA certificate available");
        }
    }

    [Fact(DisplayName = "Test JOSE EdDSA 448 with enveloped data")]
    public void Test_JOSE_EdDsa_448_Enveloped()
    {
        // EdDSA key
        AsymmetricAlgorithm? privateKey = null;

        // Try get certificate
        X509Certificate2? cert = GetCertificate(out privateKey, EdAlgorithm.Ed448);
        if (cert == null) {
            Assert.Fail("NO EdDSA certificate available");
        }

        // Check EdDSA key
        if (privateKey != null && privateKey is EdDsa) {
            // Create signer 
            JWSSigner signer = new JWSSignerEd((EdDsa)privateKey);

            // Get payload 
            signer.AttachSignersCertificate(cert);
            signer.Sign(Encoding.UTF8.GetBytes(message), "text/json");

            // Encode - produce JWS
            var jSign = signer.Encode();

            // Decode & verify
            var headers = signer.Decode<JWSHeader>(jSign, out byte[] _);
            Assert.False(headers.Count != 1);
            var pubCertEnc = headers[0].X5c?.FirstOrDefault();
            Assert.False(string.IsNullOrEmpty(pubCertEnc));
            var pubCert = new X509Certificate2(Convert.FromBase64String(pubCertEnc));
            Assert.NotNull(pubCert.GetEdDsaPublicKey());
            Assert.True(signer.Verify<JWSHeader>(new AsymmetricAlgorithm[] { pubCert.GetEdDsaPublicKey()! }, null));
        } else {
            Assert.Fail("NO EdDSA private key available");
        }
    }

    [Fact(DisplayName = "Test ETSI EdDSA 448 with enveloped data")]
    public void Test_ETSI_EdDsa_448_Enveloped()
    {
        // EdDSA key
        AsymmetricAlgorithm? privateKey = null;

        // Try get certificate
        X509Certificate2? cert = GetCertificate(out privateKey, EdAlgorithm.Ed448);
        if (cert == null) {
            Assert.Fail("NO EdDSA certificate available");
        }

        if (privateKey != null && privateKey is EdDsa) {
            // Create signer 
            ETSISigner signer = new ETSISignerEd((EdDsa)privateKey);

            // Get payload 
            signer.AttachSignersCertificate(cert);
            signer.Sign(Encoding.UTF8.GetBytes(message), "text/json", JWSConstants.JOSE);

            // Encode - produce JWS
            var jSign = signer.Encode(JWSEncodeTypeEnum.Compact);

            // Decode & verify
            Assert.True(signer.Verify(jSign, out byte[] _, out ETSIContextInfo _));
        } else {
            Assert.Fail("NO RSA certificate available");
        }
    }

    // Get certifacte from PFX store
    private static X509Certificate2? GetCertificate(out AsymmetricAlgorithm? privateKey, EdAlgorithm alg = EdAlgorithm.Ed25519)
    {
        // Ste initially
        privateKey = null;

        // Check what we need
        switch (alg) {
            case EdAlgorithm.Ed25519:
                using (FileStream fs = new(@"source\cert.pfx", FileMode.Open, FileAccess.Read, FileShare.Read)) {
                    X509Certificate2Ed[] arrCerts = fs.LoadEdCertificatesFromPfx("pass.123");
                    if (arrCerts.Length > 0) {
                        privateKey = arrCerts[0].PrivateKey;
                        return arrCerts[0].Certificate;
                    } else {
                        return null;
                    }
                }
            case EdAlgorithm.Ed448:
                using (FileStream fs = new(@"source\cert448.pfx", FileMode.Open, FileAccess.Read, FileShare.Read)) {
                    X509Certificate2Ed[] arrCerts = fs.LoadEdCertificatesFromPfx("pass.123");
                    if (arrCerts.Length > 0) {
                        privateKey = arrCerts[0].PrivateKey;
                        return arrCerts[0].Certificate;
                    } else {
                        return null;
                    }
                }
            default:
                return null;
        }
    }

    // Call Timestamp server
    private async Task<byte[]> CreateRfc3161RequestAsync(byte[] data, CancellationToken ct = default)
    {
        Rfc3161TimestampRequest req = Rfc3161TimestampRequest.CreateFromData(data, HashAlgorithmName.SHA512, null, null, true, null);

        using (HttpClient client = new HttpClient()) {
            client.DefaultRequestHeaders.Accept.Clear();

            HttpContent content = new ByteArrayContent(req.Encode());

            content.Headers.ContentType = new MediaTypeHeaderValue("application/timestamp-query");

            // "http://timestamp.sectigo.com/qualified"
            // "http://tsa.esign.bg"
            // "http://timestamp.digicert.com"
            var res = await client.PostAsync("http://timestamp.sectigo.com/qualified", content, ct);


            return (await res.Content.ReadAsByteArrayAsync(ct))[9..]; // 9 // 27 // 9
        }
    }
}
