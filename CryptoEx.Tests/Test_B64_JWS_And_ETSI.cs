
using CryptoEx.Ed;
using CryptoEx.JWK;
using CryptoEx.JWS;
using CryptoEx.JWS.ETSI;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;

namespace CryptoEx.Tests;


public class Test_B64_JWS_And_ETSI
{
    public static string HMACKey = """
    {
     "kty":"oct",
     "k":"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"
    }
    """;

    // Some test data for JADES
    public static string message = "$.02";

    public static string testFile = """
    This is a test
    This is a test again
    """;

    [Fact(DisplayName = "Test B64 JOSE RSA with enveloped data")]
    public void Test_B64_JOSE_RSA_Enveloped()
    {
        // Try get certificate
        X509Certificate2? cert = GetCertificate(CertType.RSA);
        if (cert == null) {
            Assert.Fail("NO RSA certificate available");
        }

        // Get RSA private key
        RSA? rsaKey = cert.GetRSAPrivateKey();
        if (rsaKey != null) {
            // Create signer 
            JWSSigner signer = new JWSSigner(rsaKey, HashAlgorithmName.SHA512);

            // Get payload 
            signer.AttachSignersCertificate(cert);
            signer.Sign(Encoding.UTF8.GetBytes(message), "text/json", b64: false);

            // Encode - produce JWS
            var jSign = signer.Encode();

            // Decode & verify
            var headers = signer.Decode<JWSHeader>(jSign, out byte[] _);
            Assert.False(headers.Count != 1);
            var pubCertEnc = headers[0].X5c?.FirstOrDefault();
            Assert.False(string.IsNullOrEmpty(pubCertEnc));
            var pubCert = new X509Certificate2(Convert.FromBase64String(pubCertEnc));
            Assert.NotNull(pubCert.GetRSAPublicKey());
            Assert.True(signer.Verify<JWSHeader>(new AsymmetricAlgorithm[] { pubCert.GetRSAPublicKey()! }, JWSSigner.B64Resolutor));
        } else {
            Assert.Fail("NO RSA certificate available");
        }
    }

    [Fact(DisplayName = "Test B64 JOSE HMAC with enveloped data")]
    public void Test_B64_JOSE_HMAC_Enveloped()
    {
        // Try get Key
        JwkSymmetric? jwk = JsonSerializer.Deserialize<Jwk>(HMACKey, JwkConstants.jsonOptions) as JwkSymmetric;

        // Check
        Assert.NotNull(jwk);

        // Get The hkey
        byte[]? theKey = jwk.GetSymmetricKey();

        // Check
        Assert.NotNull(theKey);

        // Get The hkey
        using (HMAC key = new HMACSHA256(theKey)) {
            // Create signer 
            JWSSigner signer = new JWSSigner(key);

            // Get payload 
            signer.Sign(Encoding.UTF8.GetBytes(message), b64: false);

            // Encode - produce JWS
            var jSign = signer.Encode();

            // Decode & verify
            var headers = signer.Decode<JWSHeader>(jSign, out byte[] _);
            Assert.False(headers.Count != 1);
            Assert.True(signer.Verify<JWSHeader>(new HMAC[] { key }, JWSSigner.B64Resolutor));
        }
    }

    [Fact(DisplayName = "Test B64 ETSI RSA with enveloped data")]
    public void Test_B64_ETSI_RSA_Enveloped()
    {
        // Try get certificate
        X509Certificate2? cert = GetCertificateOnWindows(CertType.RSA);
        if (cert == null) {
            Assert.Fail("NO RSA certificate available");
        }

        // Get RSA private key
        RSA? rsaKey = cert.GetRSAPrivateKey();
        if (rsaKey != null) {
            // Create signer 
            ETSISigner signer = new ETSISigner(rsaKey, HashAlgorithmName.SHA512);

            // Get payload 
            signer.AttachSignersCertificate(cert);
            signer.Sign(Encoding.UTF8.GetBytes(message), "text/json", JWSConstants.JOSE, b64: false);

            // Encode - produce JWS
            var jSign = signer.Encode(JWSEncodeTypeEnum.Flattened);

            // Decode & verify
            Assert.True(signer.Verify(jSign, out byte[] _, out ETSIContextInfo _));
        } else {
            Assert.Fail("NO RSA certificate available");
        }
    }

    [Fact(DisplayName = "Test B64 ETSI RSA with detached data")]
    public void Test_B64_ETSI_RSA_Detached()
    {
        // Try get certificate
        X509Certificate2? cert = GetCertificateOnWindows(CertType.RSA);
        if (cert == null) {
            Assert.Fail("NO RSA certificate available");
        }

        // Get RSA private key
        RSA? rsaKey = cert.GetRSAPrivateKey();
        if (rsaKey != null) {
            // Get payload 
            using (MemoryStream ms = new(Encoding.UTF8.GetBytes(testFile.Trim())))
            using (MemoryStream msCheck = new(Encoding.UTF8.GetBytes(testFile.Trim()), false)) {
                // Create signer 
                ETSISigner signer = new ETSISigner(rsaKey, HashAlgorithmName.SHA512);

                // Sign
                signer.AttachSignersCertificate(cert);
                signer.SignDetached(ms, mimeTypeAttachement: "text/plain", typHeaderparameter: JWSConstants.JOSE_JSON, b64: false);

                // Encode - produce JWS
                var jSign = signer.Encode(JWSEncodeTypeEnum.Flattened);

                // Decode & verify
                Assert.True(signer.VerifyDetached(msCheck, jSign, out byte[] payload, out ETSIContextInfo cInfo));
            }
        } else {
            Assert.Fail("NO RSA certificate available");
        }
    }

    [Fact(DisplayName = "Test B64 ETSI RSA Timestamp with enveloped data")]
    public async Task Test_B64_ETSI_RSA_Timestamp_Enveloped()
    {
        // Try get certificate
        X509Certificate2? cert = GetCertificateOnWindows(CertType.RSA);
        if (cert == null) {
            Assert.Fail("NO RSA certificate available");
        }

        // Get RSA private key
        RSA? rsaKey = cert.GetRSAPrivateKey();
        if (rsaKey != null) {
            // Create signer 
            ETSISigner signer = new ETSISigner(rsaKey, HashAlgorithmName.SHA512);

            // Get payload 
            signer.AttachSignersCertificate(cert);
            signer.Sign(Encoding.UTF8.GetBytes(message), "text/json", JWSConstants.JOSE_JSON, b64: false);
            await signer.AddTimestampAsync(CreateRfc3161RequestAsync);

            // Encode - produce JWS
            var jSign = signer.Encode(JWSEncodeTypeEnum.Full);

            // Decode & verify
            Assert.True(signer.Verify(jSign, out byte[] payload, out ETSIContextInfo cInfo));
        } else {
            Assert.Fail("NO RSA certificate available");
        }
    }

    [Fact(DisplayName = "Test B64 ETSI RSA Timestamp with detached data")]
    public async Task Test_B64_ETSI_RSA_Timestamp_Detached()
    {
        // Try get certificate
        X509Certificate2? cert = GetCertificateOnWindows(CertType.RSA);
        if (cert == null) {
            Assert.Fail("NO RSA certificate available");
        }

        // Get RSA private key
        RSA? rsaKey = cert.GetRSAPrivateKey();
        if (rsaKey != null) {
            // Get payload 
            using (MemoryStream ms = new(Encoding.UTF8.GetBytes(testFile.Trim())))
            using (MemoryStream msCheck = new(Encoding.UTF8.GetBytes(testFile.Trim()), false)) {
                // Create signer 
                ETSISigner signer = new ETSISigner(rsaKey, HashAlgorithmName.SHA512);

                // Sign 
                signer.AttachSignersCertificate(cert);
                signer.SignDetached(ms, message, "text/plain", "text/json", JWSConstants.JOSE_JSON,  b64: false);
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

    // Set some timestamp authority
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

    // Get some certificate from Windows store for testing
    private static X509Certificate2? GetCertificateOnWindows(CertType certType)
    {
        var now = DateTime.Now;
        using (X509Store store = new X509Store(StoreLocation.CurrentUser)) {
            store.Open(OpenFlags.ReadOnly);

            var coll = store.Certificates
                            .Where(cert => cert.HasPrivateKey && cert.NotBefore < now && cert.NotAfter > now)
                            .ToList();

            List<X509Certificate2> valColl = new List<X509Certificate2>();

            foreach (var c in coll) {
                using (var chain = new X509Chain()) {

                    chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                    chain.ChainPolicy.DisableCertificateDownloads = true;
                    if (chain.Build(c)) {
                        valColl.Add(c);
                    } else {
                        c.Dispose();
                    }

                    for (int i = 0; i < chain.ChainElements.Count; i++) {
                        chain.ChainElements[i].Certificate.Dispose();
                    }
                }
            }

            return valColl.Where(c =>
            {
                string frName = certType switch
                {
                    CertType.RSA => "RSA",
                    CertType.EC => "ECC",
                    _ => "Ed"
                };
                return c.PublicKey.Oid.FriendlyName == frName;
            })
            .FirstOrDefault();
        }
    }

    // Get some certificate from PFX store for testing
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
