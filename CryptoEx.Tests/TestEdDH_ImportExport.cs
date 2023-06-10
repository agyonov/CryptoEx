using CryptoEx.Ed;
using CryptoEx.Ed.EdDH;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace CryptoEx.Tests;

public class TestEdDH_ImportExport
{
    [Fact(DisplayName = "Get public key from Crt/Cer File")]
    public void TestGetPublicKeyFromCrt()
    {
        using (FileStream fs = File.Open(@"source\x25519.crt", FileMode.Open, FileAccess.Read, FileShare.Read)) {
            X509Certificate2? cert = fs.LoadEdCertificateFromCrt();

            // Check
            Assert.NotNull(cert);

            // Get public key
            EdDH? edDH = cert.GetEdDHPublicKey();

            // Check
            Assert.NotNull(edDH);
        }

        using (FileStream fs = File.Open(@"source\x448.crt", FileMode.Open, FileAccess.Read, FileShare.Read)) {
            X509Certificate2? cert = fs.LoadEdCertificateFromCrt();

            // Check
            Assert.NotNull(cert);

            // Get public key
            EdDH? edDH = cert.GetEdDHPublicKey();

            // Check
            Assert.NotNull(edDH);
        }
    }

    [Fact(DisplayName = "Get private key from Pfx/P12 File")]
    public void TestGetPrivateKeyFromPfx()
    {
        using (FileStream fs = File.Open(@"source\x25519.pfx", FileMode.Open, FileAccess.Read, FileShare.Read)) {
            X509Certificate2Ed[] certs = fs.LoadEdCertificatesFromPfx("pass.123");

            // Check
            Assert.NotEmpty(certs);

            // Get private key
            EdDH? edDH = certs[0].GetEdDHPrivateKey();

            // Check
            Assert.NotNull(edDH);
        }

        using (FileStream fs = File.Open(@"source\x448.pfx", FileMode.Open, FileAccess.Read, FileShare.Read)) {
            X509Certificate2Ed[] certs = fs.LoadEdCertificatesFromPfx("pass.123");

            // Check
            Assert.NotEmpty(certs);

            // Get private key
            EdDH? edDH = certs[0].GetEdDHPrivateKey();

            // Check
            Assert.NotNull(edDH);
        }
    }

    [Fact(DisplayName = "Get private key from PEM")]
    public void TestGetPrivateKeyFromPem()
    {
        // Create EdDH
        EdDH edDH = EdDH.Create();
        EdDH alice = EdDH.Create();

        // Read private key from PEM
        using (FileStream fs = File.Open(@"source\x25519.key", FileMode.Open, FileAccess.Read, FileShare.Read))
        using (StreamReader sr = new(fs)) {
            // Import
            edDH.ImportFromPem(sr.ReadToEnd());

            // Generate one pair
            byte[] edBytes = new byte[32];
            int edCount = edDH.GenerateBytes(alice, SHA256.Create(), edBytes);
            Assert.Equal(32, edCount);

            byte[] aliceBytes = new byte[32];
            int aliceCount = alice.GenerateBytes(edDH, SHA256.Create(), aliceBytes);
            Assert.Equal(32, aliceCount);

            // Check
            Assert.True(aliceBytes.SequenceEqual(edBytes));
        }

        // Create new one
        alice = EdDH.Create(EdAlgorithm.X448);

        // Read private key from PEM
        using (FileStream fs = File.Open(@"source\x448.key", FileMode.Open, FileAccess.Read, FileShare.Read))
        using (StreamReader sr = new(fs)) {
            // Import
            edDH.ImportFromPem(sr.ReadToEnd());

            // Generate one pair
            byte[] edBytes = new byte[64];
            int edCount = edDH.GenerateBytes(alice, SHA512.Create(), edBytes);
            Assert.Equal(64, edCount);

            byte[] aliceBytes = new byte[64];
            int aliceCount = alice.GenerateBytes(edDH, SHA512.Create(), aliceBytes);
            Assert.Equal(64, aliceCount);

            // Check
            Assert.True(aliceBytes.SequenceEqual(edBytes));
        }
    }

    [Fact(DisplayName = "Get private key from encrypted PEM")]
    public void TestGetPrivateKeyFromPemEncripted()
    {
        // Create EdDH
        EdDH edDH = EdDH.Create();
        EdDH alice = EdDH.Create();

        // Read private key from PEM
        using (FileStream fs = File.Open(@"source\x25519.pem", FileMode.Open, FileAccess.Read, FileShare.Read))
        using (StreamReader sr = new(fs)) {
            // Import
            edDH.ImportFromEncryptedPem(sr.ReadToEnd(), "pass.123");

            // Generate one pair
            byte[] edBytes = new byte[32];
            int edCount = edDH.GenerateBytes(alice, SHA256.Create(), edBytes);
            Assert.Equal(32, edCount);

            byte[] aliceBytes = new byte[32];
            int aliceCount = alice.GenerateBytes(edDH, SHA256.Create(), aliceBytes);
            Assert.Equal(32, aliceCount);

            // Check
            Assert.True(aliceBytes.SequenceEqual(edBytes));
        }

        // Create new one
        alice = EdDH.Create(EdAlgorithm.X448);

        // Read private key from PEM
        using (FileStream fs = File.Open(@"source\x448.pem", FileMode.Open, FileAccess.Read, FileShare.Read))
        using (StreamReader sr = new(fs)) {
            // Import
            edDH.ImportFromEncryptedPem(sr.ReadToEnd(), "pass.123");

            // Generate one pair
            byte[] edBytes = new byte[64];
            int edCount = edDH.GenerateBytes(alice, SHA512.Create(), edBytes);
            Assert.Equal(64, edCount);

            byte[] aliceBytes = new byte[64];
            int aliceCount = alice.GenerateBytes(edDH, SHA512.Create(), aliceBytes);
            Assert.Equal(64, aliceCount);

            // Check
            Assert.True(aliceBytes.SequenceEqual(edBytes));
        }
    }

    [Fact(DisplayName = "Get public key from PEM")]
    public void TestGetPublicKeyFromPemAndVerify()
    {
        // Create EdDH
        EdDH edDH = EdDH.Create();
        EdDH alice = EdDH.Create();

        // Read private key from PEM
        using (FileStream fs = File.Open(@"source\x25519.pub", FileMode.Open, FileAccess.Read, FileShare.Read))
        using (StreamReader sr = new(fs)) {
            // Import
            edDH.ImportFromPem(sr.ReadToEnd());

            // Generate one pair
            byte[] edBytes = new byte[32];
            int edCount = alice.GenerateBytes(edDH, SHA256.Create(), edBytes);
            Assert.Equal(32, edCount);
        }

        alice = EdDH.Create(EdAlgorithm.X448);

        // Read private key from PEM
        using (FileStream fs = File.Open(@"source\x448.pub", FileMode.Open, FileAccess.Read, FileShare.Read))
        using (StreamReader sr = new(fs)) {
            // Import
            edDH.ImportFromPem(sr.ReadToEnd());

            // Generate one pair
            byte[] edBytes = new byte[64];
            int edCount = alice.GenerateBytes(edDH, SHA512.Create(), edBytes);
            Assert.Equal(64, edCount);
        }
    }
}
