
using CryptoEx.Ed;
using CryptoEx.Ed.EdDH;
using System.Security.Cryptography;
using System.Text;

namespace CryptoEx.Tests;
public class TestEdDH
{
    [Fact(DisplayName = "Test EdDH Get shared secret")]
    public void Test_EdDH_GetShared_Secret()
    {
        // Create some Keys
        EdDH alice = EdDH.Create(EdAlgorithm.X448);
        EdDH bob = EdDH.Create(EdAlgorithm.X448);

        // Check
        Assert.True(bob.GetSharedSecret(alice)
            .SequenceEqual(alice.GetSharedSecret(bob)));

        // Create some Keys
        alice = EdDH.Create(EdAlgorithm.X25519);
        bob = EdDH.Create(EdAlgorithm.X25519);

        // Check
        Assert.True(bob.GetSharedSecret(alice)
            .SequenceEqual(alice.GetSharedSecret(bob)));

        // Do it with spans
        byte[] sharedSecretAlice = new byte[alice.KeySize / 8];
        byte[] sharedSecretBob = new byte[bob.KeySize / 8];

        // Generate
        bob.GetSharedSecret(alice, sharedSecretBob);
        alice.GetSharedSecret(bob, sharedSecretAlice);

        // Check
        Assert.True(sharedSecretBob.SequenceEqual(sharedSecretAlice));

        // Create some Keys
        alice = EdDH.Create(EdAlgorithm.X448);
        bob = EdDH.Create(EdAlgorithm.X448);

        // Do it with spans
        sharedSecretAlice = new byte[alice.KeySize / 8];
        sharedSecretBob = new byte[bob.KeySize / 8];

        // Generate
        bob.GetSharedSecret(alice, sharedSecretBob);
        alice.GetSharedSecret(bob, sharedSecretAlice);

        // Check
        Assert.True(sharedSecretBob.SequenceEqual(sharedSecretAlice));
    }

    [Fact(DisplayName = "Test EdDH Get Bytes")]
    public void Test_EdDH_Get_Bytes()
    {
        // Create some Keys
        EdDH alice = EdDH.Create(EdAlgorithm.X25519);
        EdDH bob = EdDH.Create(EdAlgorithm.X25519);

        // Define buffers
        byte[] aliceBuffer = new byte[64];
        byte[] BobBuffer = new byte[64];

        // Define some context
        byte[] preContext = System.Text.Encoding.UTF8.GetBytes("PreContext bytes");
        byte[] postContext = System.Text.Encoding.UTF8.GetBytes("PostContext bytes");

        // Generate
        int aliceGen = alice.GenerateBytes(bob, SHA512.Create(), aliceBuffer);
        int bobGet = bob.GenerateBytes(alice, SHA512.Create(), BobBuffer);

        Assert.True(aliceGen == 64);
        Assert.Equal(aliceGen, bobGet);
        Assert.True(aliceBuffer.SequenceEqual(BobBuffer));

        // Generate
        aliceGen = alice.GenerateBytes(bob, SHA512.Create(), preContext, postContext, aliceBuffer);
        bobGet = bob.GenerateBytes(alice, SHA512.Create(), preContext, postContext, BobBuffer);

        Assert.True(aliceGen == 64);
        Assert.Equal(aliceGen, bobGet);
        Assert.True(aliceBuffer.SequenceEqual(BobBuffer));

        // Create some Keys
        alice = EdDH.Create(EdAlgorithm.X448);
        bob = EdDH.Create(EdAlgorithm.X448);

        // try with small buffers
        Array.Fill<byte>(aliceBuffer, 0);
        Array.Fill<byte>(BobBuffer, 0);

        // Generate 
        aliceGen = alice.GenerateBytes(bob, SHA384.Create(), preContext, postContext, aliceBuffer);
        bobGet = bob.GenerateBytes(alice, SHA384.Create(), preContext, postContext, BobBuffer);

        Assert.True(aliceGen == 48);
        Assert.Equal(aliceGen, bobGet);
        Assert.True(aliceBuffer.SequenceEqual(BobBuffer));

        // try with HMAC
        HMACSHA512 hmac = new(System.Text.Encoding.UTF8.GetBytes("Some shared password for Alice and Bob"));

        // Generate
        aliceGen = alice.GenerateBytes(bob, hmac, preContext, postContext, aliceBuffer);
        bobGet = bob.GenerateBytes(alice, hmac, preContext, postContext, BobBuffer);

        Assert.True(aliceGen == 64);
        Assert.Equal(aliceGen, bobGet);
        Assert.True(aliceBuffer.SequenceEqual(BobBuffer));
    }

    [Fact(DisplayName = "Test EdDH Get Bytes NISP's way, with a KDM function")]
    public void Test_EdDH_Get_Bytes_KDM()
    {
        // Create some Keys
        EdDH alice = EdDH.Create(EdAlgorithm.X25519);
        EdDH bob = EdDH.Create(EdAlgorithm.X25519);

        // Define buffers
        byte[] aliceBuffer = new byte[512];
        byte[] BobBuffer = new byte[512];

        // Define some context
        byte[] context = System.Text.Encoding.UTF8.GetBytes("Shared context bytes");

        // Generate
        int aliceGen = alice.GenerateBytesKDM(bob, SHA256.Create(), context, aliceBuffer);
        int bobGet = bob.GenerateBytesKDM(alice, SHA256.Create(), context, BobBuffer);

        Assert.True(aliceGen == 512);
        Assert.Equal(aliceGen, bobGet);
        Assert.True(aliceBuffer.SequenceEqual(BobBuffer));

        // try with empty context
        aliceGen = alice.GenerateBytesKDM(bob, SHA256.Create(), Array.Empty<byte>(), aliceBuffer);
        bobGet = bob.GenerateBytesKDM(alice, SHA256.Create(), Array.Empty<byte>(), BobBuffer);

        Assert.True(aliceGen == 512);
        Assert.Equal(aliceGen, bobGet);
        Assert.True(aliceBuffer.SequenceEqual(BobBuffer));

        // large buffers
        aliceBuffer = new byte[5432];
        BobBuffer = new byte[5432];

        // Generate
        aliceGen = alice.GenerateBytesKDM(bob, SHA256.Create(), context, aliceBuffer);
        bobGet = bob.GenerateBytesKDM(alice, SHA256.Create(), context, BobBuffer);

        Assert.True(aliceGen == 5432);
        Assert.Equal(aliceGen, bobGet);
        Assert.True(aliceBuffer.SequenceEqual(BobBuffer));

        // X448
        alice = EdDH.Create(EdAlgorithm.X448);
        bob = EdDH.Create(EdAlgorithm.X448);

        // Generate
        aliceGen = alice.GenerateBytesKDM(bob, SHA384.Create(), context, aliceBuffer);
        bobGet = bob.GenerateBytesKDM(alice, SHA384.Create(), context, BobBuffer);

        Assert.True(aliceGen == 5432);
        Assert.Equal(aliceGen, bobGet);
        Assert.True(aliceBuffer.SequenceEqual(BobBuffer));
    }

    [Fact(DisplayName = "Test EdDH Get Bytes NISP's way and actually encrypt / decrypt with AES")]
    public void Test_EdDH_AES_X25519()
    {
        // Create some asymetric keys
        EdDH alice = EdDH.Create(EdAlgorithm.X25519);
        EdDH bob = EdDH.Create(EdAlgorithm.X25519);

        // Define symmetric keys & nonce values
        byte[] bobsKey = new byte[44];
        byte[] aliceKey = new byte[44];

        // Define some shared context and text
        byte[] context = Encoding.UTF8.GetBytes("Shared context bytes");
        string palinText = "This is a test string to encrypt and decrypt";

        // Define buffers
        byte[] cypher = new byte[palinText.Length];
        byte[] decryptResult = new byte[palinText.Length];
        byte[] tag = new byte[16];

        // Generate Bob's simetric key
        int bobGet = bob.GenerateBytesKDM(alice, SHA256.Create(), context, bobsKey);
        Assert.True(bobGet == 44);

        // Create AES
        AesGcm aesBob = new(bobsKey[..32]);

        // Encrypt
        aesBob.Encrypt(bobsKey[32..], Encoding.UTF8.GetBytes(palinText), cypher, tag);

        // Generate Alice's simetric key
        int aliceGen = alice.GenerateBytesKDM(bob, SHA256.Create(), context, aliceKey);
        Assert.True(aliceGen == 44);

        // Create AES
        AesGcm aesAlice = new(aliceKey[..32]);

        // Decrypt
        aesAlice.Decrypt(aliceKey[32..], cypher, tag, decryptResult);

        // Check if the result is the same
        Assert.True(palinText.CompareTo(Encoding.UTF8.GetString(decryptResult)) == 0);
    }

    [Fact(DisplayName = "Test EdDH Get Bytes NISP's way and actually encrypt / decrypt with ChaCha")]
    public void Test_EdDH_ChaCha_X25519()
    {
        // Create some asymetric keys
        EdDH alice = EdDH.Create(EdAlgorithm.X25519);
        EdDH bob = EdDH.Create(EdAlgorithm.X25519);

        // Define symmetric keys & nonce values
        byte[] bobsKey = new byte[44];
        byte[] aliceKey = new byte[44];

        // Define some shared context and text
        byte[] context = Encoding.UTF8.GetBytes("Shared context bytes");
        string palinText = "This is a test string to encrypt and decrypt";

        // Define buffers
        byte[] cypher = new byte[palinText.Length];
        byte[] decryptResult = new byte[palinText.Length];
        byte[] tag = new byte[16];

        // Generate Bob's simetric key
        int bobGet = bob.GenerateBytesKDM(alice, SHA256.Create(), context, bobsKey);
        Assert.True(bobGet == 44);

        // Create ChaCha
        ChaCha20Poly1305 chaBob = new(bobsKey[..32]);

        // Encrypt
        chaBob.Encrypt(bobsKey[32..], Encoding.UTF8.GetBytes(palinText), cypher, tag);

        // Generate Alice's simetric key
        int aliceGen = alice.GenerateBytesKDM(bob, SHA256.Create(), context, aliceKey);
        Assert.True(aliceGen == 44);

        // Create ChaCha
        ChaCha20Poly1305 aesAlice = new(aliceKey[..32]);

        // Decrypt
        aesAlice.Decrypt(aliceKey[32..], cypher, tag, decryptResult);

        // Check if the result is the same
        Assert.True(palinText.CompareTo(Encoding.UTF8.GetString(decryptResult)) == 0);
    }

    [Fact(DisplayName = "Test EdDH Get Bytes NISP's way and actually encrypt / decrypt with AES and X448")]
    public void Test_EdDH_AES_X448()
    {
        // Create some asymetric keys
        EdDH alice = EdDH.Create(EdAlgorithm.X448);
        EdDH bob = EdDH.Create(EdAlgorithm.X448);

        // Define symmetric keys & nonce values
        byte[] bobsKey = new byte[44];
        byte[] aliceKey = new byte[44];

        // Define some shared context and text
        byte[] context = Encoding.UTF8.GetBytes("Shared context bytes");
        string palinText = "This is a test string to encrypt and decrypt";

        // Define buffers
        byte[] cypher = new byte[palinText.Length];
        byte[] decryptResult = new byte[palinText.Length];
        byte[] tag = new byte[16];

        // Generate Bob's simetric key
        int bobGet = bob.GenerateBytesKDM(alice, SHA256.Create(), context, bobsKey);
        Assert.True(bobGet == 44);

        // Create AES
        AesGcm aesBob = new(bobsKey[..32]);

        // Encrypt
        aesBob.Encrypt(bobsKey[32..], Encoding.UTF8.GetBytes(palinText), cypher, tag);

        // Generate Alice's simetric key
        int aliceGen = alice.GenerateBytesKDM(bob, SHA256.Create(), context, aliceKey);
        Assert.True(aliceGen == 44);

        // Create AES
        AesGcm aesAlice = new(aliceKey[..32]);

        // Decrypt
        aesAlice.Decrypt(aliceKey[32..], cypher, tag, decryptResult);

        // Check if the result is the same
        Assert.True(palinText.CompareTo(Encoding.UTF8.GetString(decryptResult)) == 0);
    }

    [Fact(DisplayName = "Test EdDH Get Bytes NISP's way and actually encrypt / decrypt with ChaCha and X448")]
    public void Test_EdDH_ChaCha_X448()
    {
        // Create some asymetric keys
        EdDH alice = EdDH.Create(EdAlgorithm.X448);
        EdDH bob = EdDH.Create(EdAlgorithm.X448);

        // Define symmetric keys & nonce values
        byte[] bobsKey = new byte[44];
        byte[] aliceKey = new byte[44];

        // Define some shared context and text
        byte[] context = Encoding.UTF8.GetBytes("Shared context bytes");
        string palinText = "This is a test string to encrypt and decrypt";

        // Define buffers
        byte[] cypher = new byte[palinText.Length];
        byte[] decryptResult = new byte[palinText.Length];
        byte[] tag = new byte[16];

        // Generate Bob's simetric key
        int bobGet = bob.GenerateBytesKDM(alice, SHA256.Create(), context, bobsKey);
        Assert.True(bobGet == 44);

        // Create ChaCha
        ChaCha20Poly1305 chaBob = new(bobsKey[..32]);

        // Encrypt
        chaBob.Encrypt(bobsKey[32..], Encoding.UTF8.GetBytes(palinText), cypher, tag);

        // Generate Alice's simetric key
        int aliceGen = alice.GenerateBytesKDM(bob, SHA256.Create(), context, aliceKey);
        Assert.True(aliceGen == 44);

        // Create ChaCha
        ChaCha20Poly1305 aesAlice = new(aliceKey[..32]);

        // Decrypt
        aesAlice.Decrypt(aliceKey[32..], cypher, tag, decryptResult);

        // Check if the result is the same
        Assert.True(palinText.CompareTo(Encoding.UTF8.GetString(decryptResult)) == 0);
    }
}
