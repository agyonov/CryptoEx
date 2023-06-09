
using CryptoEx.Ed.EdDH;
using CryptoEx.Ed;

namespace CryptoEx.Tests;
public class TestEdDH
{
    [Fact(DisplayName = "Test EdDH Get shared secret")]
    public void Test_EdDH_GetShared_secret()
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
}
