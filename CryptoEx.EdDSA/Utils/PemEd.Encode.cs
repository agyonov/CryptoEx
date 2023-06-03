using CryptoEx.Utils;
using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;

namespace CryptoEx.EdDSA.Utils;
public static partial class PemEd
{
    /// <summary>
    /// Encode a Ed25519 private key to a PEM
    /// </summary>
    /// <param name="prKey">The Ed25519 private key</param>
    /// <returns>The PEM Encoded private key </returns>
    public static string WriteEd25519PrivateKey(ReadOnlySpan<byte> prKey)
    {
        // local res
        string pemResult = string.Empty;

        // Create writer
        AsnWriter writer = new AsnWriter(AsnEncodingRules.DER);

        // OneAsymetricKey
        using (writer.PushSequence()) {
            // Version
            writer.WriteInteger(0);
            // PrivateKeyAlgorithmIdentifier
            using (writer.PushSequence()) {
                // OID of the algorithm
                writer.WriteObjectIdentifier(OidEd25519.Value ?? string.Empty);
            }
            // PrivateKey
            using (writer.PushOctetString()) {
                writer.WriteOctetString(prKey);
            }
        }

        // Encode
        PEMObject pEM = new PEMObject()
        {
            Type = PRIVATE_KEY,
            Content = writer.Encode()
        };

        // Write in PEM format
        using (TextWriter textWriter = new StringWriter()) {
            // Write in PEM
            PEMReaderWriter.WritePEM(new PEMObject[] { pEM }, textWriter);

            // Set result
            textWriter.Flush();
            pemResult = textWriter.ToString() ?? string.Empty;
        }

        // return
        return pemResult;
    }

    /// <summary>
    /// Encode a Ed25519 private key to an encrypted PEM - PKCS8
    /// </summary>
    /// <param name="prKey">The Ed25519 private key</param>
    /// <param name="password">The password to use for encryption of the key</param>
    /// <returns>The PEM Encoded private key </returns>
    public static string WriteEd25519PrivateKey(ReadOnlySpan<byte> prKey, string password)
    {
        // local res
        string pemResult = string.Empty;

        // Create writer
        AsnWriter writer = new AsnWriter(AsnEncodingRules.DER);

        // PrivateKey
        writer.WriteOctetString(prKey);

        // Define some packaging
        Pkcs8PrivateKeyInfo pkcs8 = new Pkcs8PrivateKeyInfo(OidEd25519, null, writer.Encode());

        // Encode
        PEMObject pEM = new PEMObject()
        {
            Type = ENCRYPTED_PRIVATE_KEY,
            Content = pkcs8.Encrypt(password, new PbeParameters(PbeEncryptionAlgorithm.Aes256Cbc, HashAlgorithmName.SHA256, 2048))
        };

        // Write in PEM format
        using (TextWriter textWriter = new StringWriter()) {
            // Write in PEM
            PEMReaderWriter.WritePEM(new PEMObject[] { pEM }, textWriter);

            // Set result
            textWriter.Flush();
            pemResult = textWriter.ToString() ?? string.Empty;
        }

        // return
        return pemResult;
    }

    /// <summary>
    /// Encode a Ed25519 public key to a PEM
    /// </summary>
    /// <param name="pubKey">The Ed25519 public key</param>
    /// <returns>The PEM Encoded public key </returns>
    public static string WriteEd25519PublicKey(ReadOnlySpan<byte> pubKey)
    {
        // local res
        string pemResult = string.Empty;

        // Create writer
        AsnWriter writer = new AsnWriter(AsnEncodingRules.DER);

        // OneAsymetricKey
        using (writer.PushSequence()) {
            // PrivateKeyAlgorithmIdentifier
            using (writer.PushSequence()) {
                // OID of the algorithm
                writer.WriteObjectIdentifier(OidEd25519.Value ?? string.Empty);
            }
            // Publickey
            writer.WriteBitString(pubKey);
        }

        // Encode
        PEMObject pEM = new PEMObject()
        {
            Type = PUBLIC_KEY,
            Content = writer.Encode()
        };

        // Write in PEM format
        using (TextWriter textWriter = new StringWriter()) {
            // Write in PEM
            PEMReaderWriter.WritePEM(new PEMObject[] { pEM }, textWriter);

            // Set result
            textWriter.Flush();
            pemResult = textWriter.ToString() ?? string.Empty;
        }

        // return
        return pemResult;
    }

    /// <summary>
    /// Encode a Ed448 private key to a PEM
    /// </summary>
    /// <param name="prKey">The Ed448 private key</param>
    /// <returns>The PEM Encoded private key </returns>
    public static string WriteEd448PrivateKey(ReadOnlySpan<byte> prKey)
    {
        // local res
        string pemResult = string.Empty;

        // Create writer
        AsnWriter writer = new AsnWriter(AsnEncodingRules.DER);

        // OneAsymetricKey
        using (writer.PushSequence()) {
            // Version
            writer.WriteInteger(0);
            // PrivateKeyAlgorithmIdentifier
            using (writer.PushSequence()) {
                // OID of the algorithm
                writer.WriteObjectIdentifier(OidEd448.Value ?? string.Empty);
            }
            // PrivateKey
            using (writer.PushOctetString()) {
                writer.WriteOctetString(prKey);
            }
        }

        // Encode
        PEMObject pEM = new PEMObject()
        {
            Type = PRIVATE_KEY,
            Content = writer.Encode()
        };

        // Write in PEM format
        using (TextWriter textWriter = new StringWriter()) {
            // Write in PEM
            PEMReaderWriter.WritePEM(new PEMObject[] { pEM }, textWriter);

            // Set result
            textWriter.Flush();
            pemResult = textWriter.ToString() ?? string.Empty;
        }

        // return
        return pemResult;
    }

    /// <summary>
    /// Encode a Ed448 private key to an encrypted PEM - PKCS 8
    /// </summary>
    /// <param name="prKey">The Ed448 private key</param>
    /// <param name="password">The password to use for encryption of the key</param>
    /// <returns>The PEM Encoded private key </returns>
    public static string WriteEd448PrivateKey(ReadOnlySpan<byte> prKey, string password)
    {
        // local res
        string pemResult = string.Empty;

        // Create writer
        AsnWriter writer = new AsnWriter(AsnEncodingRules.DER);

        // PrivateKey
        writer.WriteOctetString(prKey);

        // Define some packaging
        Pkcs8PrivateKeyInfo pkcs8 = new Pkcs8PrivateKeyInfo(OidEd448, null, writer.Encode());

        // Encode
        PEMObject pEM = new PEMObject()
        {
            Type = ENCRYPTED_PRIVATE_KEY,
            Content = pkcs8.Encrypt(password, new PbeParameters(PbeEncryptionAlgorithm.Aes256Cbc, HashAlgorithmName.SHA256, 2048))
        };

        // Write in PEM format
        using (TextWriter textWriter = new StringWriter()) {
            // Write in PEM
            PEMReaderWriter.WritePEM(new PEMObject[] { pEM }, textWriter);

            // Set result
            textWriter.Flush();
            pemResult = textWriter.ToString() ?? string.Empty;
        }

        // return
        return pemResult;
    }

    /// <summary>
    /// Encode a Ed448 public key to a PEM
    /// </summary>
    /// <param name="pubKey">The Ed448 public key</param>
    /// <returns>The PEM Encoded public key </returns>
    public static string WriteEd448PublicKey(ReadOnlySpan<byte> pubKey)
    {
        // local res
        string pemResult = string.Empty;

        // Create writer
        AsnWriter writer = new AsnWriter(AsnEncodingRules.DER);

        // OneAsymetricKey
        using (writer.PushSequence()) {
            // PrivateKeyAlgorithmIdentifier
            using (writer.PushSequence()) {
                // OID of the algorithm
                writer.WriteObjectIdentifier(OidEd448.Value ?? string.Empty);
            }
            // Publickey
            writer.WriteBitString(pubKey);
        }

        // Encode
        PEMObject pEM = new PEMObject()
        {
            Type = PUBLIC_KEY,
            Content = writer.Encode()
        };

        // Write in PEM format
        using (TextWriter textWriter = new StringWriter()) {
            // Write in PEM
            PEMReaderWriter.WritePEM(new PEMObject[] { pEM }, textWriter);

            // Set result
            textWriter.Flush();
            pemResult = textWriter.ToString() ?? string.Empty;
        }

        // return
        return pemResult;
    }
}
