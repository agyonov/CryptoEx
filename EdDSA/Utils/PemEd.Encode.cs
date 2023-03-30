using System.Formats.Asn1;

namespace EdDSA.Utils;
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
