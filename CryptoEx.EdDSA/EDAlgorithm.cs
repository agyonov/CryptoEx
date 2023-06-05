
using CryptoEx.Ed.Utils;
using CryptoEx.Utils;
using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;

namespace CryptoEx.Ed;


/// <summary>
/// Root abstact Class for EdDsa and EdDiffieHellman (EdDH)
/// Extends AsymmetricAlgorithm
/// </summary>
public abstract class EDAlgorithm : AsymmetricAlgorithm
{
    /// <summary>
    /// When overridden in a derived class, exports the parameters for the algorithm.
    /// </summary>
    /// <param name="includePrivateParameters">
    ///   <see langword="true" /> to include private parameters, otherwise, <see langword="false" />.
    /// </param>
    /// <returns>The exported parameters.</returns>
    public abstract EDParameters ExportParameters(bool includePrivateParameters);

    /// <summary>
    /// When overridden in a derived class, imports the specified <see cref="ECParameters" />.
    /// </summary>
    /// <param name="parameters">The curve parameters.</param>
    public abstract void ImportParameters(EDParameters parameters);

    /// <summary>
    /// Export the private key as a PKCS8 with password
    /// </summary>
    /// <param name="password">The password</param>
    /// <param name="pbeParameters">Pbe parameters</param>
    /// <returns>The Pkcs8 </returns>
    public override byte[] ExportEncryptedPkcs8PrivateKey(ReadOnlySpan<char> password, PbeParameters pbeParameters)
    {
        // Create writer
        AsnWriter writer = new AsnWriter(AsnEncodingRules.DER);

        // Get the private key
        EDParameters eDParameters = ExportParameters(true);

        // PrivateKey
        writer.WriteOctetString(eDParameters.D);

        // Define some packaging
        Pkcs8PrivateKeyInfo pkcs8 = new Pkcs8PrivateKeyInfo(eDParameters.Crv, null, writer.Encode());

        // Encrypt
        return pkcs8.Encrypt(password, pbeParameters);
    }

    /// <summary>
    /// Export the private key as a PKCS8 with password
    /// </summary>
    /// <param name="password">The password</param>
    /// <param name="pbeParameters">Pbe parameters</param>
    /// <returns>The Pkcs8 </returns>
    public override byte[] ExportEncryptedPkcs8PrivateKey(ReadOnlySpan<byte> passwordBytes, PbeParameters pbeParameters)
    {
        // Create writer
        AsnWriter writer = new AsnWriter(AsnEncodingRules.DER);

        // Get the private key
        EDParameters eDParameters = ExportParameters(true);

        // PrivateKey
        writer.WriteOctetString(eDParameters.D);

        // Define some packaging
        Pkcs8PrivateKeyInfo pkcs8 = new Pkcs8PrivateKeyInfo(eDParameters.Crv, null, writer.Encode());

        // Encrypt
        return pkcs8.Encrypt(passwordBytes, pbeParameters);
    }

    /// <summary>
    /// Exports the current key in the PKCS#8 PrivateKeyInfo format
    /// </summary>
    /// <returns>The PKCS8 private key</returns>
    public override byte[] ExportPkcs8PrivateKey()
    {
        // Create writer
        AsnWriter writer = new AsnWriter(AsnEncodingRules.DER);

        // Get the private key
        EDParameters eDParameters = ExportParameters(true);

        // OneAsymetricKey
        using (writer.PushSequence())
        {
            // Version
            writer.WriteInteger(0);
            // PrivateKeyAlgorithmIdentifier
            using (writer.PushSequence())
            {
                // OID of the algorithm
                writer.WriteObjectIdentifier(eDParameters.Crv.Value ?? string.Empty);
            }
            // PrivateKey
            using (writer.PushOctetString())
            {
                writer.WriteOctetString(eDParameters.D);
            }
        }

        // Encode
        return writer.Encode();
    }

    /// <summary>
    /// Exports the public key part in the SubjectPublicKeyInfo format
    /// </summary>
    /// <returns>The public Key</returns>
    public override byte[] ExportSubjectPublicKeyInfo()
    {
        // Create writer
        AsnWriter writer = new AsnWriter(AsnEncodingRules.DER);

        // Get the private key
        EDParameters eDParameters = ExportParameters(false);

        // OneAsymetricKey
        using (writer.PushSequence())
        {
            // PrivateKeyAlgorithmIdentifier
            using (writer.PushSequence())
            {
                // OID of the algorithm
                writer.WriteObjectIdentifier(eDParameters.Crv.Value ?? string.Empty);
            }
            // Publickey
            writer.WriteBitString(eDParameters.X);
        }

        // Encode
        return writer.Encode();
    }

    /// <summary>
    /// Try to Exports the current key in the PKCS#8 PrivateKeyInfo format
    /// </summary>
    /// <param name="passwordBytes">The password</param>
    /// <param name="pbeParameters">The encryption parameters</param>
    /// <param name="destination">Result</param>
    /// <param name="bytesWritten">Number of bytes written</param>
    /// <returns>True / false - success error</returns>
    public override bool TryExportEncryptedPkcs8PrivateKey(ReadOnlySpan<byte> passwordBytes, PbeParameters pbeParameters, Span<byte> destination, out int bytesWritten)
    {
        // Create writer
        AsnWriter writer = new AsnWriter(AsnEncodingRules.DER);

        // Get the private key
        EDParameters eDParameters = ExportParameters(true);

        // PrivateKey
        writer.WriteOctetString(eDParameters.D);

        // Define some packaging
        Pkcs8PrivateKeyInfo pkcs8 = new Pkcs8PrivateKeyInfo(eDParameters.Crv, null, writer.Encode());

        // Encrypt
        return pkcs8.TryEncrypt(passwordBytes, pbeParameters, destination, out bytesWritten);
    }

    /// <summary>
    /// Try to Exports the current key in the PKCS#8 PrivateKeyInfo format
    /// </summary>
    /// <param name="passwordBytes">The password</param>
    /// <param name="pbeParameters">The encryption parameters</param>
    /// <param name="destination">Result</param>
    /// <param name="bytesWritten">Number of bytes written</param>
    /// <returns>True / false - success error</returns>
    public override bool TryExportEncryptedPkcs8PrivateKey(ReadOnlySpan<char> password, PbeParameters pbeParameters, Span<byte> destination, out int bytesWritten)
    {
        // Create writer
        AsnWriter writer = new AsnWriter(AsnEncodingRules.DER);

        // Get the private key
        EDParameters eDParameters = ExportParameters(true);

        // PrivateKey
        writer.WriteOctetString(eDParameters.D);

        // Define some packaging
        Pkcs8PrivateKeyInfo pkcs8 = new Pkcs8PrivateKeyInfo(eDParameters.Crv, null, writer.Encode());

        // Encrypt
        return pkcs8.TryEncrypt(password, pbeParameters, destination, out bytesWritten);
    }

    /// <summary>
    /// Exports the current key in the PKCS#8 PrivateKeyInfo format
    /// </summary>
    /// <param name="destination">Result</param>
    /// <param name="bytesWritten">Number of bytes written</param>
    /// <returns>True / false - success error</returns>
    public override bool TryExportPkcs8PrivateKey(Span<byte> destination, out int bytesWritten)
    {
        // Create writer
        AsnWriter writer = new AsnWriter(AsnEncodingRules.DER);

        // Get the private key
        EDParameters eDParameters = ExportParameters(true);

        // OneAsymetricKey
        using (writer.PushSequence())
        {
            // Version
            writer.WriteInteger(0);
            // PrivateKeyAlgorithmIdentifier
            using (writer.PushSequence())
            {
                // OID of the algorithm
                writer.WriteObjectIdentifier(eDParameters.Crv.Value ?? string.Empty);
            }
            // PrivateKey
            using (writer.PushOctetString())
            {
                writer.WriteOctetString(eDParameters.D);
            }
        }

        // Encode
        return writer.TryEncode(destination, out bytesWritten);
    }

    /// <summary>
    /// Exports the public key part in the SubjectPublicKeyInfo format
    /// </summary>
    /// <returns>The public Key</returns>
    public override bool TryExportSubjectPublicKeyInfo(Span<byte> destination, out int bytesWritten)
    {
        // Create writer
        AsnWriter writer = new AsnWriter(AsnEncodingRules.DER);

        // Get the private key
        EDParameters eDParameters = ExportParameters(false);

        // OneAsymetricKey
        using (writer.PushSequence())
        {
            // PrivateKeyAlgorithmIdentifier
            using (writer.PushSequence())
            {
                // OID of the algorithm
                writer.WriteObjectIdentifier(eDParameters.Crv.Value ?? string.Empty);
            }
            // Publickey
            writer.WriteBitString(eDParameters.X);
        }

        // Encode
        return writer.TryEncode(destination, out bytesWritten);
    }

    /// <summary>
    /// Imports the private keypair from a PKCS#8 EncryptedPrivateKeyInfo
    /// structure after decrypting with a byte-based password, replacing the
    /// keys for this object.
    /// </summary>
    /// <param name="passwordBytes">The bytes to use as a password when decrypting the key material.</param>
    /// <param name="source">
    /// The bytes of a PKCS#8 EncryptedPrivateKeyInfo structure in the ASN.1-BER encoding.
    /// </param>
    /// <param name="bytesRead">
    /// When this method returns, contains a value that indicates the number
    /// of bytes read from <paramref name="source" />. This parameter is treated as uninitialized.
    /// </param>
    public override void ImportEncryptedPkcs8PrivateKey(ReadOnlySpan<byte> passwordBytes, ReadOnlySpan<byte> source, out int bytesRead)
    {
        // Pfu
        byte[] pfu = source.ToArray();

        // Try to decrypt
        Pkcs8PrivateKeyInfo dcr = Pkcs8PrivateKeyInfo.DecryptAndDecode(passwordBytes, pfu, out bytesRead);

        // Create the parameters
        EDParameters eDParameters = new EDParameters
        {
            Crv = dcr.AlgorithmId,
            D = dcr.PrivateKeyBytes.Span[2..].ToArray()
        };

        // Import
        ImportParameters(eDParameters);
    }

    /// <summary>
    /// Imports the private keypair from a PKCS#8 EncryptedPrivateKeyInfo
    /// structure after decrypting with a byte-based password, replacing the
    /// keys for this object.
    /// </summary>
    /// <param name="passwordBytes">The bytes to use as a password when decrypting the key material.</param>
    /// <param name="source">
    /// The bytes of a PKCS#8 EncryptedPrivateKeyInfo structure in the ASN.1-BER encoding.
    /// </param>
    /// <param name="bytesRead">
    /// When this method returns, contains a value that indicates the number
    /// of bytes read from <paramref name="source" />. This parameter is treated as uninitialized.
    /// </param>
    public override void ImportEncryptedPkcs8PrivateKey(ReadOnlySpan<char> password, ReadOnlySpan<byte> source, out int bytesRead)
    {
        // Pfu
        byte[] pfu = source.ToArray();

        // Try to decrypt
        Pkcs8PrivateKeyInfo dcr = Pkcs8PrivateKeyInfo.DecryptAndDecode(password, pfu, out bytesRead);

        // Create the parameters
        EDParameters eDParameters = new EDParameters
        {
            Crv = dcr.AlgorithmId,
            D = dcr.PrivateKeyBytes.Span[2..].ToArray()
        };

        // Import
        ImportParameters(eDParameters);
    }

    /// <summary>
    /// Imports the private key from a PKCS#8 PrivateKeyInfo structure
    /// after decryption, replacing the keys for this object.
    /// </summary>
    /// <param name="source">The bytes of a PKCS#8 PrivateKeyInfo structure in the ASN.1-DER encoding.</param>
    /// <param name="bytesRead">
    /// When this method returns, contains a value that indicates the number
    /// of bytes read from <paramref name="source" />. This parameter is treated as uninitialized.
    /// </param>
    public override void ImportPkcs8PrivateKey(ReadOnlySpan<byte> source, out int bytesRead)
    {
        // Some helpers
        int offset, len, bytes;

        // Set initially
        bytesRead = 0;

        // Read top sequence
        AsnDecoder.ReadSequence(source, AsnEncodingRules.DER, out offset, out len, out bytes);
        source = source[offset..];
        bytesRead += bytes;

        // Read version & check
        ReadOnlySpan<byte> version = AsnDecoder.ReadIntegerBytes(source, AsnEncodingRules.DER, out bytes);
        if (version.Length != 1 && version[0] != 0)
        {
            throw new CryptographicException($"Verson of ASN.DER is not 0");
        }
        bytesRead += bytes;

        // Go further
        source = source[bytes..];

        // Read algorithm
        AsnDecoder.ReadSequence(source, AsnEncodingRules.DER, out offset, out len, out bytes);
        bytesRead += bytes;

        // Go Further
        var oidSeq = source[offset..(offset + len)];
        source = source[bytes..];

        // Parse OID
        Oid oid = new Oid(AsnDecoder.ReadObjectIdentifier(oidSeq, AsnEncodingRules.DER, out bytes));
        bytesRead += bytes;

        // read key
        byte[] resKey = AsnDecoder.ReadOctetString(source, AsnEncodingRules.DER, out bytes);
        bytesRead += bytes;

        // Create the parameters
        EDParameters eDParameters = new EDParameters
        {
            Crv = oid,
            D = resKey[2..]
        };

        // Import
        ImportParameters(eDParameters);
    }

    /// <summary>
    /// Imports the public key from an Public Key Structire structure
    /// </summary>
    /// <param name="source">The bytes of an Public Key Structire structure in the ASN.1-DER encoding.</param>
    /// <param name="bytesRead">
    /// When this method returns, contains a value that indicates the number
    /// of bytes read from <paramref name="source" />. This parameter is treated as uninitialized.
    /// </param>
    public override void ImportSubjectPublicKeyInfo(ReadOnlySpan<byte> source, out int bytesRead)
    {
        // Some helpers
        int offset, len, bytes;

        // Set initially
        bytesRead = 0;

        // Read top sequence
        AsnDecoder.ReadSequence(source, AsnEncodingRules.DER, out offset, out len, out bytes);
        source = source[offset..];
        bytesRead += bytes;

        // Read algorithm
        AsnDecoder.ReadSequence(source, AsnEncodingRules.DER, out offset, out len, out bytes);
        bytesRead += bytes;

        // Go Further
        var oidSeq = source[offset..(offset + len)];
        source = source[bytes..];

        // Parse OID
        Oid oid = new Oid(AsnDecoder.ReadObjectIdentifier(oidSeq, AsnEncodingRules.DER, out bytes));
        bytesRead += bytes;

        // read key
        byte[] resKey = AsnDecoder.ReadBitString(source, AsnEncodingRules.DER, out len, out bytes);
        bytesRead += bytes;

        // Create the parameters
        EDParameters eDParameters = new EDParameters
        {
            Crv = oid,
            X = resKey
        };

        // Import
        ImportParameters(eDParameters);
    }

    /// <summary>
    /// Imports an RFC 7468 PEM-encoded key, replacing the keys for this object.
    /// </summary>
    /// <param name="input">The PEM text of the key to import.</param>
    public override void ImportFromPem(ReadOnlySpan<char> input)
    {
        // Read it
        using (StringReader reader = new StringReader(input.ToString()))
        {
            // Read PEM object
            ICollection<PEMObject> readRes = PEMReaderWriter.ReadPEM(reader);
            PEMObject? pemObject = readRes.FirstOrDefault();

            // Check
            if (pemObject == null)
            {
                throw new CryptographicException($"No PEM object found");
            }

            // Check
            switch (pemObject.Type)
            {
                case PemEd.PUBLIC_KEY:
                    ImportSubjectPublicKeyInfo(pemObject.Content, out _);
                    break;
                case PemEd.PRIVATE_KEY:
                    ImportPkcs8PrivateKey(pemObject.Content, out _);
                    break;
                default:
                    throw new CryptographicException($"PEM object is not a public or private key. It is {pemObject.Type}");

            }
        }
    }

    /// <summary>
    /// Imports an encrypted RFC 7468 PEM-encoded private key, replacing the keys for this object.
    /// </summary>
    /// <param name="input">The PEM text of the encrypted key to import.</param>
    /// <param name="password">
    /// The password to use for decrypting the key material.
    /// </param>
    public override void ImportFromEncryptedPem(ReadOnlySpan<char> input, ReadOnlySpan<byte> passwordBytes)
    {
        // Read it
        using (StringReader reader = new StringReader(input.ToString()))
        {
            // Read PEM object
            ICollection<PEMObject> readRes = PEMReaderWriter.ReadPEM(reader);
            PEMObject? pemObject = readRes.FirstOrDefault();

            // Check
            if (pemObject == null)
            {
                throw new CryptographicException($"No PEM object found");
            }

            // Check
            switch (pemObject.Type)
            {
                case PemEd.ENCRYPTED_PRIVATE_KEY:
                    ImportEncryptedPkcs8PrivateKey(passwordBytes, pemObject.Content, out _);
                    break;
                default:
                    throw new CryptographicException($"PEM object is not an encrypted private key. It is {pemObject.Type}");

            }
        }
    }

    /// <summary>
    /// Imports an encrypted RFC 7468 PEM-encoded private key, replacing the keys for this object.
    /// </summary>
    /// <param name="input">The PEM text of the encrypted key to import.</param>
    /// <param name="password">
    /// The password to use for decrypting the key material.
    /// </param>
    public override void ImportFromEncryptedPem(ReadOnlySpan<char> input, ReadOnlySpan<char> password)
    {
        // Read it
        using (StringReader reader = new StringReader(input.ToString()))
        {
            // Read PEM object
            ICollection<PEMObject> readRes = PEMReaderWriter.ReadPEM(reader);
            PEMObject? pemObject = readRes.FirstOrDefault();

            // Check
            if (pemObject == null)
            {
                throw new CryptographicException($"No PEM object found");
            }

            // Check
            switch (pemObject.Type)
            {
                case PemEd.ENCRYPTED_PRIVATE_KEY:
                    ImportEncryptedPkcs8PrivateKey(password, pemObject.Content, out _);
                    break;
                default:
                    throw new CryptographicException($"PEM object is not an encrypted private key. It is {pemObject.Type}");

            }
        }
    }
}
