

using CryptoEx.Ed;
using CryptoEx.Utils;
using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;

namespace CryptoEx.Ed.Utils;

/// <summary>
/// Help class to encode and decode EcDSA keys in PEM files
/// </summary>
public static partial class PemEd
{
    // Some string comparison constants
    public const string PUBLIC_KEY = "PUBLIC KEY";
    public const string PRIVATE_KEY = "PRIVATE KEY";
    public const string ENCRYPTED_PRIVATE_KEY = "ENCRYPTED PRIVATE KEY";

    /// <summary>
    /// Decode a Ed25519 private key from a PEM
    /// </summary>
    /// <param name="pem">The PEM source</param>
    /// <param name="result">The Ed25519 private key</param>
    /// <returns>True / false depending of result</returns>
    public static bool TryReadEd25519PrivateKey(string pem, Span<byte> result)
    {
        using (StringReader reader = new StringReader(pem)) {
            // Read PEM object
            ICollection<PEMObject> readRes = PEMReaderWriter.ReadPEM(reader);
            PEMObject? pemObject = readRes.FirstOrDefault();

            // Check
            if (pemObject == null || pemObject.Type != PRIVATE_KEY) {
                return false;
            }

            // Try parse ASN
            try {
                // Get as span
                Span<byte> source = pemObject.Content.AsSpan();

                // Some helpers
                int offset, len, bytes;

                // Read top sequence
                AsnDecoder.ReadSequence(source, AsnEncodingRules.DER, out offset, out len, out bytes);
                source = source[offset..];

                // Read version & check
                ReadOnlySpan<byte> version = AsnDecoder.ReadIntegerBytes(source, AsnEncodingRules.DER, out bytes);
                if (version.Length != 1 && version[0] != 0) {
                    return false;
                }

                // Go further
                source = source[bytes..];

                // Read algorithm
                AsnDecoder.ReadSequence(source, AsnEncodingRules.DER, out offset, out len, out bytes);

                // Go Further
                var oidSeq = source[offset..(offset + len)];
                source = source[bytes..];

                // Parse OID
                Oid oid = new Oid(AsnDecoder.ReadObjectIdentifier(oidSeq, AsnEncodingRules.DER, out bytes));
                if (oid.Value != EdConstants.OidEd25519.Value) {
                    return false;
                }

                // read key
                byte[] resKey = AsnDecoder.ReadOctetString(source, AsnEncodingRules.DER, out bytes);
                resKey[2..].CopyTo(result);

                // return 
                return true;
            } catch {
                // No no man
                return false;
            }
        }
    }

    /// <summary>
    /// Decode a Ed25519 private key from an encrypted PEM - PKCS 8
    /// </summary>
    /// <param name="pem">The PEM source</param>
    /// <param name="password">The password used to encrypt the key</param>
    /// <param name="result">The Ed25519 private key</param>
    /// <returns>True / false depending of result</returns>
    public static bool TryReadEd25519PrivateKey(string pem, string password, Span<byte> result)
    {
        using (StringReader reader = new StringReader(pem)) {
            // Read PEM object
            ICollection<PEMObject> readRes = PEMReaderWriter.ReadPEM(reader);
            PEMObject? pemObject = readRes.FirstOrDefault();

            // Check
            if (pemObject == null || pemObject.Type != ENCRYPTED_PRIVATE_KEY) {
                return false;
            }

            // Try parse ASN
            try {
                // Try to decrypt
                int bytesRead;
                Pkcs8PrivateKeyInfo dcr = Pkcs8PrivateKeyInfo.DecryptAndDecode(password, pemObject.Content, out bytesRead);

                // Check
                if (dcr.AlgorithmId.Value != EdConstants.OidEd25519.Value) {
                    return false;
                }

                // read key
                dcr.PrivateKeyBytes.Span[2..].CopyTo(result);

                // return 
                return true;
            } catch {
                // No no man
                return false;
            }
        }
    }

    /// <summary>
    /// Decode a Ed25519 public key from a PEM
    /// </summary>
    /// <param name="pem">The PEM source</param>
    /// <param name="result">The Ed25519 public key</param>
    /// <returns>True / false depending of result</returns>
    public static bool TryReadEd25519PublicKey(string pem, Span<byte> result)
    {
        using (StringReader reader = new StringReader(pem)) {

            // Read PEM object
            ICollection<PEMObject> readRes = PEMReaderWriter.ReadPEM(reader);
            PEMObject? pemObject = readRes.FirstOrDefault();

            // Check
            if (pemObject == null || pemObject.Type != PUBLIC_KEY) {
                return false;
            }

            // Try parse ASN
            try {
                // Get as span
                Span<byte> source = pemObject.Content.AsSpan();

                // Some helpers
                int offset, len, bytes;

                // Read top sequence
                AsnDecoder.ReadSequence(source, AsnEncodingRules.DER, out offset, out len, out bytes);
                source = source[offset..];

                // Read algorithm
                AsnDecoder.ReadSequence(source, AsnEncodingRules.DER, out offset, out len, out bytes);

                // Go Further
                var oidSeq = source[offset..(offset + len)];
                source = source[bytes..];

                // Parse OID
                Oid oid = new Oid(AsnDecoder.ReadObjectIdentifier(oidSeq, AsnEncodingRules.DER, out bytes));
                if (oid.Value != EdConstants.OidEd25519.Value) {
                    return false;
                }

                // read key
                byte[] resKey = AsnDecoder.ReadBitString(source, AsnEncodingRules.DER, out len, out bytes);
                resKey.CopyTo(result);

                // return
                return true;
            } catch {
                // No no man
                return false;
            }
        }
    }

    /// <summary>
    /// Decode a Ed448 private key from a PEM
    /// </summary>
    /// <param name="pem">The PEM source</param>
    /// <param name="result">The Ed448 private key</param>
    /// <returns>True / false depending of result</returns>
    public static bool TryReadEd448PrivateKey(string pem, Span<byte> result)
    {
        using (StringReader reader = new StringReader(pem)) {
            // Read PEM object
            ICollection<PEMObject> readRes = PEMReaderWriter.ReadPEM(reader);
            PEMObject? pemObject = readRes.FirstOrDefault();

            // Check
            if (pemObject == null || pemObject.Type != PRIVATE_KEY) {
                return false;
            }

            // Try parse ASN
            try {
                // Get as span
                Span<byte> source = pemObject.Content.AsSpan();

                // Some helpers
                int offset, len, bytes;

                // Read top sequence
                AsnDecoder.ReadSequence(source, AsnEncodingRules.DER, out offset, out len, out bytes);
                source = source[offset..];

                // Read version & check
                ReadOnlySpan<byte> version = AsnDecoder.ReadIntegerBytes(source, AsnEncodingRules.DER, out bytes);
                if (version.Length != 1 && version[0] != 0) {
                    return false;
                }

                // Go further
                source = source[bytes..];

                // Read algorithm
                AsnDecoder.ReadSequence(source, AsnEncodingRules.DER, out offset, out len, out bytes);

                // Go Further
                var oidSeq = source[offset..(offset + len)];
                source = source[bytes..];

                // Parse OID
                Oid oid = new Oid(AsnDecoder.ReadObjectIdentifier(oidSeq, AsnEncodingRules.DER, out bytes));
                if (oid.Value != EdConstants.OidEd448.Value) {
                    return false;
                }

                // read key
                byte[] resKey = AsnDecoder.ReadOctetString(source, AsnEncodingRules.DER, out bytes);
                resKey[2..].CopyTo(result);

                return true;
            } catch {
                // No no man
                return false;
            }
        }
    }

    /// <summary>
    /// Decode a Ed448 private key from an encrypted PEM - PKCS 8
    /// </summary>
    /// <param name="pem">The PEM source</param>
    /// <param name="password">The password used to encrypt the key</param>
    /// <param name="result">The Ed448 private key</param>
    /// <returns>True / false depending of result</returns>
    public static bool TryReadEd448PrivateKey(string pem, string password, Span<byte> result)
    {
        using (StringReader reader = new StringReader(pem)) {
            // Read PEM object
            ICollection<PEMObject> readRes = PEMReaderWriter.ReadPEM(reader);
            PEMObject? pemObject = readRes.FirstOrDefault();

            // Check
            if (pemObject == null || pemObject.Type != ENCRYPTED_PRIVATE_KEY) {
                return false;
            }

            // Try parse ASN
            try {
                // Try to decrypt
                int bytesRead;
                Pkcs8PrivateKeyInfo dcr = Pkcs8PrivateKeyInfo.DecryptAndDecode(password, pemObject.Content, out bytesRead);

                // Check
                if (dcr.AlgorithmId.Value != EdConstants.OidEd448.Value) {
                    return false;
                }

                // read key
                dcr.PrivateKeyBytes.Span[2..].CopyTo(result);

                // return 
                return true;
            } catch {
                // No no man
                return false;
            }
        }
    }

    /// <summary>
    /// Decode a Ed448 public key from a PEM
    /// </summary>
    /// <param name="pem">The PEM source</param>
    /// <param name="result">The Ed448 public key</param>
    /// <returns>True / false depending of result</returns>
    public static bool TryReadEd448PublicKey(string pem, Span<byte> result)
    {
        using (StringReader reader = new StringReader(pem)) {

            // Read PEM object
            ICollection<PEMObject> readRes = PEMReaderWriter.ReadPEM(reader);
            PEMObject? pemObject = readRes.FirstOrDefault();

            // Check
            if (pemObject == null || pemObject.Type != PUBLIC_KEY) {
                return false;
            }

            // Try parse ASN
            try {
                // Get as span
                Span<byte> source = pemObject.Content.AsSpan();

                // Some helpers
                int offset, len, bytes;

                // Read top sequence
                AsnDecoder.ReadSequence(source, AsnEncodingRules.DER, out offset, out len, out bytes);
                source = source[offset..];

                // Read algorithm
                AsnDecoder.ReadSequence(source, AsnEncodingRules.DER, out offset, out len, out bytes);

                // Go Further
                var oidSeq = source[offset..(offset + len)];
                source = source[bytes..];

                // Parse OID
                Oid oid = new Oid(AsnDecoder.ReadObjectIdentifier(oidSeq, AsnEncodingRules.DER, out bytes));
                if (oid.Value != EdConstants.OidEd448.Value) {
                    return false;
                }

                // read key
                byte[] resKey = AsnDecoder.ReadBitString(source, AsnEncodingRules.DER, out len, out bytes);
                resKey.CopyTo(result);

                // return
                return true;
            } catch {
                // No no man
                return false;
            }
        }
    }
}
