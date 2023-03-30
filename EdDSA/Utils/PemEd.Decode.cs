

using System.Formats.Asn1;
using System.Security.Cryptography;

namespace EdDSA.Utils;

/// <summary>
/// Help class to encode and decode EcDSA keys in PEM files
/// </summary>
public static partial class PemEd
{
    // Ed25519 OID
    public static readonly Oid OidEd25519 = new Oid("1.3.101.112");

    // Ed448 OID
    public static readonly Oid OidEd448 = new Oid("1.3.101.113");

    // Some string comparison constants
    private const string PUBLIC_KEY = "PUBLIC KEY";
    private const string PRIVATE_KEY = "PRIVATE KEY";

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
                if (oid.Value != OidEd25519.Value) {
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
                if (oid.Value != OidEd25519.Value) {
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
    public static bool TryReadEd4489PrivateKey(string pem, Span<byte> result)
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
                if (oid.Value != OidEd448.Value) {
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
    /// Decode a Ed448 public key from a PEM
    /// </summary>
    /// <param name="pem">The PEM source</param>
    /// <param name="result">The Ed448 public key</param>
    /// <returns>True / false depending of result</returns>
    public static bool TryReadEd4489PublicKey(string pem, Span<byte> result)
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
                if (oid.Value != OidEd448.Value) {
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
