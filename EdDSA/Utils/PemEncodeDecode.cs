

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Utilities.IO.Pem;
using System.Security.Cryptography;

namespace EdDSA.Utils;

/// <summary>
/// Help class to encode and decode EcDSA keys in PEM files
/// </summary>
public static class PemEncodeDecode
{
    // Ed25519 OID
    public static readonly Oid OidEd25519 = new Oid("1.3.101.112");

    // Ed448 OID
    public static readonly Oid OidEd448 = new Oid("1.3.101.113");

    /// <summary>
    /// Decode a Ed25519 private key from a PEM
    /// </summary>
    /// <param name="pem">The PEM source</param>
    /// <param name="result">The Ed25519 private key</param>
    /// <returns>True / false depending of result</returns>
    public static bool TryReadEd25519PrivateKey(string pem, Span<byte> result)
    {
        using (StringReader reader = new StringReader(pem))
        using (PemReader pemReader = new PemReader(reader)) {
            // Read PEM object
            PemObject pemObject = pemReader.ReadPemObject();

            // Check
            if (pemObject.Type != "PRIVATE KEY") {
                return false;
            }

            // Try parse ASN
            using (Asn1InputStream asn = new Asn1InputStream(pemObject.Content)) {
                // Cycle
                var asn1Object = asn.ReadObject() as Asn1Sequence;
                if (asn1Object == null) {
                    return false;
                }

                // Parse further down
                foreach (var obj in asn1Object) {
                    switch (obj) {
                        case Asn1Sequence:
                            // Check algorithm
                            var seqOid = obj as Asn1Sequence;
                            if (seqOid == null || seqOid.Count != 1) {
                                return false;
                            }
                            DerObjectIdentifier? oid = seqOid[0] as DerObjectIdentifier;
                            if (oid == null || oid.Id != OidEd25519.Value) {
                                return false;
                            }
                            break;
                        case Asn1OctetString:
                            // Check key
                            var keyOcted = obj as Asn1OctetString;
                            byte[]? bytes = keyOcted?.GetOctets();
                            if (bytes == null || bytes.Length != 34) {
                                return false;
                            }
                            bytes[2..].CopyTo(result);
                            return true;
                    }
                }
            }
        }

        // Get me out of here
        return true;
    }


    /// <summary>
    /// Decode a Ed25519 public key from a PEM
    /// </summary>
    /// <param name="pem">The PEM source</param>
    /// <param name="result">The Ed25519 public key</param>
    /// <returns>True / false depending of result</returns>
    public static bool TryReadEd25519PublicKey(string pem, Span<byte> result)
    {
        using (StringReader reader = new StringReader(pem))
        using (PemReader pemReader = new PemReader(reader)) {
            // Read PEM object
            PemObject pemObject = pemReader.ReadPemObject();

            // Check
            if (pemObject.Type != "PUBLIC KEY") {
                return false;
            }

            // Try parse ASN
            using (Asn1InputStream asn = new Asn1InputStream(pemObject.Content)) {
                // Cycle
                var asn1Object = asn.ReadObject() as Asn1Sequence;
                if (asn1Object == null) {
                    return false;
                }

                // Parse further down
                foreach (var obj in asn1Object) {
                    switch (obj) {
                        case Asn1Sequence:
                            // Check algorithm
                            var seqOid = obj as Asn1Sequence;
                            if (seqOid == null || seqOid.Count != 1) {
                                return false;
                            }
                            DerObjectIdentifier? oid = seqOid[0] as DerObjectIdentifier;
                            if (oid == null || oid.Id != OidEd25519.Value) {
                                return false;
                            }
                            break;
                        case DerBitString:
                            // Check key
                            var keyOcted = obj as DerBitString;
                            byte[]? bytes = keyOcted?.GetOctets();
                            if (bytes == null || bytes.Length != 32) {
                                return false;
                            }
                            bytes.CopyTo(result);
                            return true;
                    }
                }
            }
        }

        // Get me out of here
        return true;
    }

}
