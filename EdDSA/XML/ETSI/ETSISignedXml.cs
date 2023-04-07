using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml;

namespace EdDSA.XML.ETSI;
public class ETSISignedXml
{
    // some constants on signed XML
    protected internal const string IdSignature = "id-sig-etsi-signed-xml";
    protected internal const string IdReferenceSignature = "id-ref-sig-etsi-signed-xml";
    protected internal const string IdXadesSignedProperties = "id-xades-signed-properties";
    protected internal const string ETSISignedPropertiesType = "http://uri.etsi.org/01903#SignedProperties";

    // The signing key
    protected readonly AsymmetricAlgorithm _signer;

    // XML algorithm name for dagest
    protected readonly string _algorithmNameDigestXML;

    // XML algorithm name for signature
    protected readonly string _algorithmNameSignatureXML;

    // DOTNET Hash algorithm name
    protected readonly HashAlgorithmName _hashAlgorithm;

    /// <summary>
    /// A constructiror with an private key - RSA or ECDSA, used for signing
    /// </summary>
    /// <param name="signer">The private key</param>
    public ETSISignedXml(AsymmetricAlgorithm signer)
    {
        // Store
        _signer = signer;

        // Determine the algorithm
        switch (signer) {
            case RSA rsa:
                _algorithmNameDigestXML = rsa.KeySize switch
                {
                    2048 => SignedXml.XmlDsigSHA256Url,
                    3072 => SignedXml.XmlDsigSHA384Url,
                    4096 => SignedXml.XmlDsigSHA512Url,
                    _ => throw new ArgumentException("Invalid RSA key size")
                };
                _algorithmNameSignatureXML = rsa.KeySize switch
                {
                    2048 => SignedXml.XmlDsigRSASHA256Url,
                    3072 => SignedXml.XmlDsigRSASHA384Url,
                    4096 => SignedXml.XmlDsigRSASHA512Url,
                    _ => throw new ArgumentException("Invalid RSA key size")
                };
                break;
            case ECDsa ecdsa:
                _algorithmNameDigestXML = ecdsa.KeySize switch
                {
                    256 => SignedXml.XmlDsigSHA256Url,
                    384 => SignedXml.XmlDsigSHA384Url,
                    521 => SignedXml.XmlDsigSHA512Url,
                    _ => throw new ArgumentException("Invalid ECDSA key size")
                };
                _algorithmNameSignatureXML = ecdsa.KeySize switch
                {
                    256 => SignedXmlExt.XmlDsigECDSASHA256Url,
                    384 => SignedXmlExt.XmlDsigECDSASHA384Url,
                    521 => SignedXmlExt.XmlDsigECDSASHA512Url,
                    _ => throw new ArgumentException("Invalid ECDSA key size")
                };
                break;
            default:
                throw new ArgumentException("Invalid key type");
        }

        // Store
        _hashAlgorithm = HashAlgorithmName.SHA512;
    }

    /// <summary>
    /// A constructiror with an private key - RSA or ECDSA, used for signing and hash algorithm
    /// </summary>
    /// <param name="signer">The private key</param>
    /// <param name="hashAlgorithm">Hash algorithm, mainly for RSA</param>
    /// <exception cref="ArgumentException">Invalid private key type</exception>
    public ETSISignedXml(AsymmetricAlgorithm signer, HashAlgorithmName hashAlgorithm) : this(signer)
    {
        // Determine the algorithm
        switch (signer) {
            case RSA:
                // Allow set of hash algorithm
                _algorithmNameDigestXML = hashAlgorithm.Name switch
                {
                    "SHA256" => SignedXml.XmlDsigSHA256Url,
                    "SHA384" => SignedXml.XmlDsigSHA384Url,
                    "SHA512" => SignedXml.XmlDsigSHA512Url,
                    _ => throw new ArgumentException("Invalid hash algorithm")
                };
                _algorithmNameSignatureXML = hashAlgorithm.Name switch
                {
                    "SHA256" => SignedXml.XmlDsigRSASHA256Url,
                    "SHA384" => SignedXml.XmlDsigRSASHA384Url,
                    "SHA512" => SignedXml.XmlDsigRSASHA512Url,
                    _ => throw new ArgumentException("Invalid key size")
                };
                break;
            case ECDsa:
                break;
            default:
                throw new ArgumentException("Invalid key type");
        }

        // Store
        _hashAlgorithm = hashAlgorithm;
    }

    /// <summary>
    /// Digitally sign the xml document as enveloped
    /// </summary>
    /// <param name="payload">The payload</param>
    /// <param name="cert">The certificate</param>
    /// <returns>The Xml Signature element</returns>
    public virtual XmlElement Sign(XmlDocument payload, X509Certificate2 cert)
    {
        // Create a SignedXml object.
        SignedXmlExt signedXml = new SignedXmlExt(payload);
        signedXml.Signature.Id = IdSignature;
        signedXml.SignedInfo.SignatureMethod = _algorithmNameSignatureXML;

        // Create a reference to be able to sign everything into the message.
        Reference reference = new()
        {
            Uri = "",
            Id = IdReferenceSignature
        };
        reference.AddTransform(new XmlDsigEnvelopedSignatureTransform());
        signedXml.AddReference(reference);

        // Create a new KeyInfo object & add signing certificate
        KeyInfo keyInfo = new KeyInfo();
        keyInfo.AddClause(new KeyInfoX509Data(cert.RawData));
        signedXml.KeyInfo = keyInfo;

        // Create a data object to hold the data for the ETSI qualifying properties.
        DataObject dataObject = new DataObject();
        dataObject.Data = SignedXmlExt.CreateQualifyingPropertiesXML(cert, _hashAlgorithm);
        signedXml.AddObject(dataObject);

        // Create a reference to be able to sign ETSI qualifying properties.
        var parametersSignature = new Reference
        {
            Uri = $"#{IdXadesSignedProperties}",
            Type = ETSISignedPropertiesType
        };
        parametersSignature.AddTransform(new XmlDsigExcC14NTransform());
        signedXml.AddReference(parametersSignature);

        // Set hash algorithm
        foreach (var r in signedXml.SignedInfo.References) {
            ((Reference)r).DigestMethod = _algorithmNameDigestXML;
        }

        // Compute the signature.
        signedXml.SigningKey = _signer;
        signedXml.ComputeSignature();

        return signedXml.GetXml();
    }

}
