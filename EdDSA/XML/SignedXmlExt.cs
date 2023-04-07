using EdDSA.Utils;
using EdDSA.XML.ETSI;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml;
using System.Xml.Linq;

namespace EdDSA.XML;

/// <summary>
/// Signed XML with ID override over additional data objects
/// And additional knowledge about ECDSA keys
/// </summary>
internal class SignedXmlExt : SignedXml
{
    // XADES namespace
    private const string XadesNamespaceUrl = "http://uri.etsi.org/01903/v1.3.2#";
    private const string XadesNamespaceName = "xades";

    // ECDSA algorithms
    public const string XmlDsigECDSASHA256Url = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256";
    public const string XmlDsigECDSASHA384Url = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384";
    public const string XmlDsigECDSASHA512Url = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512";

    // last qualifying properties
    private static readonly List<XmlNodeList> _qualifyingPropetries;

    /// <summary>
    /// Static constructor
    /// to add knowledge about ECDSA keys
    /// </summary>
    static SignedXmlExt()
    {
        // init list
        _qualifyingPropetries = new List<XmlNodeList>();

        // add knowledge about ECDSA keys
        CryptoConfig.AddAlgorithm(
            typeof(EcdsaSha256SignatureDescription), XmlDsigECDSASHA256Url);
        CryptoConfig.AddAlgorithm(
            typeof(EcdsaSha384SignatureDescription), XmlDsigECDSASHA384Url);
        CryptoConfig.AddAlgorithm(
            typeof(EcdsaSha512SignatureDescription), XmlDsigECDSASHA512Url);
    }

    /// <summary>
    /// Call parent constructor
    /// </summary>
    public SignedXmlExt() : base()
    {

    }

    /// <summary>
    /// Call parent constructor
    /// </summary>
    public SignedXmlExt(XmlDocument xml) : base(xml)
    {
    }

    /// <summary>
    /// Call parent constructor
    /// </summary>
    public SignedXmlExt(XmlElement xmlElement)
        : base(xmlElement)
    {
    }

    /// <summary>
    /// Helper method to create XADES qualifiying properties to be added as DataObject to the signature
    /// </summary>
    /// <param name="certificate">The signing certificate - public part</param>
    /// <param name="mimeType">Mime type - default is text/xml</param>
    /// <returns>The XmlNodeList that hold the qualifing parameters to be added to a DataObject</returns>
    public static XmlNodeList CreateQualifyingPropertiesXML(X509Certificate2 certificate, HashAlgorithmName hashAlgorithm, string mimeType = "text/xml")
    {
        XNamespace xades = XadesNamespaceUrl;
        XNamespace ds = XmlDsigNamespaceUrl;

        // Allow set of hash algorithm
        string algorithmNameDigestXML = hashAlgorithm.Name switch
        {
            "SHA256" => SignedXml.XmlDsigSHA256Url,
            "SHA384" => SignedXml.XmlDsigSHA384Url,
            "SHA512" => SignedXml.XmlDsigSHA512Url,
            _ => throw new ArgumentException("Invalid hash algorithm")
        };
        byte[] certHash = hashAlgorithm.Name switch
        {
            "SHA256" => certificate.GetCertHash(HashAlgorithmName.SHA256),
            "SHA384" => certificate.GetCertHash(HashAlgorithmName.SHA384),
            "SHA512" => certificate.GetCertHash(HashAlgorithmName.SHA512),
            _ => throw new ArgumentException("Invalid hash algorithm")
        };

        XElement obj =
            new XElement(ds + "Object",
                new XAttribute("xmlns", XmlDsigNamespaceUrl),
                new XElement(xades + "QualifyingProperties",
                    new XAttribute(XNamespace.Xmlns + XadesNamespaceName, XadesNamespaceUrl),
                    new XAttribute("Target", $"#{ETSISignedXml.IdSignature}"),
                    new XElement(xades + "SignedProperties",
                        new XAttribute("Id", ETSISignedXml.IdXadesSignedProperties),
                        new XElement(xades + "SignedSignatureProperties",
                            new XElement(xades + "SigningTime", $"{DateTimeOffset.UtcNow:yyyy-MM-ddTHH:mm:ssZ}"),
                            new XElement(xades + "SigningCertificateV2",
                                new XElement(xades + "Cert",
                                    new XElement(xades + "CertDigest",
                                        new XElement(ds + "DigestMethod", new XAttribute("Algorithm", algorithmNameDigestXML)),
                                        new XElement(ds + "DigestValue", Convert.ToBase64String(certHash))
                                    )
                                )
                            )
                        ),
                        new XElement(xades + "SignedDataObjectProperties",
                            new XElement(xades + "DataObjectFormat",
                                new XAttribute("ObjectReference", $"#{ETSISignedXml.IdReferenceSignature}"),
                                new XElement(xades + "MimeType", mimeType)
                            )
                        )
                    )
                )
           );

        // calc
        var elm = obj.ToXmlElement()!.ChildNodes;
        lock (_qualifyingPropetries) {
            _qualifyingPropetries.Add(elm);
        }
        return elm;
    }

    /// <summary>
    /// Override GetIdElement to find the element with the specified ID attribute value in the XML document
    /// or in the additional data objects (Qualifiyng properties)
    /// </summary>
    /// <param name="document">The document being signed with SignedXML</param>
    /// <param name="idValue">The id value being searched/param>
    /// <returns>The XML element with given searchId value if found</returns>
    public override XmlElement? GetIdElement(XmlDocument document, string idValue)
    {
        if (string.IsNullOrEmpty(idValue))
            return null;

        var xmlElement = base.GetIdElement(document, idValue);
        if (xmlElement != null) {
            return xmlElement;
        }

        lock (_qualifyingPropetries) {
            // Check
            if (_qualifyingPropetries.Count == 0) {
                return null;
            }

            // cycle
            foreach (XmlNodeList xList in _qualifyingPropetries) {
                // Check
                if (xList.Count < 1) {
                    continue;
                }
                var xNode = xList[0];
                if (xNode == null || xNode.ChildNodes.Count < 1) {
                    continue;
                }

                // Maybe we have found it
                xNode = xNode.ChildNodes[0];
                if (xNode == null || xNode is not XmlElement) {
                    continue;
                } else {
                    // Confirm that we have found it
                    var hlp = (XmlElement)xNode;
                    var xEl = hlp.ToXElement();
                    if (xEl != null) {
                        // Check it
                        if (xEl.Attributes().Where(atr => atr.Name == "Id" && atr.Value == idValue).Any()) {
                            return hlp;
                        }
                    }
                }
            }
        }

        // General
        return null;
    }
}

