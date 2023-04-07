using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Threading.Tasks;
using System.Xml;
using System.Xml.Linq;
using EdDSA.Utils;

namespace EdDSA.XML.ETSI;

// signed XML with ID override for ETSI
internal class SignedXmlWithId : SignedXml
{
    private const string XadesNamespaceUrl = "http://uri.etsi.org/01903/v1.3.2#";
    private const string XadesNamespaceName = "xades";

    // last qualifying properties
    private XmlNodeList? _qualifyingPropetries;

    public SignedXmlWithId() : base()
    {
    }

    public SignedXmlWithId(XmlDocument xml) : base(xml)
    {
    }

    public SignedXmlWithId(XmlElement xmlElement)
        : base(xmlElement)
    {
    }

    public XmlNodeList CreateQualifyingPropertiesXML(X509Certificate2 certificate, string mimeType = "text/xml")
    {
        XNamespace xades = XadesNamespaceUrl;
        XNamespace ds = XmlDsigNamespaceUrl;

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
                                        new XElement(ds + "DigestMethod", new XAttribute("Algorithm", XmlDsigSHA512Url)),
                                        new XElement(ds + "DigestValue", Convert.ToBase64String(certificate.GetCertHash(HashAlgorithmName.SHA512)))
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
        _qualifyingPropetries = obj.ToXmlElement()!.ChildNodes;
        return _qualifyingPropetries;

        //XmlDocument xmlDocument = new XmlDocument();
        //xmlDocument.LoadXml(obj.ToString());
        //return xmlDocument.ChildNodes[0]!.ChildNodes;
    }
}

