using System.Security.Cryptography;
using System.Security.Cryptography.Xml;
using System.Xml;

namespace CryptoEx.XML;

/// <summary>
/// Signed XML with:
///   1. ID override over additional data objects
///   2. Additional knowledge about ECDSA keys
/// </summary>
public class SignedXmlExt : SignedXml
{
    // ECDSA algorithms
    public const string XmlDsigECDSASHA256Url = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256";
    public const string XmlDsigECDSASHA384Url = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384";
    public const string XmlDsigECDSASHA512Url = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512";

    /// <summary>
    /// A defenition of delegate to use for extended ID lookup
    /// </summary>
    /// <param name="idValue">The Id to look for</param>
    /// <returns>The found XmlElement. NULL if no such element is found</returns>
    public delegate XmlElement? GetIdElementDelegate(string idValue);

    // The optional delegate to use for extended ID lookup
    protected readonly GetIdElementDelegate? _seekIdDelegate;

    /// <summary>
    /// Static constructor
    /// to add knowledge about ECDSA keys
    /// </summary>
    static SignedXmlExt()
    {
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
    /// <param name="seekIdDelegate">Optional delegate to use for extended ID lookup</param>
    public SignedXmlExt(GetIdElementDelegate? seekIdDelegate = null) : base()
    {
        _seekIdDelegate = seekIdDelegate;
    }

    /// <summary>
    /// Call parent constructor
    /// </summary>
    /// <param name="seekIdDelegate">Optional delegate to use for extended ID lookup</param>
    public SignedXmlExt(XmlDocument xml, GetIdElementDelegate? seekIdDelegate = null) : base(xml)
    {
        _seekIdDelegate = seekIdDelegate;
    }

    /// <summary>
    /// Call parent constructor
    /// </summary>
    /// <param name="seekIdDelegate">Optional delegate to use for extended ID lookup</param>
    public SignedXmlExt(XmlElement xmlElement, GetIdElementDelegate? seekIdDelegate = null)
        : base(xmlElement)
    {
        _seekIdDelegate = seekIdDelegate;
    }

    /// <summary>
    /// Override GetIdElement to find the element with the specified ID attribute value in the XML document
    /// or in the additional data objects (Qualifiyng properties)
    /// </summary>
    /// <param name="document">The document being signed with SignedXML</param>
    /// <param name="idValue">The id value being searched/param>
    /// <returns>The XML element with given searchId value if found</returns>
    public override XmlElement? GetIdElement(XmlDocument? document, string idValue)
    {
        if (string.IsNullOrEmpty(idValue) || document == null)
            return null;

        var xmlElement = base.GetIdElement(document, idValue);
        if (xmlElement != null) {
            return xmlElement;
        }

        if (_seekIdDelegate != null) {
            return _seekIdDelegate(idValue);
        }

        // General
        return null;
    }
}

