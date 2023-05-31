using CryptoEx.Utils;
using System.Globalization;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml;
using System.Xml.Linq;

namespace CryptoEx.XML.ETSI;
public class ETSISignedXml
{
    // XADES namespace
    protected const string XadesNamespaceUri = "http://uri.etsi.org/01903/v1.3.2#";
    protected const string XadesNamespaceName = "xades";
    protected const string ETSISignedPropertiesType = "http://uri.etsi.org/01903#SignedProperties";

    // Some constants on signed XML
    private const string IdSignature = "id-sig-etsi-signed-xml";
    private const string IdReferenceSignature = "id-ref-sig-etsi-signed-signature";
    private const string IdReferenceSignatureXML = "id-ref-sig-etsi-signed-signature-xml";
    private const string IdXadesSignedProperties = "id-xades-signed-properties";

    // The signing key
    protected readonly AsymmetricAlgorithm? _signer;

    // XML algorithm name for dagest
    protected readonly string? _algorithmNameDigestXML;

    // XML algorithm name for signature
    protected readonly string? _algorithmNameSignatureXML;

    // DOTNET Hash algorithm name
    protected readonly HashAlgorithmName _hashAlgorithm;

    // last qualifying properties
    protected XmlNodeList? _qualifyingPropetries;

    /// <summary>
    /// A constructiror without a private key - used for verification
    /// </summary>
    public ETSISignedXml()
    {

    }

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
    /// <param name="payload">The payload - original XML file</param>
    /// <param name="cert">The certificate. ONLY Public part is used! The PrivateKey is proided in constructor!</param>
    /// <returns>The Xml Signature element</returns>
    public virtual XmlElement Sign(XmlDocument payload, X509Certificate2 cert)
    {
        // Check
        if (_signer == null) {
            throw new InvalidOperationException("No private key provided");
        }

        // Create a SignedXml object & provide GetIdElement method
        SignedXmlExt signedXml = new SignedXmlExt(payload, GetIdElement);
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
        dataObject.Data = CreateQualifyingPropertiesXML(cert, _hashAlgorithm);
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

        // Compute the signature
        signedXml.SigningKey = _signer;
        signedXml.ComputeSignature();

        return signedXml.GetXml();
    }

    /// <summary>
    /// Digitally sign the attachement as XML signature.
    ///     If no payload is provided, the signature is detached.
    ///     if payload is provided, the signature is datached and provided XML is enveloped.
    /// </summary>
    /// <param name="attachement">The external, attached content - file, picture, etc...</param>
    /// <param name="cert">The certificate. ONLY Public part is used! The PrivateKey is proided in constructor!</param>
    /// <param name="payload">OPTIONAL payload - XML file</param>
    /// <returns>The Xml Signature element</returns>
    public virtual XmlElement SignDetached(Stream attachement, X509Certificate2 cert, XmlDocument? payload = null)
    {
        // Check
        if (_signer == null) {
            throw new InvalidOperationException("No private key provided");
        }

        // Create a SignedXml object & provide GetIdElement method
        SignedXmlExt signedXml = payload == null ? new SignedXmlExt(GetIdElement) : new SignedXmlExt(payload, GetIdElement);
        signedXml.Signature.Id = IdSignature;
        signedXml.SignedInfo.SignatureMethod = _algorithmNameSignatureXML;

        // Create a reference to be able to sign hash of the attachement.
        Reference reference = new(attachement);
        reference.Id = IdReferenceSignature;
        signedXml.AddReference(reference);

        // Create a reference to be able to sign everything into the message.
        if (payload != null) {
            Reference referenceXML = new()
            {
                Uri = "",
                Id = IdReferenceSignatureXML
            };
            referenceXML.AddTransform(new XmlDsigEnvelopedSignatureTransform());
            signedXml.AddReference(referenceXML);
        }

        // Create a new KeyInfo object & add signing certificate
        KeyInfo keyInfo = new KeyInfo();
        keyInfo.AddClause(new KeyInfoX509Data(cert.RawData));
        signedXml.KeyInfo = keyInfo;

        // Create a data object to hold the data for the ETSI qualifying properties.
        DataObject dataObject = new DataObject();
        dataObject.Data = CreateQualifyingPropertiesXML(cert, _hashAlgorithm, "application/octet-stream", payload != null);
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

        // Compute the signature
        signedXml.SigningKey = _signer;
        signedXml.ComputeSignature();

        return signedXml.GetXml();
    }

    /// <summary>
    /// Verify the signature of an enveloped XML document
    /// </summary>
    /// <param name="payload">The XML signature document</param>
    /// <param name="cInfo">returns the context info about the signature</param>
    /// <returns>True signature is valid. False - no it is invalid</returns>
    public virtual bool Verify(XmlDocument payload, out ETSIContextInfo cInfo)
    {
        // set initially
        cInfo = new ETSIContextInfo();

        // Create a SignedXml object & provide GetIdElement method
        SignedXmlExt signedXml = new SignedXmlExt(payload);

        // Load the signature node
        XmlNodeList nodeList = payload.GetElementsByTagName("Signature", SignedXml.XmlDsigNamespaceUrl);
        XmlElement? sigantureNode = nodeList[0] as XmlElement;
        if (sigantureNode == null) {
            return false;
        }

        // Load the signature
        signedXml.LoadXml(sigantureNode);

        // Try get certificate
        if (signedXml.KeyInfo.Count < 0) {
            return false;
        }
        foreach (var ki in signedXml.KeyInfo) {
            if (ki is KeyInfoX509Data) {
                if (((KeyInfoX509Data)ki).Certificates.Count < 0) {
                    continue;
                }
                cInfo.SigningCertificate = ((KeyInfoX509Data)ki).Certificates[0] as X509Certificate2;
                if (cInfo.SigningCertificate != null) {
                    break;
                } else {
                    continue;
                }
            }
        }

        // Check if certificate is present
        if (cInfo.SigningCertificate == null) {
            return false;
        }

        // Try load some more info
        ExtractQualifyingProperties(sigantureNode, cInfo);

        // Verify the signature
        RSA? rsa = cInfo.SigningCertificate.GetRSAPublicKey();
        if (rsa != null) {
            return signedXml.CheckSignature(rsa);
        }
        ECDsa? ecdsa = cInfo.SigningCertificate.GetECDsaPublicKey();
        if (ecdsa != null) {
            return signedXml.CheckSignature(ecdsa);
        }

        // No baby no
        return false;
    }

    /// <summary>
    /// Verify the signature of an detached XML document
    /// </summary>
    /// <param name="payload">The XML signature document</param>
    /// <param name="cert">returns the signing certificate</param>
    /// <returns>True signature is valid. False - no it is invalid</returns>
    public virtual bool VerifyDetached(Stream attachement, XmlDocument payload, out ETSIContextInfo cInfo)
    {
        // set initially
        cInfo = new ETSIContextInfo();

        // Create a SignedXml object & provide GetIdElement method
        SignedXmlExt signedXml = new SignedXmlExt(payload);

        // Load the signature node
        XmlNodeList nodeList = payload.GetElementsByTagName("Signature", SignedXml.XmlDsigNamespaceUrl);
        XmlElement? sigantureNode = nodeList[0] as XmlElement;
        if (sigantureNode == null) {
            return false;
        }

        // Load the signature
        signedXml.LoadXml(sigantureNode);

        // Try get certificate
        if (signedXml.KeyInfo.Count < 0) {
            return false;
        }
        foreach (var ki in signedXml.KeyInfo) {
            if (ki is KeyInfoX509Data) {
                if (((KeyInfoX509Data)ki).Certificates.Count < 0) {
                    continue;
                }
                cInfo.SigningCertificate = ((KeyInfoX509Data)ki).Certificates[0] as X509Certificate2;
                if (cInfo.SigningCertificate != null) {
                    break;
                } else {
                    continue;
                }
            }
        }

        // Check if certificate is present
        if (cInfo.SigningCertificate == null) {
            return false;
        }

        // Try load some more info
        ExtractQualifyingProperties(sigantureNode, cInfo);

        // cycle
        for (int loop = 0; loop < signedXml.SignedInfo.References.Count; loop++) {
            // Get the reference
            Reference? r = signedXml.SignedInfo.References[loop] as Reference;

            // Find the reference for the attachement
            if (r != null && (r.Uri == null || r.TransformChain.Count < 1)) {
                // Remove the reference
                signedXml.SignedInfo.References.Remove(r);

                // Check hash
                if (!CheckDigest(attachement, r)) {
                    return false;
                }
            }
        }

        // Verify the signature
        RSA? rsa = cInfo.SigningCertificate.GetRSAPublicKey();
        if (rsa != null) {
            return signedXml.CheckSignature(rsa);
        }
        ECDsa? ecdsa = cInfo.SigningCertificate.GetECDsaPublicKey();
        if (ecdsa != null) {
            return signedXml.CheckSignature(ecdsa);
        }

        // No baby no
        return false;
    }

    /// <summary>
    /// Add timestamping
    /// </summary>
    /// <param name="funcAsync">Async function that calls Timestamping server, with input data and returns 
    /// response from the server
    /// </param>
    /// <param name="signedDoc">The signed document</param>
    public virtual async Task AddTimestampAsync(Func<byte[], CancellationToken, Task<byte[]>> funcAsync, XmlDocument signedDoc, CancellationToken ct = default)
    {
        // locals
        byte[] timeStamp;
        XNamespace xades = XadesNamespaceUri;
        XNamespace ds = SignedXml.XmlDsigNamespaceUrl;

        var qProperties = signedDoc.DocumentElement?.GetElementsByTagName("QualifyingProperties", XadesNamespaceUri);
        var sigValue = signedDoc.DocumentElement?.GetElementsByTagName("SignatureValue", SignedXml.XmlDsigNamespaceUrl);

        // Check
        if (qProperties == null || qProperties.Count < 1 || sigValue == null || sigValue.Count < 1) {
            return;
        }

        //Initialise the stream to read the node list
        using (MemoryStream nodeStream = new MemoryStream())
        using (XmlWriter xw = XmlWriter.Create(nodeStream)) {
            // Write the signature value to the stream
            sigValue[0]!.WriteTo(xw);
            xw.Flush();
            nodeStream.Position = 0;

            // Perform the C14N transform on the nodes in the stream
            XmlDsigExcC14NTransform transform = new("#default");
            transform.LoadInput(nodeStream);
            using (MemoryStream outputStream = (MemoryStream)transform.GetOutput(typeof(Stream))) {
                // Get the timestamp
                timeStamp = await funcAsync(outputStream.ToArray(), ct);
                if (ct.IsCancellationRequested) {
                    return;
                }
            }
        }

        // Build the timestamp XML
        XElement obj =
           new XElement(ds + "Object",
               new XAttribute("xmlns", SignedXml.XmlDsigNamespaceUrl),
               new XElement(xades + "QualifyingProperties",
                    new XAttribute(XNamespace.Xmlns + XadesNamespaceName, XadesNamespaceUri),
                    new XAttribute("Target", $"#{IdSignature}"),
                    new XElement(xades + "UnsignedProperties",
                        new XElement(xades + "UnsignedSignatureProperties",
                            new XElement(xades + "SignatureTimeStamp",
                                new XElement(ds + "CanonicalizationMethod", new XAttribute("Algorithm", SignedXml.XmlDsigExcC14NTransformUrl)),
                                new XElement(xades + "EncapsulatedTimeStamp", Convert.ToBase64String(timeStamp))
                            )
                        )
                    )
                )
            );

        // Extract the unsigned properties
        var unsProps = obj.ToXmlElement()?.GetElementsByTagName("UnsignedProperties", XadesNamespaceUri)[0];
        if (unsProps == null) {
            return;
        }

        // Append
        qProperties[0]!.AppendChild(signedDoc.ImportNode(unsProps, true));
    }

    /// <summary>
    /// Helper method to create XADES qualifiying properties to be added as DataObject to the signature
    /// </summary>
    /// <param name="certificate">The signing certificate - public part</param>
    /// <param name="mimeType">Mime type - default is text/xml</param>
    /// <returns>The XmlNodeList that hold the qualifing parameters to be added to a DataObject</returns>
    protected virtual XmlNodeList CreateQualifyingPropertiesXML(X509Certificate2 certificate, HashAlgorithmName hashAlgorithm, string mimeType = "text/xml", bool hasDetachedAndXML = false)
    {
        XNamespace xades = XadesNamespaceUri;
        XNamespace ds = SignedXml.XmlDsigNamespaceUrl;

        // Allow set of hash algorithm
        string algorithmNameDigestXML = hashAlgorithm.Name switch
        {
            "SHA256" => SignedXml.XmlDsigSHA256Url,
            "SHA384" => SignedXml.XmlDsigSHA384Url,
            "SHA512" => SignedXml.XmlDsigSHA512Url,
            _ => throw new ArgumentException("Invalid hash algorithm")
        };
        byte[] certHash = certificate.GetCertHash(hashAlgorithm);

        object[] dataObjects =  {
            new XElement(xades + "DataObjectFormat",
                new XAttribute("ObjectReference", $"#{IdReferenceSignature}"),
                new XElement(xades + "MimeType", mimeType)
            ),
            new XElement(xades + "DataObjectFormat",
                new XAttribute("ObjectReference", $"#{IdReferenceSignatureXML}"),
                new XElement(xades + "MimeType", "text/xml")
            )
        };
        if (!hasDetachedAndXML) {
            dataObjects = dataObjects[..1];
        }

        XElement obj =
            new XElement(ds + "Object",
                new XAttribute("xmlns", SignedXml.XmlDsigNamespaceUrl),
                new XElement(xades + "QualifyingProperties",
                    new XAttribute(XNamespace.Xmlns + XadesNamespaceName, XadesNamespaceUri),
                    new XAttribute("Target", $"#{IdSignature}"),
                    new XElement(xades + "SignedProperties",
                        new XAttribute("Id", IdXadesSignedProperties),
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
                            dataObjects
                        )
                    )
                )
           );

        // calc
        _qualifyingPropetries = obj.ToXmlElement()!.ChildNodes;
        return _qualifyingPropetries;
    }

    /// <summary>
    /// Provide GetIdElementDelegate to find the element with the specified ID attribute value
    /// in the additional data objects (Qualifiyng properties)
    /// </summary>
    /// <param name="idValue">The id value being searched/param>
    /// <returns>The XML element with given searchId value if found</returns>
    protected XmlElement? GetIdElement(string idValue)
    {
        // Check
        if (_qualifyingPropetries == null) {
            return null;
        }

        // Get the first node of the qualifying properties
        var xNode = _qualifyingPropetries[0];
        if (xNode == null || xNode.ChildNodes.Count < 1) {
            return null;
        }

        // Maybe we have found it
        xNode = xNode.ChildNodes[0];
        if (xNode == null || xNode is not XmlElement) {
            return null;
        } else {
            // Confirm that we have found it
            XElement? xEl = ((XmlElement)xNode).ToXElement();
            if (xEl != null) {
                // Check it
                if (xEl.Attributes().Where(atr => atr.Name == "Id" && atr.Value == idValue).Any()) {
                    return (XmlElement)xNode;
                }
            }
        }

        // General
        return null;
    }

    /// <summary>
    /// Checks digest of the attachement
    /// </summary>
    /// <param name="attachement">The attachement</param>
    /// <param name="r">The reference object for the attachement in the signature</param>
    /// <returns>True if digests are equal</returns>
    /// <exception cref="Exception">Unsupported hashing algorithm</exception>
    protected bool CheckDigest(Stream attachement, Reference r)
    {
        // Get hash algorithm
        using (HashAlgorithm hash = r.DigestMethod switch
        {
            SignedXml.XmlDsigSHA256Url => SHA256.Create(),
            SignedXml.XmlDsigSHA384Url => SHA384.Create(),
            SignedXml.XmlDsigSHA512Url => SHA512.Create(),
            _ => throw new Exception($"Unsuported digest method {r.DigestMethod}")
        }) {
            // Original hash
            byte[] origHash = r.DigestValue;

            // Calc new one
            byte[] computed = hash.ComputeHash(attachement);

            // Compare
            if (!origHash.SequenceEqual(computed)) {
                return false;
            }
        }

        // return 
        return true;
    }

    /// <summary>
    /// Try to extract some of the qualifying properties from the signature
    /// </summary>
    /// <param name="signature">The signature</param>
    /// <param name="info">The info to hold the properties</param>
    protected virtual void ExtractQualifyingProperties(XmlElement signature, ETSIContextInfo info)
    {
        // Some namespaces
        XNamespace xades = XadesNamespaceUri;
        XNamespace ds = SignedXml.XmlDsigNamespaceUrl;

        // Find the qualifying properties
        XmlNodeList? qProperties = signature.GetElementsByTagName("QualifyingProperties", XadesNamespaceUri);

        // Check
        if (qProperties == null || qProperties.Count < 1 || qProperties[0] is not XmlElement) {
            return;
        }

        // Get as XElement
        XElement? qProps = ((XmlElement)qProperties[0]!).ToXElement();
        if (qProps == null) {
            return;
        }

        // Get the signed properties
        XElement? sigProps = (from seg in qProps.Descendants(xades + "SignedSignatureProperties")
                              select seg).FirstOrDefault();
        if (sigProps == null) {
            return;
        }

        // Get the signing time and the rest values
        string? sigTime = (from seg in sigProps.Descendants(xades + "SigningTime")
                           select seg.Value).FirstOrDefault();
        string? certDigestValue = (from seg in sigProps.Descendants(ds + "DigestValue")
                                   select seg.Value).FirstOrDefault();
        string? certDigestMethod = (from seg in sigProps.Descendants(ds + "DigestMethod")
                                    select seg.Attribute("Algorithm")?.Value).FirstOrDefault();

        // Check
        if (!string.IsNullOrEmpty(sigTime)) {
            if (DateTimeOffset.TryParseExact(sigTime, "yyyy-MM-ddTHH:mm:ssZ", CultureInfo.InvariantCulture, DateTimeStyles.None, out DateTimeOffset dt)) {
                info.SigningDateTime = dt;
            }
        }
        if (!string.IsNullOrEmpty(certDigestValue)) {
            try {
                info.SigningCertificateDigestValue = Convert.FromBase64String(certDigestValue);
            } catch { }
        }
        if (!string.IsNullOrEmpty(certDigestMethod)) {
            info.SigningCertificateDagestMethod = certDigestMethod switch
            {
                SignedXml.XmlDsigSHA256Url => HashAlgorithmName.SHA256,
                SignedXml.XmlDsigSHA384Url => HashAlgorithmName.SHA384,
                SignedXml.XmlDsigSHA512Url => HashAlgorithmName.SHA512,
                _ => null
            };
        }
    }
}
