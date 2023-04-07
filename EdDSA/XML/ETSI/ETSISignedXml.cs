using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Threading.Tasks;
using System.Xml;

namespace EdDSA.XML.ETSI;
public class ETSISignedXml 
{
    protected internal const string IdSignature = "id-sig-etsi-signed-xml";
    protected internal const string IdReferenceSignature = "id-ref-sig-etsi-signed-xml";
    protected internal const string IdXadesSignedProperties = "id-xades-signed-properties";

    public ETSISignedXml(AsymmetricAlgorithm signer) 
    {
    }
}
