using System.Xml;
using System.Xml.Linq;

namespace CryptoEx.Utils;
public static class XMLConvertors
{
    public static XmlElement? ToXmlElement(this XElement el)
    {
        var doc = new XmlDocument();
        using (var reader = el.CreateReader()) {
            doc.Load(reader);
        }
        return doc.DocumentElement;
    }

    public static XElement? ToXElement(this XmlElement el)
    {
        using (var reader = el.CreateNavigator()?.ReadSubtree()) {
            return reader != null ? XElement.Load(reader, LoadOptions.PreserveWhitespace) : null;
        }
    }
}
