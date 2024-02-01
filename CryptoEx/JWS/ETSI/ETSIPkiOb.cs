using System.Text.Json.Serialization;

namespace CryptoEx.JWS.ETSI;
public record class ETSIPkiOb
{
    [JsonPropertyName("encoding")]
    public string? Encoding { get; set; } = null;

    [JsonPropertyName("specRef")]
    public string? SpecRef { get; set; } = null;

    [JsonPropertyName("val")]
    public string Val { get; set; } = string.Empty;
}

public record class ETSIxValItem
{
    [JsonPropertyName("x509Cert")]
    public ETSIPkiOb X509Cert { get; set; } = new ();
}

public record class ETSIxVals
{
    [JsonPropertyName("xVals")]
    public ETSIxValItem[] XVals { get; set; } = Array.Empty<ETSIxValItem>();
}

public record class ETSIrVal
{
    [JsonPropertyName("crlVals")]
    public ETSIPkiOb[]? CrlVals { get; set; } = null;
    [JsonPropertyName("ocspVals")]
    public ETSIPkiOb[]? OcspVals { get; set; } =null;
}

public record class ETSIrVals
{
    [JsonPropertyName("rVals")]
    public ETSIrVal RVals { get; set; } = new ();
}
