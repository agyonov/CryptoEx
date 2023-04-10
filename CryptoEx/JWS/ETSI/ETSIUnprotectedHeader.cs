using System.Text.Json.Serialization;

namespace CryptoEx.JWS.ETSI;

// ETSI unprotected header as defined in ETSI TS 119 182-1
public record class ETSIUnprotectedHeader
{
    [JsonPropertyName("etsiU")]
    public string[] EtsiU { get; set; } = Array.Empty<string>();
}
