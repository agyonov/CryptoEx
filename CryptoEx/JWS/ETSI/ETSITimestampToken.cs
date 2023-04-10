using System.Text.Json.Serialization;

namespace CryptoEx.JOSE.ETSI;

// ETSI Timestamp token As of ETSI TS 119 182-1
public record class ETSITimestampToken
{
    [JsonPropertyName("type")]
    public string? Type { get; set; } = null;
    [JsonPropertyName("encoding")]
    public string? Encoding { get; set; } = null;
    [JsonPropertyName("specRef")]
    public string? SpecRef { get; set; } = null;
    [JsonPropertyName("val")]
    public string Val { get; set; } = string.Empty;
}
