using System.Text.Json.Serialization;

namespace EdDSA.JOSE.ETSI;

// ETSI Timestamp container As of ETSI TS 119 182-1
public record class ETSITimestampContainer
{
    [JsonPropertyName("canonAlg")]
    public string? CanonAlg { get; set; } = null;
    [JsonPropertyName("tstTokens")]
    public ETSITimestampToken[] TstTokens { get; set; } = Array.Empty<ETSITimestampToken>();
}
