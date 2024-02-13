
using System.Text.Json.Serialization;

namespace CryptoEx.JWS.ETSI;

// ETSI Archive Timestamp As of ETSI TS 119 182-1
public record class ETSIArchiveTimestamp
{
    [JsonPropertyName("arcTst")]
    public ETSITimestampContainer? ArcTst { get; set; } = null;
}
