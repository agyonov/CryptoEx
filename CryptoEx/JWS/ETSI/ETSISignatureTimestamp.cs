using System.Text.Json.Serialization;

namespace CryptoEx.JWS.ETSI;

// ETSI Signature Timestamp As of ETSI TS 119 182-1
public record class ETSISignatureTimestamp
{
    [JsonPropertyName("sigTst")]
    public ETSITimestampContainer? SigTst { get; set; } = null;
}