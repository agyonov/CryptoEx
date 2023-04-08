using System.Text.Json.Serialization;

namespace CryptoEx.JOSE.ETSI;

// ETSI detached parts as defined in ETSI TS 119 182-1
public record class ETSIDetachedParts
{
    [JsonPropertyName("mId")]
    public string MId { get; set; } = ETSIConstants.ETSI_DETACHED_PARTS_OBJECT_HASH;
    [JsonPropertyName("pars")]
    public string[] Pars { get; set; } = Array.Empty<string>();
    [JsonPropertyName("hashM")]
    public string? HashM { get; set; } = null;
    [JsonPropertyName("hashV")]
    public string[]? HashV { get; set; } = null;
    [JsonPropertyName("ctys")]
    public string[]? Ctys { get; set; } = null;
}
