using System.Text.Json.Serialization;

namespace CryptoEx.JOSE;

public record class JWSHeader
{
    [JsonPropertyName("alg")]
    public string Alg { get; set; } = string.Empty;
    [JsonPropertyName("cty")]
    public string? Cty { get; set; } = null;
    [JsonPropertyName("kid")]
    public string? Kid { get; set; } = null;
    [JsonPropertyName("x5t#S256")]
    public string? X5 { get; set; } = string.Empty;
    [JsonPropertyName("x5c")]
    public string[]? X5c { get; set; } = null;
    [JsonPropertyName("typ")]
    public virtual string? Typ { get; set; } = null;
}
