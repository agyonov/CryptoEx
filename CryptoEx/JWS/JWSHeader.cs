using CryptoEx.JWK;
using System.Text.Json.Serialization;

namespace CryptoEx.JWS;

public record class JWSHeader
{
    [JsonPropertyName("alg")]
    public string Alg { get; set; } = string.Empty;

    [JsonPropertyName("jku")]
    public string? Jku { get; set; } = null;

    [JsonPropertyName("jwk")]
    public Jwk? Jwk { get; set; } = null;

    [JsonPropertyName("kid")]
    public string? Kid { get; set; } = null;

    [JsonPropertyName("x5u")]
    public string? X5u { get; set; } = null;

    [JsonPropertyName("x5c")]
    public string[]? X5c { get; set; } = null;

    [JsonPropertyName("x5t")]
    public string? X5t { get; set; } = null;

    [JsonPropertyName("x5t#S256")]
    public string? X5 { get; set; } = string.Empty;

    [JsonPropertyName("typ")]
    public string? Typ { get; set; } = null;

    [JsonPropertyName("cty")]
    public string? Cty { get; set; } = null;

    [JsonPropertyName("crit")]
    public virtual string[]? Crit { get; set; } = null;
}
