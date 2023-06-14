using System.Text.Json.Serialization;

namespace CryptoEx.JWK;

/// <summary>
/// A Jeson Web Key (JWK) is a JavaScript Object Notation (JSON) data structure that represents a cryptographic key.
/// </summary>
[JsonConverter(typeof(JwkConverter))]
public record class Jwk
{
    /// <summary>
    /// (Key Type) Parameter - RSA, EC, Symmetric
    /// </summary>
    [JsonPropertyName("kty")]
    public string Kty { get; set; } = string.Empty;
    /// <summary>
    /// (Key Type) Parameter - 'sig', 'enc', oteher...
    /// </summary>
    [JsonPropertyName("use")]
    public string? Use { get; set; } = null;
    /// <summary>
    /// (Key Operations) Parameter  - 'sign', 'verify', 'encrypt', 'decrypt', 'wrapKey', 'unwrapKey', 'deriveKey', 'deriveBits'
    /// </summary>
    [JsonPropertyName("key_ops")]
    public List<string>? KeyOps { get; set; } = null;
    /// <summary>
    /// OPTIOANL  (Algorithm) Parameter - RS256, ES256, etc
    /// </summary>
    [JsonPropertyName("alg")]
    public string? Alg { get; set; } = null;
    /// <summary>
    /// (Key ID) Parameter. OPTIONAL
    /// </summary>
    [JsonPropertyName("kid")]
    public string? Kid { get; set; } = null;
    /// <summary>
    /// (X.509 URL) Parameter. OPTIONAL
    /// </summary>
    [JsonPropertyName("x5u")]
    public string? X5U { get; set; } = null;
    /// <summary>
    /// (X.509 Certificate Chain) Parameter. OPTIONAL
    /// </summary>
    [JsonPropertyName("x5c")]
    public List<string>? X5C { get; set; } = null;
    /// <summary>
    /// (X.509 Certificate SHA-1 Thumbprint) Parameter
    /// </summary>
    [JsonPropertyName("x5t")]
    public string? X5T { get; set; } = null;
    /// <summary>
    /// (X.509 Certificate SHA-256 Thumbprint) Parameter
    /// </summary>
    [JsonPropertyName("x5t#S256")]
    public string? X5TSha256 { get; set; } = null;
}


