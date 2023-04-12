using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace CryptoEx.JWS;

public static class JWSConstants
{
    /// <summary>
    /// RSASSA-PKCS1-v1_5 using SHA-256
    /// </summary>
    public const string RS256 = "RS256";
    /// <summary>
    /// RSASSA-PKCS1-v1_5 using SHA-384
    /// </summary>
    public const string RS384 = "RS384";
    /// <summary>
    /// RSASSA-PKCS1-v1_5 using SHA-512
    /// </summary>
    public const string RS512 = "RS512";
    /// <summary>
    /// ECDSA using P-256 and SHA-256
    /// </summary>
    public const string ES256 = "ES256";
    /// <summary>
    /// ECDSA using P-384 and SHA-384
    /// </summary>
    public const string ES384 = "ES384";
    /// <summary>
    /// ECDSA using P-521 and SHA-512
    /// </summary>
    public const string ES512 = "ES512";
    /// <summary>
    ///  HMAC using SHA-256
    /// </summary>
    public const string HS256 = "HS256";
    /// <summary>
    /// HMAC using SHA-384
    /// </summary>
    public const string HS384 = "HS384";
    /// <summary>
    /// HMAC using SHA-512
    /// </summary>
    public const string HS512 = "HS512";
    /// <summary>
    /// JWS in compact serialization format
    /// </summary>
    public const string JOSE = "jose";
    /// <summary>
    /// JWS in flattened or full serialization format
    /// </summary>
    public const string JOSE_JSON = "jose+json";
    /// <summary>
    /// Some JSON options
    /// </summary>
    public static readonly JsonSerializerOptions jsonOptions = new JsonSerializerOptions
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        WriteIndented = false,
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
        TypeInfoResolver = JWSSourceGenerationContext.Default
    };
}
