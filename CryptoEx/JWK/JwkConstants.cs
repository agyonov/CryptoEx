using CryptoEx.JWS;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace CryptoEx.JWK;

/// <summary>
/// Various constants used in JWK.
/// </summary>
public static class JwkConstants
{
    #region JWK Key Types

    /// <summary>
    /// Simetric
    /// </summary>
    public const string OCT = "oct";
    /// <summary>
    /// Eliptic Curve
    /// </summary>
    public const string EC = "EC";
    /// <summary>
    /// RSA
    /// </summary>
    public const string RSA = "RSA";
    /// <summary>
    /// Ed Key type
    /// </summary>
    public const string OKP = "OKP";

    #endregion

    #region EC Curves

    /// <summary>
    /// P-256 NISP
    /// </summary>
    public const string CurveP256 = "P-256";
    /// <summary>
    /// P-384 NISP
    /// </summary>
    public const string CurveP384 = "P-384";
    /// <summary>
    /// P-521 NISP
    /// </summary>
    public const string CurveP521 = "P-521";

    #endregion EC Curves

    #region Ed Curves

    /// <summary>
    ///  Ed25519 signature algorithm key pairs
    /// </summary>
    public const string CurveEd25519 = "Ed25519";
    /// <summary>
    /// Ed448 signature algorithm key pairs
    /// </summary>
    public const string CurveEd448 = "Ed448";

    #endregion Ed Curves

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
