using CryptoEx.EdDSA;
using CryptoEx.JWK;
using CryptoEx.Utils;

namespace CryptoEx.Ed.JWK;

/// <summary>
/// Some extentiom methods for JWK - to get the key from the JWK
/// To put the key into the JWK
/// </summary>
public static class JwkExtentions
{
    /// <summary>
    /// Gets the EdDsa public key from the jwk or null if the jwk does not have an EdDsa public key.
    /// </summary>
    public static EdDsa? GetEdDsaPublicKey(this Jwk jwk)
    {
        //check the key type
        if (jwk is not JwkEd) {
            return null;
        }

        //get the key
        JwkEd jEd = (JwkEd)jwk;

        // check the key
        if (string.IsNullOrEmpty(jEd.X) || string.IsNullOrEmpty(jEd.Crv)) {
            return null;
        }

        //try create the EC key
        try {
            EDParameters param = new();
            param.X = Base64UrlEncoder.Decode(jEd.X);
            param.Crv = jEd.Crv switch
            {
                JwkConstants.CurveEd25519 => EdConstants.OidEd25519,
                JwkConstants.CurveEd448 => EdConstants.OidEd448,
                _ => throw new Exception($"Unknown curve name {jEd.Crv}")
            };

            return EdDsa.Create(param);
        } catch {
            return null;
        }
    }

    /// <summary>
    /// Gets the EdDsa private key from the jwk or null if the jwk does not have an EdDsa private key.
    /// </summary>
    public static EdDsa? GetEdDsaPrivateKey(this Jwk jwk)
    {
        //check the key type
        if (jwk is not JwkEd) {
            return null;
        }

        //get the key
        JwkEd jEd = (JwkEd)jwk;

        // check the key
        if (string.IsNullOrEmpty(jEd.X) || string.IsNullOrEmpty(jEd.Crv) || string.IsNullOrEmpty(jEd.D)) {
            return null;
        }

        //try create the EC key
        try {
            EDParameters param = new();
            param.X = Base64UrlEncoder.Decode(jEd.X);
            param.D = Base64UrlEncoder.Decode(jEd.D);
            param.Crv = jEd.Crv switch
            {
                JwkConstants.CurveEd25519 => EdConstants.OidEd25519,
                JwkConstants.CurveEd448 => EdConstants.OidEd448,
                _ => throw new Exception($"Unknown curve name {jEd.Crv}")
            };

            return EdDsa.Create(param);
        } catch {
            return null;
        }
    }
}
