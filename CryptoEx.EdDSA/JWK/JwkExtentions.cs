namespace CryptoEx.EdDSA.JWK;

/// <summary>
/// Some extentiom methods for JWK - to get the key from the JWK
/// To put the key into the JWK
/// </summary>
public static class JwkExtentions
{
    ///// <summary>
    ///// Gets the EdDsa public key from the jwk or null if the jwk does not have an EdDsa public key.
    ///// </summary>
    //public static ECDsa? GetECDsaPublicKey(this Jwk jwk)
    //{
    //    //check the key type
    //    if (jwk is not JwkEd) {
    //        return null;
    //    }

    //    //get the key
    //    JwkEd jEd = (JwkEd)jwk;

    //    // check the key
    //    if (string.IsNullOrEmpty(jEc.X) || string.IsNullOrEmpty(jEc.Y) || string.IsNullOrEmpty(jEc.Crv)) {
    //        return null;
    //    }

    //    //try create the EC key
    //    try {
    //        ECParameters param = new ECParameters();
    //        param.Q = new ECPoint();
    //        param.Q.X = Base64UrlEncoder.Decode(jEc.X);
    //        param.Q.Y = Base64UrlEncoder.Decode(jEc.Y);
    //        param.Curve = jEc.Crv switch
    //        {
    //            JwkConstants.CurveP256 => ECCurve.NamedCurves.nistP256,
    //            JwkConstants.CurveP384 => ECCurve.NamedCurves.nistP384,
    //            JwkConstants.CurveP521 => ECCurve.NamedCurves.nistP521,
    //            _ => throw new Exception($"Unknown curve name {jEc.Crv}")
    //        };
    //        return ECDsa.Create(param);
    //    } catch {
    //        return null;
    //    }
    //}

    ///// <summary>
    ///// Gets the EdDsa private key from the jwk or null if the jwk does not have an EdDsa private key.
    ///// </summary>
    //public static ECDsa? GetECDsaPrivateKey(this Jwk jwk)
    //{
    //    //check the key type
    //    if (jwk is not JwkEc) {
    //        return null;
    //    }

    //    //get the key
    //    JwkEc jEc = (JwkEc)jwk;

    //    // check the key
    //    if (string.IsNullOrEmpty(jEc.X) || string.IsNullOrEmpty(jEc.Y) || string.IsNullOrEmpty(jEc.Crv) || string.IsNullOrEmpty(jEc.D)) {
    //        return null;
    //    }

    //    //try create the EC key
    //    try {
    //        ECParameters param = new ECParameters();
    //        param.Q = new ECPoint();
    //        param.Q.X = Base64UrlEncoder.Decode(jEc.X);
    //        param.Q.Y = Base64UrlEncoder.Decode(jEc.Y);
    //        param.D = Base64UrlEncoder.Decode(jEc.D);
    //        param.Curve = jEc.Crv switch
    //        {
    //            JwkConstants.CurveP256 => ECCurve.NamedCurves.nistP256,
    //            JwkConstants.CurveP384 => ECCurve.NamedCurves.nistP384,
    //            JwkConstants.CurveP521 => ECCurve.NamedCurves.nistP521,
    //            _ => throw new Exception($"Unknown curve name {jEc.Crv}")
    //        };
    //        return ECDsa.Create(param);
    //    } catch {
    //        return null;
    //    }
    //}
}
