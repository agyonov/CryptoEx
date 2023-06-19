using CryptoEx.Utils;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace CryptoEx.JWK;


/// <summary>
/// Some extentiom methods for JWK - to get the key from the JWK
/// To put the key into the JWK
/// </summary>
public static class JwkExtentions
{
    /// <summary>
    /// Gets the RSA public key from the jwk or null if the jwk does not have an RSA public key.
    /// </summary>
    public static RSA? GetRSAPublicKey(this Jwk jwk)
    {
        //check the key type
        if (jwk is not JwkRSA) {
            return null;
        }

        //get the key
        JwkRSA jRsa = (JwkRSA)jwk;

        // check the key
        if (string.IsNullOrEmpty(jRsa.E) || string.IsNullOrEmpty(jRsa.N)) {
            return null;
        }

        //try create the RSA key
        try {
            RSAParameters param = new RSAParameters();
            param.Modulus = Base64UrlEncoder.Decode(jRsa.N);
            param.Exponent = Base64UrlEncoder.Decode(jRsa.E);
            return RSA.Create(param);
        } catch {
            return null;
        }
    }

    /// <summary>
    /// Gets the RSA private / public key from the jwk or null if the jwk does not have an RSA public key.
    /// </summary>
    public static RSA? GetRSAPrivateKey(this Jwk jwk)
    {
        //check the key type
        if (jwk is not JwkRSA) {
            return null;
        }

        //get the key
        JwkRSA jRsa = (JwkRSA)jwk;

        // check the key
        if (string.IsNullOrEmpty(jRsa.E) || string.IsNullOrEmpty(jRsa.N)
            || string.IsNullOrEmpty(jRsa.D) || string.IsNullOrEmpty(jRsa.P)
            || string.IsNullOrEmpty(jRsa.Q) || string.IsNullOrEmpty(jRsa.DP)
            || string.IsNullOrEmpty(jRsa.DQ) || string.IsNullOrEmpty(jRsa.QI)) {
            return null;
        }

        //try create the RSA key
        try {
            RSAParameters param = new RSAParameters();
            param.Modulus = string.IsNullOrEmpty(jRsa.N) ? null : Base64UrlEncoder.Decode(jRsa.N);
            param.Exponent = string.IsNullOrEmpty(jRsa.E) ? null : Base64UrlEncoder.Decode(jRsa.E);
            param.D = string.IsNullOrEmpty(jRsa.D) ? null : Base64UrlEncoder.Decode(jRsa.D);
            param.Q = string.IsNullOrEmpty(jRsa.Q) ? null : Base64UrlEncoder.Decode(jRsa.Q);
            param.P = string.IsNullOrEmpty(jRsa.P) ? null : Base64UrlEncoder.Decode(jRsa.P);
            param.DQ = string.IsNullOrEmpty(jRsa.DQ) ? null : Base64UrlEncoder.Decode(jRsa.DQ);
            param.DP = string.IsNullOrEmpty(jRsa.DP) ? null : Base64UrlEncoder.Decode(jRsa.DP);
            param.InverseQ = string.IsNullOrEmpty(jRsa.QI) ? null : Base64UrlEncoder.Decode(jRsa.QI);
            return RSA.Create(param);
        } catch {
            return null;
        }
    }

    /// <summary>
    /// Gets the ECDsa public key from the jwk or null if the jwk does not have an ECDsa public key.
    /// </summary>
    public static ECDsa? GetECDsaPublicKey(this Jwk jwk)
    {
        //check the key type
        if (jwk is not JwkEc) {
            return null;
        }

        //get the key
        JwkEc jEc = (JwkEc)jwk;

        // check the key
        if (string.IsNullOrEmpty(jEc.X) || string.IsNullOrEmpty(jEc.Y) || string.IsNullOrEmpty(jEc.Crv)) {
            return null;
        }

        //try create the EC key
        try {
            ECParameters param = new ECParameters();
            param.Q = new ECPoint();
            param.Q.X = Base64UrlEncoder.Decode(jEc.X);
            param.Q.Y = Base64UrlEncoder.Decode(jEc.Y);
            param.Curve = jEc.Crv switch
            {
                JwkConstants.CurveP256 => ECCurve.NamedCurves.nistP256,
                JwkConstants.CurveP384 => ECCurve.NamedCurves.nistP384,
                JwkConstants.CurveP521 => ECCurve.NamedCurves.nistP521,
                _ => throw new Exception($"Unknown curve name {jEc.Crv}")
            };
            return ECDsa.Create(param);
        } catch {
            return null;
        }
    }

    /// <summary>
    /// Gets the ECDsa private key from the jwk or null if the jwk does not have an ECDsa private key.
    /// </summary>
    public static ECDsa? GetECDsaPrivateKey(this Jwk jwk)
    {
        //check the key type
        if (jwk is not JwkEc) {
            return null;
        }

        //get the key
        JwkEc jEc = (JwkEc)jwk;

        // check the key
        if (string.IsNullOrEmpty(jEc.X) || string.IsNullOrEmpty(jEc.Y) || string.IsNullOrEmpty(jEc.Crv) || string.IsNullOrEmpty(jEc.D)) {
            return null;
        }

        //try create the EC key
        try {
            ECParameters param = new ECParameters();
            param.Q = new ECPoint();
            param.Q.X = Base64UrlEncoder.Decode(jEc.X);
            param.Q.Y = Base64UrlEncoder.Decode(jEc.Y);
            param.D = Base64UrlEncoder.Decode(jEc.D);
            param.Curve = jEc.Crv switch
            {
                JwkConstants.CurveP256 => ECCurve.NamedCurves.nistP256,
                JwkConstants.CurveP384 => ECCurve.NamedCurves.nistP384,
                JwkConstants.CurveP521 => ECCurve.NamedCurves.nistP521,
                _ => throw new Exception($"Unknown curve name {jEc.Crv}")
            };
            return ECDsa.Create(param);
        } catch {
            return null;
        }
    }

    /// <summary>
    /// Gets the symmetric key from the Jwk or null if the jwk does not have an symmetric key.
    /// </summary>
    public static byte[]? GetSymmetricKey(this Jwk jwk)
    {
        //check the key type
        if (jwk is not JwkSymmetric) {
            return null;
        }

        //get the key
        JwkSymmetric jKey = (JwkSymmetric)jwk;

        // check the key
        if (string.IsNullOrEmpty(jKey.K)) {
            return null;
        }

        //try create the Decode key
        try {
            return Base64UrlEncoder.Decode(jKey.K);
        } catch {
            return null;
        }
    }

    /// <summary>
    /// Get JWK from RSA or null if not possible. By default does not export the private key
    /// </summary>
    public static JwkRSA? GetJwk(this RSA key, bool includePrivate = false)
    {
        try {
            // Create 
            JwkRSA jwk = new();
            jwk.Kty = JwkConstants.RSA;

            // Get params
            RSAParameters param = key.ExportParameters(includePrivate);

            // Set public part
            jwk.N = Base64UrlEncoder.Encode(param.Modulus);
            jwk.E = Base64UrlEncoder.Encode(param.Exponent);

            // Check it
            if (includePrivate) {
                jwk.D = Base64UrlEncoder.Encode(param.D);
                jwk.Q = Base64UrlEncoder.Encode(param.Q);
                jwk.P = Base64UrlEncoder.Encode(param.P);
                jwk.DQ = Base64UrlEncoder.Encode(param.DQ);
                jwk.DP = Base64UrlEncoder.Encode(param.DP);
                jwk.QI = Base64UrlEncoder.Encode(param.InverseQ);
            }

            // return
            return jwk;
        } catch {
            return null;
        }
    }

    /// <summary>
    /// Get JWK from ECDsa or null if not possible. By default does not export the private key
    /// </summary>
    public static JwkEc? GetJwk(this ECDsa key, bool includePrivate = false)
    {
        try {
            // Create 
            JwkEc jwk = new();
            jwk.Kty = JwkConstants.EC;

            // Get params
            ECParameters param = key.ExportParameters(includePrivate);

            // Set public part
            jwk.X = Base64UrlEncoder.Encode(param.Q.X);
            jwk.Y = Base64UrlEncoder.Encode(param.Q.Y);
            jwk.Crv = param.Curve.Oid.Value switch
            {
                "1.2.840.10045.3.1.7" => JwkConstants.CurveP256,
                "1.3.132.0.34" => JwkConstants.CurveP384,
                "1.3.132.0.35" => JwkConstants.CurveP521,
                _ => throw new Exception($"Unknown curve name {param.Curve.Oid.Value}")
            };

            // Check it
            if (includePrivate) {
                jwk.D = Base64UrlEncoder.Encode(param.D);
            }

            // return
            return jwk;
        } catch {
            return null;
        }
    }

    /// <summary>
    ///  Get JWK from private (HMAC) or null if not possible.
    /// </summary>
    public static JwkSymmetric? GetJwk(this byte[] key)
    {
        try {
            // Create 
            JwkSymmetric jwk = new();
            jwk.Kty = JwkConstants.OCT;

            // Set public part
            jwk.K = Base64UrlEncoder.Encode(key);

            // return
            return jwk;
        } catch {
            return null;
        }
    }

    /// <summary>
    /// Set some certificate info into the Jwk
    /// </summary>
    public static void SetX509Certificate(this Jwk jwk, X509Certificate2 cert)
    {
        jwk.X5C = new List<string>
        {
            Convert.ToBase64String(cert.RawData)
        };
        using (HashAlgorithm hash = SHA256.Create()) {
            jwk.X5TSha256 = Base64UrlEncoder.Encode(hash.ComputeHash(cert.RawData));
        }
    }

    /// <summary>
    /// Set some certificates info into the Jwk
    /// </summary>
    public static void SetX509Certificate(this Jwk jwk, List<X509Certificate2> certs)
    {
        // Get number one
        X509Certificate2? cert = certs.FirstOrDefault();

        // Check
        if (cert == null) {
            return;
        }

        // Set some data
        jwk.X5C = new List<string>(certs.Count);
        foreach (X509Certificate2 elm in certs) {
            jwk.X5C.Add(Convert.ToBase64String(elm.RawData));
        }
        using (HashAlgorithm hash = SHA256.Create()) {
            jwk.X5TSha256 = Base64UrlEncoder.Encode(hash.ComputeHash(cert.RawData));
        }
    }

    /// <summary>
    /// Get certificates from JWK
    /// </summary>
    public static List<X509Certificate2>? GetX509Certificates(this Jwk jwk)
    {
        // Check
        if (jwk.X5C == null) {
            return null;
        }

        try {
            // convert
            List<X509Certificate2> result = new(jwk.X5C.Count);
            foreach (string elm in jwk.X5C) {
                X509Certificate2 cert = new X509Certificate2(Convert.FromBase64String(elm));
                result.Add(cert);
            }

            // return 
            return result;
        } catch {
            return null;
        }
    }
}
