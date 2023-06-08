using CryptoEx.Ed.EdDsa;
using CryptoEx.Ed.JWK;
using CryptoEx.JWK;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;

namespace CryptoEx.Tests;

public class TestJWK
{
    public const string JWK_PUBLIC_1 =
        """
        {
         "kty":"EC",
         "crv":"P-256",
         "x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
         "y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
         "kid":"JWK_PUB_1"
        }
        """;

    public const string JWK_PUBLIC_2 =
        """
        {
        "kty":"RSA",
        "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
        "e":"AQAB",
        "alg":"RS256",
        "kid":"2011-04-29"
        }
        """;

    public const string JWK_PUBLIC_3 =
        """
        {
         "kty":"OKP",
         "crv":"Ed25519",
         "x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
         "kid":"JWK_PUB_3"
        }
        """;

    public const string JWK_PRIVATE_1 =
        """
        {
        "kty":"EC",
        "crv":"P-256",
        "x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
        "y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
        "d":"870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE",
        "use":"enc",
        "kid":"1"
        }
        """;

    public const string JWK_PRIVATE_2 =
        """
        {
        "kty":"RSA",
        "n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
        "e":"AQAB",
        "d":"X4cTteJY_gn4FYPsXB8rdXix5vwsg1FLN5E3EaG6RJoVH-HLLKD9M7dx5oo7GURknchnrRweUkC7hT5fJLM0WbFAKNLWY2vv7B6NqXSzUvxT0_YSfqijwp3RTzlBaCxWp4doFk5N2o8Gy_nHNKroADIkJ46pRUohsXywbReAdYaMwFs9tv8d_cPVY3i07a3t8MN6TNwm0dSawm9v47UiCl3Sk5ZiG7xojPLu4sbg1U2jx4IBTNBznbJSzFHK66jT8bgkuqsk0GjskDJk19Z4qwjwbsnn4j2WBii3RL-Us2lGVkY8fkFzme1z0HbIkfz0Y6mqnOYtqc0X4jfcKoAC8Q",
        "p":"83i-7IvMGXoMXCskv73TKr8637FiO7Z27zv8oj6pbWUQyLPQBQxtPVnwD20R-60eTDmD2ujnMt5PoqMrm8RfmNhVWDtjjMmCMjOpSXicFHj7XOuVIYQyqVWlWEh6dN36GVZYk93N8Bc9vY41xy8B9RzzOGVQzXvNEvn7O0nVbfs",
        "q":"3dfOR9cuYq-0S-mkFLzgItgMEfFzB2q3hWehMuG0oCuqnb3vobLyumqjVZQO1dIrdwgTnCdpYzBcOfW5r370AFXjiWft_NGEiovonizhKpo9VVS78TzFgxkIdrecRezsZ-1kYd_s1qDbxtkDEgfAITAG9LUnADun4vIcb6yelxk",
        "dp":"G4sPXkc6Ya9y8oJW9_ILj4xuppu0lzi_H7VTkS8xj5SdX3coE0oimYwxIi2emTAue0UOa5dpgFGyBJ4c8tQ2VF402XRugKDTP8akYhFo5tAA77Qe_NmtuYZc3C3m3I24G2GvR5sSDxUyAN2zq8Lfn9EUms6rY3Ob8YeiKkTiBj0",
        "dq":"s9lAH9fggBsoFR8Oac2R_E2gw282rT2kGOAhvIllETE1efrA6huUUvMfBcMpn8lqeW6vzznYY5SSQF7pMdC_agI3nG8Ibp1BUb0JUiraRNqUfLhcQb_d9GF4Dh7e74WbRsobRonujTYN1xCaP6TO61jvWrX-L18txXw494Q_cgk",
        "qi":"GyM_p6JrXySiz1toFgKbWV-JdI3jQ4ypu9rbMWx3rQJBfmt0FoYzgUIZEVFEcOqwemRN81zoDAaa-Bk0KWNGDjJHZDdDmFhW3AN7lI-puxk_mHZGJ11rxyR8O55XLSe3SPmRfKwZI6yU24ZxvQKFYItdldUKGzO6Ia6zTKhAVRU",
        "alg":"RS256",
        "kid":"2011-04-29"
        }
        """;

    public const string JWK_PRIVATE_3 =
        """
        {
        "kty":"OKP",
        "crv":"Ed25519",
        "x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
        "d":"nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A",
        "use":"sig",
        "kid":"3"
        }
        """;

    public const string JWK_SYMMETRIC =
        """
        {
        "kty":"oct",
        "k":"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow",
        "kid":"HMAC_1"
        }
        """;

    public const string JWK_RSA_X509 = """
        {
        "kty":"RSA",
        "use":"sig",
        "kid":"1b94c",
        "n":"vrjOfz9Ccdgx5nQudyhdoR17V-IubWMeOZCwX_jj0hgAsz2J_pqYW08PLbK_PdiVGKPrqzmDIsLI7sA25VEnHU1uCLNwBuUiCO11_-7dYbsr4iJmG0Qu2j8DsVyT1azpJC_NG84Ty5KKthuCaPod7iI7w0LK9orSMhBEwwZDCxTWq4aYWAchc8t-emd9qOvWtVMDC2BXksRngh6X5bUYLy6AyHKvj-nUy1wgzjYQDwHMTplCoLtU-o-8SNnZ1tmRoGE9uJkBLdh5gFENabWnU5m1ZqZPdwS-qo-meMvVfJb6jJVWRpl2SUtCnYG2C32qvbWbjZ_jBPD5eunqsIo1vQ",
        "e":"AQAB",
        "x5c":[
                "MIIDQjCCAiqgAwIBAgIGATz/FuLiMA0GCSqGSIb3DQEBBQUAMGIxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDTzEPMA0GA1UEBxMGRGVudmVyMRwwGgYDVQQKExNQaW5nIElkZW50aXR5IENvcnAuMRcwFQYDVQQDEw5CcmlhbiBDYW1wYmVsbDAeFw0xMzAyMjEyMzI5MTVaFw0xODA4MTQyMjI5MTVaMGIxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDTzEPMA0GA1UEBxMGRGVudmVyMRwwGgYDVQQKExNQaW5nIElkZW50aXR5IENvcnAuMRcwFQYDVQQDEw5CcmlhbiBDYW1wYmVsbDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAL64zn8/QnHYMeZ0LncoXaEde1fiLm1jHjmQsF/449IYALM9if6amFtPDy2yvz3YlRij66s5gyLCyO7ANuVRJx1NbgizcAblIgjtdf/u3WG7K+IiZhtELto/A7Fck9Ws6SQvzRvOE8uSirYbgmj6He4iO8NCyvaK0jIQRMMGQwsU1quGmFgHIXPLfnpnfajr1rVTAwtgV5LEZ4Iel+W1GC8ugMhyr4/p1MtcIM42EA8BzE6ZQqC7VPqPvEjZ2dbZkaBhPbiZAS3YeYBRDWm1p1OZtWamT3cEvqqPpnjL1XyW+oyVVkaZdklLQp2Btgt9qr21m42f4wTw+Xrp6rCKNb0CAwEAATANBgkqhkiG9w0BAQUFAAOCAQEAh8zGlfSlcI0o3rYDPBB07aXNswb4ECNIKG0CETTUxmXl9KUL+9gGlqCz5iWLOgWsnrcKcY0vXPG9J1r9AqBNTqNgHq2G03X09266X5CpOe1zFo+Owb1zxtp3PehFdfQJ610CDLEaS9V9Rqp17hCyybEpOGVwe8fnk+fbEL2Bo3UPGrpsHzUoaGpDftmWssZkhpBJKVMJyf/RuP2SmmaIzmnw9JiSlYhzo4tpzd5rFXhjRbg4zW9C+2qok+2+qDM1iJ684gPHMIY8aLWrdgQTxkumGmTqgawR+N5MDtdPTEQ0XfIBc2cJEUyMTY5MPvACWpkA6SdS4xSvdXK3IVfOWA=="
              ]
        }
        """;

    [Fact(DisplayName = "Decode RSA key public certificate")]
    public void DecodeRSAPublicCertificate()
    {
        JwkRSA? jwk = JsonSerializer.Deserialize<Jwk>(JWK_RSA_X509, JwkConstants.jsonOptions) as JwkRSA;

        Assert.NotNull(jwk);
        Assert.Equal("RSA", jwk.Kty);
        Assert.Equal("AQAB", jwk.E);
        Assert.Equal("vrjOfz9Ccdgx5nQudyhdoR17V-IubWMeOZCwX_jj0hgAsz2J_pqYW08PLbK_PdiVGKPrqzmDIsLI7sA25VEnHU1uCLNwBuUiCO11_-7dYbsr4iJmG0Qu2j8DsVyT1azpJC_NG84Ty5KKthuCaPod7iI7w0LK9orSMhBEwwZDCxTWq4aYWAchc8t-emd9qOvWtVMDC2BXksRngh6X5bUYLy6AyHKvj-nUy1wgzjYQDwHMTplCoLtU-o-8SNnZ1tmRoGE9uJkBLdh5gFENabWnU5m1ZqZPdwS-qo-meMvVfJb6jJVWRpl2SUtCnYG2C32qvbWbjZ_jBPD5eunqsIo1vQ", jwk.N);
        Assert.Equal("1b94c", jwk.Kid);

        List<X509Certificate2>? certs = jwk.GetX509Certificates();
        Assert.NotNull(certs);
        Assert.True(certs.Any());

        jwk.SetX509Certificate(certs);

        Assert.NotNull(jwk.X5TSha256);
        Assert.NotNull(jwk.X5C);
        Assert.True(jwk.X5C.Any());
        Assert.Equal("MIIDQjCCAiqgAwIBAgIGATz/FuLiMA0GCSqGSIb3DQEBBQUAMGIxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDTzEPMA0GA1UEBxMGRGVudmVyMRwwGgYDVQQKExNQaW5nIElkZW50aXR5IENvcnAuMRcwFQYDVQQDEw5CcmlhbiBDYW1wYmVsbDAeFw0xMzAyMjEyMzI5MTVaFw0xODA4MTQyMjI5MTVaMGIxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDTzEPMA0GA1UEBxMGRGVudmVyMRwwGgYDVQQKExNQaW5nIElkZW50aXR5IENvcnAuMRcwFQYDVQQDEw5CcmlhbiBDYW1wYmVsbDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAL64zn8/QnHYMeZ0LncoXaEde1fiLm1jHjmQsF/449IYALM9if6amFtPDy2yvz3YlRij66s5gyLCyO7ANuVRJx1NbgizcAblIgjtdf/u3WG7K+IiZhtELto/A7Fck9Ws6SQvzRvOE8uSirYbgmj6He4iO8NCyvaK0jIQRMMGQwsU1quGmFgHIXPLfnpnfajr1rVTAwtgV5LEZ4Iel+W1GC8ugMhyr4/p1MtcIM42EA8BzE6ZQqC7VPqPvEjZ2dbZkaBhPbiZAS3YeYBRDWm1p1OZtWamT3cEvqqPpnjL1XyW+oyVVkaZdklLQp2Btgt9qr21m42f4wTw+Xrp6rCKNb0CAwEAATANBgkqhkiG9w0BAQUFAAOCAQEAh8zGlfSlcI0o3rYDPBB07aXNswb4ECNIKG0CETTUxmXl9KUL+9gGlqCz5iWLOgWsnrcKcY0vXPG9J1r9AqBNTqNgHq2G03X09266X5CpOe1zFo+Owb1zxtp3PehFdfQJ610CDLEaS9V9Rqp17hCyybEpOGVwe8fnk+fbEL2Bo3UPGrpsHzUoaGpDftmWssZkhpBJKVMJyf/RuP2SmmaIzmnw9JiSlYhzo4tpzd5rFXhjRbg4zW9C+2qok+2+qDM1iJ684gPHMIY8aLWrdgQTxkumGmTqgawR+N5MDtdPTEQ0XfIBc2cJEUyMTY5MPvACWpkA6SdS4xSvdXK3IVfOWA==", jwk.X5C.First());
    }

    [Fact(DisplayName = "Decode RSA key public one")]
    public void DecodeRSAPublic()
    {
        JwkRSA? jwk = JsonSerializer.Deserialize<Jwk>(JWK_PUBLIC_2, JwkConstants.jsonOptions) as JwkRSA;

        Assert.NotNull(jwk);
        Assert.Equal("RSA", jwk.Kty);
        Assert.Equal("AQAB", jwk.E);
        Assert.Equal("0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw", jwk.N);
        Assert.Equal("2011-04-29", jwk.Kid);

        RSA? rsa = jwk.GetRSAPublicKey();
        Assert.NotNull(rsa);

        jwk = rsa.GetJwk();

        Assert.NotNull(jwk);
        Assert.Equal("RSA", jwk.Kty);
        Assert.Equal("AQAB", jwk.E);
        Assert.Equal("0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw", jwk.N);
    }

    [Fact(DisplayName = "Decode EC key public one")]
    public void DecodeECPublic()
    {
        JwkEc? jwk = JsonSerializer.Deserialize<Jwk>(JWK_PUBLIC_1, JwkConstants.jsonOptions) as JwkEc;

        Assert.NotNull(jwk);
        Assert.Equal("EC", jwk.Kty);
        Assert.Equal("P-256", jwk.Crv);
        Assert.Equal("f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU", jwk.X);
        Assert.Equal("x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0", jwk.Y);
        Assert.Equal("JWK_PUB_1", jwk.Kid);

        ECDsa? ecdsa = jwk.GetECDsaPublicKey();
        Assert.NotNull(ecdsa);

        jwk = ecdsa.GetJwk();

        Assert.NotNull(jwk);
        Assert.Equal("EC", jwk.Kty);
        Assert.Equal("P-256", jwk.Crv);
        Assert.Equal("f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU", jwk.X);
        Assert.Equal("x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0", jwk.Y);

    }

    [Fact(DisplayName = "Decode EC key private one")]
    public void DecodeECPrivate()
    {
        JwkEc? jwk = JsonSerializer.Deserialize<Jwk>(JWK_PRIVATE_1, JwkConstants.jsonOptions) as JwkEc;

        Assert.NotNull(jwk);
        Assert.Equal("EC", jwk.Kty);
        Assert.Equal("P-256", jwk.Crv);
        Assert.Equal("MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4", jwk.X);
        Assert.Equal("4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM", jwk.Y);
        Assert.Equal("870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE", jwk.D);
        Assert.Equal("enc", jwk.Use);
        Assert.Equal("1", jwk.Kid);

        ECDsa? ecdsa = jwk.GetECDsaPrivateKey();
        Assert.NotNull(ecdsa);

        jwk = ecdsa.GetJwk(true);
        Assert.NotNull(jwk);
        Assert.Equal("EC", jwk.Kty);
        Assert.Equal("P-256", jwk.Crv);
        Assert.Equal("MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4", jwk.X);
        Assert.Equal("4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM", jwk.Y);
        Assert.Equal("870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE", jwk.D);
    }

    [Fact(DisplayName = "Decode ED key public one")]
    public void DecodeEDPublic()
    {
        JwkEd? jwk = JsonSerializer.Deserialize<Jwk>(JWK_PUBLIC_3, JwkConstants.jsonOptions) as JwkEd;

        Assert.NotNull(jwk);
        Assert.Equal("OKP", jwk.Kty);
        Assert.Equal("Ed25519", jwk.Crv);
        Assert.Equal("11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo", jwk.X);
        Assert.Equal("JWK_PUB_3", jwk.Kid);

        EdDsa? eddsa = jwk.GetEdDsaPublicKey();
        Assert.NotNull(eddsa);

        jwk = eddsa.GetJwk();

        Assert.NotNull(jwk);
        Assert.Equal("OKP", jwk.Kty);
        Assert.Equal("Ed25519", jwk.Crv);
        Assert.Equal("11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo", jwk.X);
    }

    [Fact(DisplayName = "Decode ED key private one")]
    public void DecodeEDPrivate()
    {
        JwkEd? jwk = JsonSerializer.Deserialize<Jwk>(JWK_PRIVATE_3, JwkConstants.jsonOptions) as JwkEd;

        Assert.NotNull(jwk);
        Assert.Equal("OKP", jwk.Kty);
        Assert.Equal("Ed25519", jwk.Crv);
        Assert.Equal("11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo", jwk.X);
        Assert.Equal("nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A", jwk.D);
        Assert.Equal("sig", jwk.Use);
        Assert.Equal("3", jwk.Kid);

        EdDsa? eddsa = jwk.GetEdDsaPrivateKey();
        Assert.NotNull(eddsa);

        jwk = eddsa.GetJwk(true);
        Assert.NotNull(jwk);
        Assert.Equal("OKP", jwk.Kty);
        Assert.Equal("Ed25519", jwk.Crv);
        Assert.Equal("11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo", jwk.X);
        Assert.Equal("nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A", jwk.D);
    }

    [Fact(DisplayName = "Decode RSA key private one")]
    public void DecodeRSAPrivate()
    {
        JwkRSA? jwk = JsonSerializer.Deserialize<Jwk>(JWK_PRIVATE_2, JwkConstants.jsonOptions) as JwkRSA;

        Assert.NotNull(jwk);
        Assert.Equal("RSA", jwk.Kty);
        Assert.Equal("AQAB", jwk.E);
        Assert.Equal("0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw", jwk.N);
        Assert.Equal("X4cTteJY_gn4FYPsXB8rdXix5vwsg1FLN5E3EaG6RJoVH-HLLKD9M7dx5oo7GURknchnrRweUkC7hT5fJLM0WbFAKNLWY2vv7B6NqXSzUvxT0_YSfqijwp3RTzlBaCxWp4doFk5N2o8Gy_nHNKroADIkJ46pRUohsXywbReAdYaMwFs9tv8d_cPVY3i07a3t8MN6TNwm0dSawm9v47UiCl3Sk5ZiG7xojPLu4sbg1U2jx4IBTNBznbJSzFHK66jT8bgkuqsk0GjskDJk19Z4qwjwbsnn4j2WBii3RL-Us2lGVkY8fkFzme1z0HbIkfz0Y6mqnOYtqc0X4jfcKoAC8Q", jwk.D);
        Assert.Equal("83i-7IvMGXoMXCskv73TKr8637FiO7Z27zv8oj6pbWUQyLPQBQxtPVnwD20R-60eTDmD2ujnMt5PoqMrm8RfmNhVWDtjjMmCMjOpSXicFHj7XOuVIYQyqVWlWEh6dN36GVZYk93N8Bc9vY41xy8B9RzzOGVQzXvNEvn7O0nVbfs", jwk.P);
        Assert.Equal("3dfOR9cuYq-0S-mkFLzgItgMEfFzB2q3hWehMuG0oCuqnb3vobLyumqjVZQO1dIrdwgTnCdpYzBcOfW5r370AFXjiWft_NGEiovonizhKpo9VVS78TzFgxkIdrecRezsZ-1kYd_s1qDbxtkDEgfAITAG9LUnADun4vIcb6yelxk", jwk.Q);
        Assert.Equal("G4sPXkc6Ya9y8oJW9_ILj4xuppu0lzi_H7VTkS8xj5SdX3coE0oimYwxIi2emTAue0UOa5dpgFGyBJ4c8tQ2VF402XRugKDTP8akYhFo5tAA77Qe_NmtuYZc3C3m3I24G2GvR5sSDxUyAN2zq8Lfn9EUms6rY3Ob8YeiKkTiBj0", jwk.DP);
        Assert.Equal("s9lAH9fggBsoFR8Oac2R_E2gw282rT2kGOAhvIllETE1efrA6huUUvMfBcMpn8lqeW6vzznYY5SSQF7pMdC_agI3nG8Ibp1BUb0JUiraRNqUfLhcQb_d9GF4Dh7e74WbRsobRonujTYN1xCaP6TO61jvWrX-L18txXw494Q_cgk", jwk.DQ);
        Assert.Equal("GyM_p6JrXySiz1toFgKbWV-JdI3jQ4ypu9rbMWx3rQJBfmt0FoYzgUIZEVFEcOqwemRN81zoDAaa-Bk0KWNGDjJHZDdDmFhW3AN7lI-puxk_mHZGJ11rxyR8O55XLSe3SPmRfKwZI6yU24ZxvQKFYItdldUKGzO6Ia6zTKhAVRU", jwk.QI);
        Assert.Equal("RS256", jwk.Alg);
        Assert.Equal("2011-04-29", jwk.Kid);

        RSA? rsa = jwk.GetRSAPrivateKey();
        Assert.NotNull(rsa);

        jwk = rsa.GetJwk(true);
        Assert.NotNull(jwk);
        Assert.Equal("RSA", jwk.Kty);
        Assert.Equal("AQAB", jwk.E);
        Assert.Equal("0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw", jwk.N);
        Assert.Equal("X4cTteJY_gn4FYPsXB8rdXix5vwsg1FLN5E3EaG6RJoVH-HLLKD9M7dx5oo7GURknchnrRweUkC7hT5fJLM0WbFAKNLWY2vv7B6NqXSzUvxT0_YSfqijwp3RTzlBaCxWp4doFk5N2o8Gy_nHNKroADIkJ46pRUohsXywbReAdYaMwFs9tv8d_cPVY3i07a3t8MN6TNwm0dSawm9v47UiCl3Sk5ZiG7xojPLu4sbg1U2jx4IBTNBznbJSzFHK66jT8bgkuqsk0GjskDJk19Z4qwjwbsnn4j2WBii3RL-Us2lGVkY8fkFzme1z0HbIkfz0Y6mqnOYtqc0X4jfcKoAC8Q", jwk.D);
        Assert.Equal("83i-7IvMGXoMXCskv73TKr8637FiO7Z27zv8oj6pbWUQyLPQBQxtPVnwD20R-60eTDmD2ujnMt5PoqMrm8RfmNhVWDtjjMmCMjOpSXicFHj7XOuVIYQyqVWlWEh6dN36GVZYk93N8Bc9vY41xy8B9RzzOGVQzXvNEvn7O0nVbfs", jwk.P);
        Assert.Equal("3dfOR9cuYq-0S-mkFLzgItgMEfFzB2q3hWehMuG0oCuqnb3vobLyumqjVZQO1dIrdwgTnCdpYzBcOfW5r370AFXjiWft_NGEiovonizhKpo9VVS78TzFgxkIdrecRezsZ-1kYd_s1qDbxtkDEgfAITAG9LUnADun4vIcb6yelxk", jwk.Q);
        Assert.Equal("G4sPXkc6Ya9y8oJW9_ILj4xuppu0lzi_H7VTkS8xj5SdX3coE0oimYwxIi2emTAue0UOa5dpgFGyBJ4c8tQ2VF402XRugKDTP8akYhFo5tAA77Qe_NmtuYZc3C3m3I24G2GvR5sSDxUyAN2zq8Lfn9EUms6rY3Ob8YeiKkTiBj0", jwk.DP);
        Assert.Equal("s9lAH9fggBsoFR8Oac2R_E2gw282rT2kGOAhvIllETE1efrA6huUUvMfBcMpn8lqeW6vzznYY5SSQF7pMdC_agI3nG8Ibp1BUb0JUiraRNqUfLhcQb_d9GF4Dh7e74WbRsobRonujTYN1xCaP6TO61jvWrX-L18txXw494Q_cgk", jwk.DQ);
        Assert.Equal("GyM_p6JrXySiz1toFgKbWV-JdI3jQ4ypu9rbMWx3rQJBfmt0FoYzgUIZEVFEcOqwemRN81zoDAaa-Bk0KWNGDjJHZDdDmFhW3AN7lI-puxk_mHZGJ11rxyR8O55XLSe3SPmRfKwZI6yU24ZxvQKFYItdldUKGzO6Ia6zTKhAVRU", jwk.QI);
    }

    [Fact(DisplayName = "Decode HMAC")]
    public void DecodeHMAC()
    {
        JwkSymmetric? jwk = JsonSerializer.Deserialize<Jwk>(JWK_SYMMETRIC, JwkConstants.jsonOptions) as JwkSymmetric;

        Assert.NotNull(jwk);
        Assert.Equal("AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow", jwk.K);
        Assert.Equal("HMAC_1", jwk.Kid);

        byte[]? hmac = jwk.GetSymmetricKey();
        Assert.NotNull(hmac);

        jwk = hmac.GetJwk();
        Assert.NotNull(jwk);
        Assert.Equal("AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow", jwk.K);
    }
}
