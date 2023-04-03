using System.Text;


namespace EdDSA.Utils;

/// <summary>
/// Encodes and Decodes strings as Base64Url encoding.
/// </summary>
public static class Base64UrlEncoder
{
    /// <summary>
    /// The following functions perform base64url encoding which differs from regular base64 encoding as follows
    /// * padding is skipped so the pad character '=' doesn't have to be percent encoded
    /// * the 62nd and 63rd regular base64 encoding characters ('+' and '/') are replace with ('-' and '_')
    /// The changes make the encoding alphabet file and URL safe.
    /// </summary>
    /// <param name="arg">string to encode.</param>
    /// <returns>Base64Url encoding of the UTF8 bytes.</returns>
    public static string Encode(ReadOnlySpan<byte> arg)
    {
        string wrk = Convert.ToBase64String(arg);
        StringBuilder sb = new StringBuilder(wrk.Length);

        for (int loop = 0; loop < wrk.Length; loop++) {
            sb.Append(wrk[loop] switch
            {
                '+' => '-',
                '/' => '_',
                _ => wrk[loop]
            });
        }

        if (wrk.EndsWith("==")) {
            sb.Remove(wrk.Length - 2, 2);
        } else if (wrk.EndsWith('=')) {
            sb.Remove(wrk.Length - 1, 1);
        }

        return sb.ToString();
    }

    /// <summary>
    /// Converts the specified string, base-64-url encoded to  bytes.</summary>
    /// <param name="str">base64Url encoded string.</param>
    /// <returns>UTF8 bytes.</returns>
    public static byte[] Decode(string str)
    {
        StringBuilder sb = new StringBuilder(str.Length);

        for (int loop = 0; loop < str.Length; loop++) {
            sb.Append(str[loop] switch
            {
                '-' => '+',
                '_' => '/',
                _ => str[loop]
            });
        }
        int rem = sb.Length % 3;
        if (rem == 1) {
            sb.Append("==");
        } else if (rem == 2) {
            sb.Append('=');
        }

        return Convert.FromBase64String(sb.ToString());
    }
}
