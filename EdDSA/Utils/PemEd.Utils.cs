using System.Globalization;
using System.Text;

namespace EdDSA.Utils;
public static partial class PemEd
{
    /// <summary>
    /// Read hex encoded bytestring into byte array
    /// </summary>
    /// <param name="src">The string</param>
    /// <returns>The byte array</returns>
    public static byte[] HexToByte(ReadOnlySpan<char> src)
    {
        byte[] res = new byte[src.Length / 2];
        for (int loop = 0; loop < src.Length; loop += 2) {
            res[loop / 2] = byte.Parse(src[loop..(loop + 2)], NumberStyles.HexNumber);
        }
        return res;
    }

    /// <summary>
    /// Write byte array as hex encoded bytestring
    /// </summary>
    /// <param name="src">The byte array</param>
    /// <returns>The encoded string</returns>
    public static string ByteToHex(ReadOnlySpan<byte> src)
    {
        StringBuilder sb = new StringBuilder();
        foreach (byte b in src) {
            sb.Append(b.ToString("X2"));
        }
        return sb.ToString();
    }
}
