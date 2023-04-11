using CryptoEx.Utils;
using System.Text;

namespace CryptoEx.Tests;
public class TestBase64Url
{

    private static byte[] inByteFix = { 0x3f, 0x2f, 0x1f, 0x0f, 0x3e, 0x3d, 0x3c, 0x3b, 0x3a };
    private static byte[] inByteOne = { 0x3f, 0x2f, 0x1f, 0x0f, 0x3e, 0x3d, 0x3c, 0x3b };
    private static byte[] inByteTwo = { 0x3f, 0x2f, 0x1f, 0x0f, 0x3e, 0x3d, 0x3c };

    private static string inStrFix = "Py8fDz49PDs6";
    private static string inStrOne = "Py8fDz49PDs";
    private static string inStrTwo = "Py8fDz49PA";

    [Fact(DisplayName = "Test Base64Url encode data")]
    public void Test_Base64UrlEncode()
    {
        Assert.False(string.Compare(Base64UrlEncoder.Encode(inByteFix), inStrFix) != 0);
        Assert.False(string.Compare(Base64UrlEncoder.Encode(inByteOne), inStrOne) != 0);
        Assert.False(string.Compare(Base64UrlEncoder.Encode(inByteTwo), inStrTwo) != 0);
    }

    [Fact(DisplayName = "Test Base64Url encode data streamed")]
    public void Test_Base64UrlEncodeStream()
    {
        byte[] res = new byte[12];
        using (MemoryStream ms = new(inByteFix))
        using (StreamWriter sw = new(new MemoryStream(res, true), Encoding.ASCII)) {
            Base64UrlEncoder.Encode(ms, sw);
        }
        Assert.False(string.Compare(Encoding.ASCII.GetString(res), inStrFix) != 0);

        byte[] resOne = new byte[11];
        using (MemoryStream ms = new(inByteOne))
        using (StreamWriter sw = new(new MemoryStream(resOne, true), Encoding.ASCII)) {
            Base64UrlEncoder.Encode(ms, sw);
        }
        Assert.False(string.Compare(Encoding.ASCII.GetString(resOne), inStrOne) != 0);

        byte[] resTwo = new byte[10];
        using (MemoryStream ms = new(inByteTwo))
        using (StreamWriter sw = new(new MemoryStream(resTwo, true), Encoding.ASCII)) {
            Base64UrlEncoder.Encode(ms, sw);
        }
        Assert.False(string.Compare(Encoding.ASCII.GetString(resTwo), inStrTwo) != 0);
    }

    [Fact(DisplayName = "Test Base64Url encode data streamed asynchronious")]
    public async Task Test_Base64UrlEncodeStreamAsync()
    {
        byte[] res = new byte[12];
        using (MemoryStream ms = new(inByteFix))
        using (StreamWriter sw = new(new MemoryStream(res, true), Encoding.ASCII)) {
            await Base64UrlEncoder.EncodeAsync(ms, sw);
        }
        Assert.False(string.Compare(Encoding.ASCII.GetString(res), inStrFix) != 0);

        byte[] resOne = new byte[11];
        using (MemoryStream ms = new(inByteOne))
        using (StreamWriter sw = new(new MemoryStream(resOne, true), Encoding.ASCII)) {
            await Base64UrlEncoder.EncodeAsync(ms, sw);
        }
        Assert.False(string.Compare(Encoding.ASCII.GetString(resOne), inStrOne) != 0);

        byte[] resTwo = new byte[10];
        using (MemoryStream ms = new(inByteTwo))
        using (StreamWriter sw = new(new MemoryStream(resTwo, true), Encoding.ASCII)) {
            await Base64UrlEncoder.EncodeAsync(ms, sw);
        }
        Assert.False(string.Compare(Encoding.ASCII.GetString(resTwo), inStrTwo) != 0);
    }

    [Fact(DisplayName = "Test Base64Url decode data")]
    public void Test_Base64UrlDecode()
    {
        Assert.False(!compareArrays(Base64UrlEncoder.Decode(inStrFix), inByteFix));
        Assert.False(!compareArrays(Base64UrlEncoder.Decode(inStrOne), inByteOne));
        Assert.False(!compareArrays(Base64UrlEncoder.Decode(inStrTwo), inByteTwo));
    }

    [Fact(DisplayName = "Test Base64Url decode data streamed")]
    public void Test_Base64UrlDecodeStream()
    {
        byte[] res = new byte[9];
        using (StringReader sr = new(inStrFix))
        using (MemoryStream ms = new(res, true)) {
            Base64UrlEncoder.Decode(sr, ms);
        }
        Assert.False(!compareArrays(res, inByteFix));

        byte[] resOne = new byte[8];
        using (StringReader sr = new(inStrOne))
        using (MemoryStream ms = new(resOne, true)) {
            Base64UrlEncoder.Decode(sr, ms);
        }
        Assert.False(!compareArrays(resOne, inByteOne));

        byte[] resTwo = new byte[7];
        using (StringReader sr = new(inStrTwo))
        using (MemoryStream ms = new(resTwo, true)) {
            Base64UrlEncoder.Decode(sr, ms);
        }
        Assert.False(!compareArrays(resTwo, inByteTwo));
    }

    [Fact(DisplayName = "Test Base64Url decode data streamed asynchronous")]
    public async Task Test_Base64UrlDecodeStreamAsync()
    {
        byte[] res = new byte[9];
        using (StringReader sr = new(inStrFix))
        using (MemoryStream ms = new(res, true)) {
            await Base64UrlEncoder.DecodeAsync(sr, ms);
        }
        Assert.False(!compareArrays(res, inByteFix));

        byte[] resOne = new byte[8];
        using (StringReader sr = new(inStrOne))
        using (MemoryStream ms = new(resOne, true)) {
            await Base64UrlEncoder.DecodeAsync(sr, ms);
        }
        Assert.False(!compareArrays(resOne, inByteOne));

        byte[] resTwo = new byte[7];
        using (StringReader sr = new(inStrTwo))
        using (MemoryStream ms = new(resTwo, true)) {
            await Base64UrlEncoder.DecodeAsync(sr, ms);
        }
        Assert.False(!compareArrays(resTwo, inByteTwo));
    }

    private bool compareArrays(byte[] arrS, byte[] arrT)
    {
        if (arrS.Length != arrT.Length) {
            return false;
        }

        for (int i = 0; i < arrS.Length; i++) {
            if (arrS[i] != arrT[i]) {
                return false;
            }
        }

        return true;
    }
}
