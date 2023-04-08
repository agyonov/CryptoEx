using CryptoEx.Utils;

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

    [Fact(DisplayName = "Test Base64Url decode data")]
    public void Test_Base64UrlDecode()
    {
        Assert.False(!compareArrays(Base64UrlEncoder.Decode(inStrFix), inByteFix));
        Assert.False(!compareArrays(Base64UrlEncoder.Decode(inStrOne), inByteOne));
        Assert.False(!compareArrays(Base64UrlEncoder.Decode(inStrTwo), inByteTwo));
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
