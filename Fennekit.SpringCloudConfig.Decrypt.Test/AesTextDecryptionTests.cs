using NUnit.Framework;

namespace Fennekit.SpringCloudConfig.Decrypt.Test;

public class AesTextDecryptionTests
{
    [Test]
    [TestCaseSource(nameof(GetTestVector))]
    public void DecodeTestForSpringConfigCipher(string salt, string key, string plainText)
    {
        var textDecryptor = new AesTextDecryptor(key, salt);
        var cipher = textDecryptor.Encrypt(plainText);
        var decrypted = textDecryptor.Decrypt(cipher);
        Assert.That(decrypted, Is.EqualTo(plainText));
    }

    private static IEnumerable<object[]> GetTestVector()
    {
        yield return
        [
            "deadbeef",
            "12345678901234567890",
            "encrypt the world"
        ]; 
    }
}