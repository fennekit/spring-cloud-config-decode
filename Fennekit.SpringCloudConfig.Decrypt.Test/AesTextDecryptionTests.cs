using NUnit.Framework;

namespace Fennekit.SpringCloudConfig.Decrypt.Test;

public class AesTextDecryptionTests
{
    [Test]
    [TestCaseSource(nameof(GetTestVector))]
    public void EncryptionShouldBeDecryptable(string salt, string key, string plainText)
    {
        var textDecryptor = new AesTextDecryptor(key, salt);
        var cipher = textDecryptor.Encrypt(plainText);
        var decrypted = textDecryptor.Decrypt(cipher);
        Assert.That(decrypted, Is.EqualTo(plainText));
    }

    [Test]
    [TestCaseSource(nameof(GetTestVector))]
    public void EncryptionShouldAlwaysBeDifferent(string salt, string key, string plainText)
    {
        var decryptor = new AesTextDecryptor(key, salt);
          
        var encrypt1 = decryptor.Encrypt(plainText);
        var encrypt2 = decryptor.Encrypt(plainText);
        
        Assert.That(encrypt1, Is.Not.EqualTo(encrypt2));
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