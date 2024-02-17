using NUnit.Framework;

namespace Fennekit.SpringCloudConfig.Decrypt.Test;

public class RsaKeyStoreEncryptionTest
{

    [Test]
    [TestCaseSource(nameof(GetTestVector))]
    public void EncryptionShouldBeDecryptable(string salt, string strong, string algorithm, string plainText)
    {
        var decryptor = new RsaKeyStoreDecryptor("server.jks", "letmein", "mytestkey", salt: salt,
            strong: bool.Parse(strong), algorithm: algorithm);

        var encrypt = decryptor.Encrypt(plainText);
        var decrypted = decryptor.Decrypt(encrypt);

        Assert.That(decrypted, Is.EqualTo(plainText));
    }
    
    [Test]
    [TestCaseSource(nameof(GetTestVector))]
    public void EncryptionShouldAlwaysBeDifferent(string salt, string strong, string algorithm, string plainText)
    {
        var decryptor = new RsaKeyStoreDecryptor("server.jks", "letmein", "mytestkey", salt: salt,
            strong: bool.Parse(strong), algorithm: algorithm);

        var encrypt1 = decryptor.Encrypt(plainText);
        var encrypt2 = decryptor.Encrypt(plainText);
        
        Assert.That(encrypt1, Is.Not.EqualTo(encrypt2));
    }

    private static IEnumerable<object[]> GetTestVector()
    {
        yield return
        [
            "deadbeef",
            "false",
            "OAEP",
            "encrypt the world"
        ];

        yield return
        [
            "beefdead",
            "true",
            "OAEP",
            "encrypt the world"
        ];


        yield return
        [
            "beefdead",
            "true",
            "DEFAULT",
            "encrypt the world"
        ];
        
        yield return
        [
            "nohexsaltvalue",
            "true",
            "DEFAULT", 
            "encrypt the world"
        ];
        
    }
}