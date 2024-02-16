using NUnit.Framework;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;


namespace Fennekit.SpringCloudConfig.Decrypt.Test;

public class RsaKeyStoreDecryptionTest
{

    [Test]
    [TestCaseSource(nameof(GetTestVector))]
    public void DecodeTestForSpringConfigCipher(string salt, string strong, string algorithm, string plainText)
    {
        RsaKeyStoreDecryptor decryptor = new RsaKeyStoreDecryptor("server.jks", "letmein", "mytestkey", salt: salt,
            strong: Boolean.Parse(strong), algorithm: algorithm);

        var encrypt = decryptor.Encrypt(plainText);
        var decrypted = decryptor.Decrypt(encrypt);

        Assert.That(decrypted, Is.EqualTo(plainText));
    }

    static IEnumerable<object[]> GetTestVector()
    {
        yield return new[]
        {
            "deadbeef",
            "false",
            "OAEP",
            "encrypt the world"
        };

        yield return new[]
        {
            "beefdead",
            "true",
            "OAEP",
            "encrypt the world"
        };


        yield return new[]
        {
            "beefdead",
            "true",
            "DEFAULT",
            "encrypt the world"
        };
        
        yield return new[]
        {
            "nohexsaltvalue",
            "true",
            "DEFAULT", 
            "encrypt the world"
        };
        
    }
}