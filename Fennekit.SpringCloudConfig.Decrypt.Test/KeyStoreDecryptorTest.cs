using NUnit.Framework;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;


namespace Fennekit.SpringCloudConfig.Decrypt.Test;

public class KeyStoreDecryptorTest
{
    [Test]
    [TestCaseSource(nameof(GetTestVector))]
    public void DecodeTestForSpringConfigCipher(string salt, string strong, string algorithm, string cipher, string plainText)
    {
        KeyStoreDecryptor decryptor = new KeyStoreDecryptor("server.jks", "letmein", "mytestkey", salt: salt, strong: Boolean.Parse(strong));
        var decrypted = decryptor.Decrypt(cipher);
        
        Assert.That(decrypted, Is.EqualTo(plainText));
    }
    
    static IEnumerable<object[]> GetTestVector()
    {
        yield return new[]
        {
            "deadbeef",
            "false",
            "DEFAULT",
            "AQATBPXCmri0MCEoCam0noXJgKGlFfE/chVN7XhH1V23MqJ8sI3lI61PyvsryJP3LlfNn38gUuulMeslAs/gUCoPFPV/zD7M8x527wQUbmWD6bR0ZMJ4hu3DisK6Diw2YAOxXSsm3Zh46cPFQcowfOG1x2OXj+5uL4T+VBGdt3Nr6dHCOumkTJ1KAtaJMfASf3J8G4M27v6m4Y2EdBqP1zWwDhAZ3R0u9uTP9xYUqQiKsUeOixrhOaCvtb1Q+Zg6A41CxM4cjL3Ty6miNYLx3QkxRvfkdo0iqo7jTrWWAT1aeRV6t5U5iMlWnD4eXzad60E3ZSINhvDiB03xPPPuHKC6qUTRJEEbQFegmn/KIPMMn9WaH/JLLZNvQYMuaFszZ84AE3aQcH0be+sNFDSjHNHL",
            "encrypt the world"
        }; 
        
        yield return new[]
        {
            "deadbeef",
            "false",
            "DEFAULT",
            "AQBoZM07gyw+GN0SXCkARLiSDjhN0flk07QP9+BsNnPEQD+alfH6A5FJwwuEf7d/kNJozppaZuHcPpDnRZbzmsRcqOcO0BiJFjsbX5K9o8jcAsGhDmLAf0jy/Ry1de6bELjZ4MPArbVN9numHTre4plXBXun2AVeNNBYG3yHed0A68o6FCc6UR/Pfdo/H+oTburn2qVKaZL+DAqIKHntcZjTLg/ZRa7MKUMCKiFEtV88U3lg+1YUqgz+XUmg2zyUsHgHNzYlTOtJWkFW51wNz/M2C92Zsu4R6bF1ewb2RM0N8VmjQAw6GpfLNX+CB3gGlDPsfGjc9qiF3zNsJSk88dm1+NruXeon5Nth691NQJ6DpgMXhhFzv7L/eyZKL/kZpGIVZK6dW3iePzsBtuFdrjiZ",
            "encrypt the world"
        };
        
        yield return new[]
        {
            "beefdead",
            "true",
            "DEFAULT",
            "AQAbWqohCeQ+TTqyJ3ZlNvAtx5cC2I3PmJetuSR82yRRyX+wWd7mTkUXuN/wANJ+nr1ySdzPudjml1lHaxZn42I9szkIKSkNT+6Yg+zNaREMetcE5SXA1awtSbEaFY2NcualSzPVWs8ulsUkKlYyyh6XP9gT/kODbmX0mS6DCtxalJgjei7WujLaJaPjc3jk+EhV9M1TovexqI7XoLlsgrGf6/1gQE+SSOamTFJopWpYEeSpSEwY2dXZfct5KCFWGJVA7eDPRJk0dT6EWIvqd6J4YoMWonxgVy4nG/Gq0NTisXv9XpJHAPYBg0c8B0WrWi2PG/Q00wvFRqGmYQ1hQIVmbJm8z+f0WoCxKwnCZvvdLlgrx2qeK1S21dPdgtmLXlj5bRUrektFrNhlevlENW7wgg==",
            "encrypt the world"
        };
        
    }
    

}

