using NUnit.Framework;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;


namespace Fennekit.SpringCloudConfig.Decrypt.Test;

public class KeyProviderTests
{
    [Test]
    [TestCaseSource(nameof(GetTestVector))]
    public void DecodeTestForSpringConfigCipher(string salt, string algorithm, string cipher, string plainText)
    {
        KeyStoreDecryptor decryptor = new KeyStoreDecryptor("server.jks", "letmein", "mytestkey");
        var decrypted = decryptor.Decrypt(cipher);
        
        Assert.That(decrypted, Is.EqualTo(plainText));
    }
    
    static IEnumerable<object[]> GetTestVector()
    {
        yield return new[]
        {
            "deadbeef",
            "DEFAULT",
            "AQATBPXCmri0MCEoCam0noXJgKGlFfE/chVN7XhH1V23MqJ8sI3lI61PyvsryJP3LlfNn38gUuulMeslAs/gUCoPFPV/zD7M8x527wQUbmWD6bR0ZMJ4hu3DisK6Diw2YAOxXSsm3Zh46cPFQcowfOG1x2OXj+5uL4T+VBGdt3Nr6dHCOumkTJ1KAtaJMfASf3J8G4M27v6m4Y2EdBqP1zWwDhAZ3R0u9uTP9xYUqQiKsUeOixrhOaCvtb1Q+Zg6A41CxM4cjL3Ty6miNYLx3QkxRvfkdo0iqo7jTrWWAT1aeRV6t5U5iMlWnD4eXzad60E3ZSINhvDiB03xPPPuHKC6qUTRJEEbQFegmn/KIPMMn9WaH/JLLZNvQYMuaFszZ84AE3aQcH0be+sNFDSjHNHL",
            "encrypt the world"
        }; 
        
        yield return new[]
        {
            "deadbeef",
            "DEFAULT",
            "AQBoZM07gyw+GN0SXCkARLiSDjhN0flk07QP9+BsNnPEQD+alfH6A5FJwwuEf7d/kNJozppaZuHcPpDnRZbzmsRcqOcO0BiJFjsbX5K9o8jcAsGhDmLAf0jy/Ry1de6bELjZ4MPArbVN9numHTre4plXBXun2AVeNNBYG3yHed0A68o6FCc6UR/Pfdo/H+oTburn2qVKaZL+DAqIKHntcZjTLg/ZRa7MKUMCKiFEtV88U3lg+1YUqgz+XUmg2zyUsHgHNzYlTOtJWkFW51wNz/M2C92Zsu4R6bF1ewb2RM0N8VmjQAw6GpfLNX+CB3gGlDPsfGjc9qiF3zNsJSk88dm1+NruXeon5Nth691NQJ6DpgMXhhFzv7L/eyZKL/kZpGIVZK6dW3iePzsBtuFdrjiZ",
            "encrypt the world"
        };
        
        yield return new[]
        {
            "deadbeef",
            "DEFAULT",
            "AQAVdtG0YlWOZkQKqpIKzNkHOJRyTfjD0nZeNvB8lk/XpYMYLsql2aa4O0kPZx4Us9f/jR+q6CAjLveJ425huFeQkpHZ96Hwkru7FxZQ6aWoJRZtdQICedmd7co+xFklFYzpghDbhfluLRfpG0aPpMDwdjzEHevP0kyvckinfLfrcJ6zW0YSic8KvPT1RsjUu5jKOC0uGpJAEfNzngHgnTg0l5COgX7V1z4WLVwEDv0Z6YXY62BSW1pJM4eveFJEICggE4x9+FIVG4l4TJ0mhawYeh4vukqOQTZfu30z3tLfrd/WXzNLvkzY9O6ZhneoFMK+fpo9ZVZVN8rrRqvYpmKj4hYaEb6R1GumUWwVwLiYSW/n2Hl/bBuvFdmuvV6oYteBM1WsU/WgPx6SHG9bRsTg",
            "encrypt the world"
        };
    }
    

}

