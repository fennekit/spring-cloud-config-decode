using NUnit.Framework;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;


namespace Fennekit.SpringCloudConfig.Decrypt.Test;

public class RsaKeyStoreDecryptorTest
{
    [Test]
    public void CreateWithUnsupportedAlgorithmThrows()
    {
        Assert.Throws(typeof(ArgumentException),
            () => new RsaKeyStoreDecryptor("server.jks", "letmein", "mytestkey", algorithm: "Exception"));
    }

    [Test]
    [TestCaseSource(nameof(GetTestVector))]
    public void DecodeTestForSpringConfigCipher(string salt, string strong, string algorithm, string cipher,
        string plainText)
    {
        RsaKeyStoreDecryptor decryptor = new RsaKeyStoreDecryptor("server.jks", "letmein", "mytestkey", salt: salt,
            strong: Boolean.Parse(strong), algorithm: algorithm);
        var decrypted = decryptor.Decrypt(cipher);

        Assert.That(decrypted, Is.EqualTo(plainText));
    }

    static IEnumerable<object[]> GetTestVector()
    {
        yield return new[]
        {
            "deadbeef",
            "false",
            "OAEP",
            "AQATBPXCmri0MCEoCam0noXJgKGlFfE/chVN7XhH1V23MqJ8sI3lI61PyvsryJP3LlfNn38gUuulMeslAs/gUCoPFPV/zD7M8x527wQUbmWD6bR0ZMJ4hu3DisK6Diw2YAOxXSsm3Zh46cPFQcowfOG1x2OXj+5uL4T+VBGdt3Nr6dHCOumkTJ1KAtaJMfASf3J8G4M27v6m4Y2EdBqP1zWwDhAZ3R0u9uTP9xYUqQiKsUeOixrhOaCvtb1Q+Zg6A41CxM4cjL3Ty6miNYLx3QkxRvfkdo0iqo7jTrWWAT1aeRV6t5U5iMlWnD4eXzad60E3ZSINhvDiB03xPPPuHKC6qUTRJEEbQFegmn/KIPMMn9WaH/JLLZNvQYMuaFszZ84AE3aQcH0be+sNFDSjHNHL",
            "encrypt the world"
        };

        yield return new[]
        {
            "deadbeef",
            "false",
            "OAEP",
            "AQBoZM07gyw+GN0SXCkARLiSDjhN0flk07QP9+BsNnPEQD+alfH6A5FJwwuEf7d/kNJozppaZuHcPpDnRZbzmsRcqOcO0BiJFjsbX5K9o8jcAsGhDmLAf0jy/Ry1de6bELjZ4MPArbVN9numHTre4plXBXun2AVeNNBYG3yHed0A68o6FCc6UR/Pfdo/H+oTburn2qVKaZL+DAqIKHntcZjTLg/ZRa7MKUMCKiFEtV88U3lg+1YUqgz+XUmg2zyUsHgHNzYlTOtJWkFW51wNz/M2C92Zsu4R6bF1ewb2RM0N8VmjQAw6GpfLNX+CB3gGlDPsfGjc9qiF3zNsJSk88dm1+NruXeon5Nth691NQJ6DpgMXhhFzv7L/eyZKL/kZpGIVZK6dW3iePzsBtuFdrjiZ",
            "encrypt the world"
        };

        yield return new[]
        {
            "beefdead",
            "true",
            "OAEP",
            "AQAbWqohCeQ+TTqyJ3ZlNvAtx5cC2I3PmJetuSR82yRRyX+wWd7mTkUXuN/wANJ+nr1ySdzPudjml1lHaxZn42I9szkIKSkNT+6Yg+zNaREMetcE5SXA1awtSbEaFY2NcualSzPVWs8ulsUkKlYyyh6XP9gT/kODbmX0mS6DCtxalJgjei7WujLaJaPjc3jk+EhV9M1TovexqI7XoLlsgrGf6/1gQE+SSOamTFJopWpYEeSpSEwY2dXZfct5KCFWGJVA7eDPRJk0dT6EWIvqd6J4YoMWonxgVy4nG/Gq0NTisXv9XpJHAPYBg0c8B0WrWi2PG/Q00wvFRqGmYQ1hQIVmbJm8z+f0WoCxKwnCZvvdLlgrx2qeK1S21dPdgtmLXlj5bRUrektFrNhlevlENW7wgg==",
            "encrypt the world"
        };


        yield return new[]
        {
            "beefdead",
            "true",
            "DEFAULT",
            "AQAhwKArLZqxrc44G2sG6+EwWeqn9JytaIyBpf/Yz2UZ0bLZthR3HPtGgOoKY9AkWpBuRzrw3zQ20ZRkq6q7XU+Stp1kB4OXhrmgbwydNUtYJmuTlpGohtHH8wVoT2n0bd7NuL9rJ2OAbkPXg8K1kJMSgen7Hyg3b+LFZmaA8wCHXdmHuP63Rk4NhSec4Ul/gRRn5jftojmbxVVQ6xRGAeFTZi70oAZ+tzdyXZmukorRZsUtnlgj94aSmGdMCGkukanCiEHHrh130Nigxba4qZ2F2e5n46De7+7EVwnIWWYa2sQH+3BQ+cp5OCebWMiGPdylqZzyTagkwo2jHv/OzW0/ytIF1Qo3AblMQgympSL3/PMPggllopaf2al4o7w63vWczXdv6YzdLchQMrdXRdkLrw==",
            "encrypt the world"
        };
        
        yield return new[]
        {
            "nohexsaltvalue",
            "true",
            "DEFAULT",
            "AQA+sdMQ94WuW7DMBX7ZJQeWaybtFWJqAeVv9kmHyVCwil3yobQPXMxuoF/FGpZgYQu+9JyK52jnuIXiARdyqqaDKxY7ECN/8GLVXdcQi5ooO+ewyOrL53fycyyB2iQtZphbdgmzU2qKQkXvFcWQkauHCCtni6IemITLX/y9O3I6Ss9LEK86lSAWKD1Tikf9ly78vJsCJ01ahQhEQVMbkpTixnnFRgqSL7XZo+2FGMvsyYKHp9pQwEnLkbehI8AFODQlFsTcQ9YYab5lGa4OoYw+5oS3fFH8XlIvVSTfxipI18iyphppz3EefvuGd8FwgSGCbfIeQ2R2zcYxykfWgCgSH5ckev2EqeLaiyaK3tXFanumQBeLiSg7Uii80jg9LLJ62jyrR16m0+8CGqaw6uzZkQ==",
            "encrypt the world"
        };
    }
}