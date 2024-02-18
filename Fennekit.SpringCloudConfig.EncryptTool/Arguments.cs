using System.CommandLine;

namespace Fennekit.SpringCloudConfig.EncryptTool;

public static class Arguments
{
    public static Argument<string> AesKey => new("key", "Key to use.");
    public static Argument<string> PlainText => new("plaintext", "Plaintext to encrypt");
    
    public static Argument<string> cipherText = new("cipher text", "Ciphertext to decrypt");
}