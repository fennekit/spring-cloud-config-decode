using System.CommandLine;

namespace Fennekit.SpringCloudConfig.EncryptTool;

public static class Arguments
{
    static Arguments()
    {
        AesKey = new("key", "Key to use.");
        PlainText =new("plaintext", "Plaintext to encrypt");
        CipherText = new("cipher text", "Ciphertext to decrypt");
    }
    
    public static Argument<string> AesKey { get; }
    public static Argument<string> PlainText { get; }
    public static Argument<string> CipherText { get; }
}