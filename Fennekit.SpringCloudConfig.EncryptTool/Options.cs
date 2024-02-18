using System.CommandLine;

namespace Fennekit.SpringCloudConfig.EncryptTool;

public static class Options
{
    static Options()
    {
        AesSalt = new(
            "--salt",
            description: "Salt value to use.",
            getDefaultValue: () => "deadbeef");
        AesStrong = new(
            "--strong",
            description: "Use strong encryption (AES/GCM/NoPadding) or not (AES/CBC/PKCS5Padding)",
            getDefaultValue: () => false);
        KeystoreFilename = new(
            name: "--keystore",
            description: "Keystore containing the private and/or public key"
        );
        KeyAlias = new(
            name: "--alias",
            description: "Alias of the key in the store"
        );
        
        KeystorePassword = new(
            name: "--password",
            description: "Password of the store",
            getDefaultValue: () => ""
        );
        
        Algorithm = new(
            name: "--algorithm",
            description: "RSA algorhitm to use DEFAULT (RSA/NONE/PKCS1Padding) or OAEP (RSA/ECB/PKCS1)",
            getDefaultValue: () => RsaAlgorithm.DEFAULT
        );
    }
    
    public static Option<string> AesSalt { get; }
    
    public static Option<bool> AesStrong { get; }

    public static Option<string> KeystoreFilename { get; }

    public static Option<string> KeyAlias { get; }

    public static Option<string> KeystorePassword { get; }

    public static Option<RsaAlgorithm> Algorithm { get; }
}