using System.CommandLine;

namespace Fennekit.SpringCloudConfig.EncryptTool;

public static class Options
{
    public static Option<string> AesSalt => new(
        "--salt",
        description: "Salt value to use.",
        getDefaultValue: () => "deadbeef");

    public static Option<bool> AesStrong => new(
        "--strong",
        description: "Use strong encryption (AES/GCM/NoPadding) or not (AES/CBC/PKCS5Padding)",
        getDefaultValue: () => false);

    public static Option<string> KeystoreFilename => new(
        name: "--keystore",
        description: "Keystore containing the private and/or public key"
    );

    public static Option<string> KeyAlias => new(
        name: "--alias",
        description: "Alias of the key in the store"
    );

    public static Option<string> KeystorePassword => new(
        name: "--password",
        description: "Password of the store",
        getDefaultValue: () => ""
    );

    public static Option<RsaAlgorithm> Algorithm => new(
        name: "--algorithm",
        description: "RSA algorhitm to use DEFAULT (RSA/NONE/PKCS1Padding) or OAEP (RSA/ECB/PKCS1)",
        getDefaultValue: () => RsaAlgorithm.DEFAULT
    );
}