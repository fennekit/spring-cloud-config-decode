using System.CommandLine;
using Fennekit.SpringCloudConfig.Decrypt;
using Fennekit.SpringCloudConfig.EncryptTool;

var encryptCommand = new Command("encrypt", "Encrypt plaintext");
var aesEncryptCommand = new Command("aes", "Encrypt with AES")
{
    Options.AesSalt,
    Options.AesStrong
};
encryptCommand.AddCommand(aesEncryptCommand);
aesEncryptCommand.Add(Arguments.AesKey);
aesEncryptCommand.Add(Arguments.PlainText);
aesEncryptCommand.SetHandler((salt, strong, key, plainText) =>
{
    try
    {
        var decryptor = new AesTextDecryptor(key, salt, strong);
        Console.WriteLine();
        Console.WriteLine(decryptor.Encrypt(plainText));
        Console.WriteLine();
    }
    catch (Exception ex)
    {
        Console.WriteLine(ex.Message);
        Environment.Exit(-1);
    }
}, Options.AesSalt, Options.AesStrong, Arguments.AesKey, Arguments.PlainText);


var rsaEncryptCommand = new Command("rsa", "Encrypt with RSA")
{
    Options.AesSalt,
    Options.AesStrong,
    Options.KeystoreFilename,
    Options.KeyAlias,
    Options.KeystorePassword,
    Options.Algorithm
};
rsaEncryptCommand.Add(Arguments.PlainText);
rsaEncryptCommand.SetHandler((salt, strong, filename, keyAlias, keystorePassword, algorithm, plainText) =>
    {
         try
        {
            var decryptor =
                new RsaKeyStoreDecryptor(filename, keystorePassword, keyAlias, salt, strong, algorithm.ToString());
            Console.WriteLine();
            Console.WriteLine(decryptor.Encrypt(plainText));
            Console.WriteLine();
        }
        catch (Exception ex)
        {
            Console.WriteLine(ex.Message);
            Environment.Exit(-1);
        }
    }, Options.AesSalt, Options.AesStrong, Options.KeystoreFilename, Options.KeyAlias, Options.KeystorePassword,
    Options.Algorithm, Arguments.PlainText);
encryptCommand.AddCommand(rsaEncryptCommand);


var decryptCommand = new Command("decrypt", "Decrypt ciphertext");
var aesDecryptCommand = new Command("aes", "Decrypt with AES")
{
    Options.AesSalt,
    Options.AesStrong
};
aesDecryptCommand.Add(Arguments.AesKey);
aesDecryptCommand.Add(Arguments.CipherText);
aesDecryptCommand.SetHandler((salt, strong, key, cipher) =>
{
    try
    {
        var decryptor = new AesTextDecryptor(key, salt, strong);
        Console.WriteLine();
        Console.WriteLine(decryptor.Decrypt(cipher));
        Console.WriteLine();
    }
    catch (Exception ex)
    {
        Console.WriteLine(ex.Message);
        Environment.Exit(-1);
    }
}, Options.AesSalt, Options.AesStrong, Arguments.AesKey, Arguments.CipherText);
decryptCommand.AddCommand(aesDecryptCommand);

var rsaDecryptCommand = new Command("rsa", "Decrypt with RSA")
{
    Options.AesSalt,
    Options.AesStrong,
    Options.KeystoreFilename,
    Options.KeyAlias,
    Options.KeystorePassword,
    Options.Algorithm
};
rsaDecryptCommand.Add(Arguments.CipherText);
rsaDecryptCommand.SetHandler((salt, strong, filename, keyAlias, keystorePassword, algorithm, cipherText) =>
    {
        try
        {
            var decryptor =
                new RsaKeyStoreDecryptor(filename, keystorePassword, keyAlias, salt, strong, algorithm.ToString());
            Console.WriteLine();
            Console.WriteLine(decryptor.Decrypt(cipherText));
            Console.WriteLine();
        }
        catch (Exception ex)
        {
            Console.WriteLine(ex.Message);
            Environment.Exit(-1);
        }
    }, Options.AesSalt, Options.AesStrong, Options.KeystoreFilename, Options.KeyAlias, Options.KeystorePassword,
    Options.Algorithm, Arguments.CipherText);
decryptCommand.AddCommand(rsaDecryptCommand);

var rootCommand = new RootCommand(
    "Encryption for Spring Boot Cloud (https://docs.spring.io/spring-cloud-config/docs/current/reference/html/#_encryption_and_decryption) config and Steeltoe.Encryption (https://github.com/SteeltoeOSS/Documentation/blob/v4/api/v4/configuration/encryption-resolver.md).");

rootCommand.AddCommand(encryptCommand);
rootCommand.AddCommand(decryptCommand);

await rootCommand.InvokeAsync(args);