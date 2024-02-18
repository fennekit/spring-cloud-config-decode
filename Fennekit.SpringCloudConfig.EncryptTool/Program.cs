using System.CommandLine;
using Fennekit.SpringCloudConfig.Decrypt;

var aessalt = new Option<string>(
    "--salt",
    description: "Salt value to us.",
    getDefaultValue: () => "deadbeef");
var aesstrong = new Option<bool>(
    "--strong",
    description: "Use strong encryption (AES/GCM/NoPadding) or not (AES/CBC/PKCS5Padding)",
    getDefaultValue: () => false);

var aeskey = new Argument<string>(
    "key", "Key to use");
var plainText = new Argument<string>(
    "plaintext", "Plaintext to encrypt");
var encryptCommand = new Command("encrypt", "Encrypt plaintext");

var aesEncryptCommand = new Command("aes", "Encrypt with AES")
{
    aessalt,
    aesstrong
};
encryptCommand.AddCommand(aesEncryptCommand);
aesEncryptCommand.Add(aeskey);
aesEncryptCommand.Add(plainText);

aesEncryptCommand.SetHandler((salt, strong, key, text) =>
{
    var decryptor = new AesTextDecryptor(key, salt, strong);
    Console.WriteLine(decryptor.Encrypt(text));
}, aessalt, aesstrong, aeskey, plainText);

var keystoreFilename = new Option<string>(
    name: "--keystore",
    description: "Keystore containing the private and/or public key"
); 
var keyAlias = new Option<string>(
    name: "--alias",
    description: "Alias of the key in the store"
); 
var keystorePassword = new Option<string>(
    name: "--password",
    description: "Password of the store",
    getDefaultValue: () => ""
); 
var algorithm = new Option<string>(
    name: "--algorithm",
    description: "RSA algorhitm to use DEFAULT (RSA/NONE/PKCS1Padding) or OAEP (RSA/ECB/PKCS1)",
    getDefaultValue: () => "DEFAULT"
); 
var rsaEncryptCommand = new Command("rsa", "Encrypt with RSA")
{
    aessalt,
    aesstrong,
    keystoreFilename,
    keyAlias,
    keystorePassword,
    algorithm
};
rsaEncryptCommand.Add(plainText);
encryptCommand.SetHandler((salt, strong, filename, keyAlias, keystorePassword, algorithm, plainText) =>
{
    var decryptor = new RsaKeyStoreDecryptor(filename, keystorePassword, keyAlias, salt, strong, algorithm);
    Console.WriteLine(decryptor.Encrypt(plainText));
}, aessalt, aesstrong, keystoreFilename, keyAlias, keystorePassword, algorithm, plainText);
encryptCommand.AddCommand(rsaEncryptCommand);

var cipherText = new Argument<string>("cipher text", "Ciphertext to decrypt");

var decryptCommand = new Command("decrypt", "Decrypt ciphertext");
var aesDecryptCommand = new Command("aes", "Decrypt with AES")
{
    aessalt,
    aesstrong
};
aesDecryptCommand.Add(aeskey);
aesDecryptCommand.Add(cipherText);
aesDecryptCommand.SetHandler((salt, strong, key, cipher) =>
{
    var decryptor = new AesTextDecryptor(key, salt, strong);
    Console.WriteLine(decryptor.Decrypt(cipher));
}, aessalt, aesstrong, aeskey, cipherText);
decryptCommand.AddCommand(aesDecryptCommand);

var rsaDecryptCommand = new Command("rsa", "Decrypt with RSA"){
    aessalt,
    aesstrong,
    keystoreFilename,
    keyAlias,
    keystorePassword,
    algorithm
};
rsaDecryptCommand.Add(cipherText);
rsaDecryptCommand.SetHandler((salt, strong, filename, keyAlias, keystorePassword, algorithm, cipherText) =>
{
    var decryptor = new RsaKeyStoreDecryptor(filename, keystorePassword, keyAlias, salt, strong, algorithm);
    Console.WriteLine(decryptor.Decrypt(cipherText));
}, aessalt, aesstrong, keystoreFilename, keyAlias, keystorePassword, algorithm, cipherText);

decryptCommand.AddCommand(rsaDecryptCommand);


var rootCommand = new RootCommand("Encryption for Spring Boot Cloud config");

rootCommand.AddCommand(encryptCommand);
rootCommand.AddCommand(decryptCommand);

await rootCommand.InvokeAsync(args);