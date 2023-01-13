using Microsoft.AspNetCore.Cryptography.KeyDerivation;
using System.Security.Cryptography;

namespace Fennekit.SpringCloudConfig.Decrypt;

public class TextDecryptor
{
    private readonly byte[] _key;
    private readonly byte[] _salt;
    private readonly string _algorithm;

    public TextDecryptor(string key, string salt = "deadbeef", string algorithm="DEFAULT")
    {
        _salt = Convert.FromHexString(salt);
        _key = KeyDerivation.Pbkdf2(key, _salt, KeyDerivationPrf.HMACSHA1, 1024, 256/8);
        _algorithm = algorithm;
    }

    public string Decrypt(string cipher)
    {
        var fullCipher = Convert.FromHexString(cipher);
        
        var iv = new byte[16];
        var cipherBytes = new byte[fullCipher.Length-16];

        Buffer.BlockCopy(fullCipher, 0, iv, 0, iv.Length);
        Buffer.BlockCopy(fullCipher, iv.Length, cipherBytes, 0, cipherBytes.Length);

        using var aesAlg = Aes.Create();
        
        //  aesAlg.Mode = CipherMode.ECB;
        // aesAlg.Padding = PaddingMode.ANSIX923;
        
        using var decryptor = aesAlg.CreateDecryptor(_key, iv);
        using var msDecrypt = new MemoryStream(cipherBytes);
        using var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read);
        using var srDecrypt = new StreamReader(csDecrypt);
        return srDecrypt.ReadToEnd();
    }
}