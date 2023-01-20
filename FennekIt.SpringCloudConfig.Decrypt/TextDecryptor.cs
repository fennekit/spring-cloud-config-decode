using Microsoft.AspNetCore.Cryptography.KeyDerivation;
using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace Fennekit.SpringCloudConfig.Decrypt;

public class TextDecryptor : ITextDecryptor
{
    private readonly byte[] _key;
    private readonly IBufferedCipher _cipher;

    public TextDecryptor(string key, string salt = "deadbeef", bool strong = false)
    {
        _cipher = strong
            ? CipherUtilities.GetCipher("AES/GCM/NoPadding")
            : CipherUtilities.GetCipher("AES/CBC/PKCS5Padding");
        var saltBytes = Convert.FromHexString(salt);
        
        _key =  KeyDerivation.Pbkdf2(key, saltBytes, KeyDerivationPrf.HMACSHA1, 1024, 256 / 8);
    }

    public string Decrypt(string cipher)
    {
        var fullCipher = Convert.FromHexString(cipher);

        return Decrypt(fullCipher);
    }

    public string Decrypt(byte[] fullCipher)
    {
        var iv = new byte[16];
        var cipherBytes = new byte[fullCipher.Length - 16];

        using var ms = new MemoryStream(fullCipher);
        ms.Read(iv);
        ms.Read(cipherBytes);
        
        var keyParam = new KeyParameter(_key);
        var keyParameters = new ParametersWithIV(keyParam, iv);
        _cipher.Init(false, keyParameters);
        
        var clearTextBytes = _cipher.DoFinal(cipherBytes);
        return UTF8Encoding.Default.GetString(clearTextBytes);
    }
}