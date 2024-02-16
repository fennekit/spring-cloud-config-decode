using Microsoft.AspNetCore.Cryptography.KeyDerivation;
using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace Fennekit.SpringCloudConfig.Decrypt;

public class AesTextDecryptor : ITextDecryptor
{
    private readonly short KEYSIZE = 256;
    private readonly byte[] _key;
    private readonly IBufferedCipher _cipher;
    private SecureRandom _random;

    public AesTextDecryptor(string key, string salt = "deadbeef", bool strong = false)
    {
        _random = new SecureRandom();
        _cipher = strong
            ? CipherUtilities.GetCipher("AES/GCM/NoPadding")
            : CipherUtilities.GetCipher("AES/CBC/PKCS5Padding");

        byte[] saltBytes = GetSaltBytes(salt);

        _key =  KeyDerivation.Pbkdf2(key, saltBytes, KeyDerivationPrf.HMACSHA1, 1024, KEYSIZE / 8);
    }

    private static byte[] GetSaltBytes(string salt)
    {
        try
        {
            return Convert.FromHexString(salt);
        }
        catch
        {
            return UTF8Encoding.Default.GetBytes(salt);
        }
    }

    public string Decrypt(string cipher)
    {
        var fullCipher = Convert.FromHexString(cipher);
        var clearTextBytes = Decrypt(fullCipher);
        return UTF8Encoding.Default.GetString(clearTextBytes);
    }
  

    public string Encrypt(string text)
    {
        var cipherBytes = UTF8Encoding.Default.GetBytes(text);
        var fullCipher = Encrypt(cipherBytes);
        return Convert.ToHexString(fullCipher);
    }

    public byte[] Encrypt(byte[] bytes)
    {
        byte[] iv = new byte[16];
        _random.NextBytes(iv);
        InitializeCipher(true, iv);
        var cipherText = _cipher.DoFinal(bytes);
        var fullCipher = new byte[cipherText.Length + 16];

        using var ms = new MemoryStream(fullCipher);
        ms.Write(iv);
        ms.Write(cipherText);
        return fullCipher;
    }

    public byte[] Decrypt(byte[] fullCipher)
    {
        var iv = new byte[16];
        var cipherBytes = new byte[fullCipher.Length - 16];

        using var ms = new MemoryStream(fullCipher);
        ms.Read(iv);
        ms.Read(cipherBytes);
        
        InitializeCipher(false, iv);

        return _cipher.DoFinal(cipherBytes);
    }

    private void InitializeCipher(bool decrypt, byte[] iv)
    {
        var keyParam = new KeyParameter(_key);
        var keyParameters = new ParametersWithIV(keyParam, iv);
        _cipher.Init(decrypt, keyParameters);
    }
}