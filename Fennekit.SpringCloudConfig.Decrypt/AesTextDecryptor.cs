using Microsoft.AspNetCore.Cryptography.KeyDerivation;
using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace Fennekit.SpringCloudConfig.Decrypt;

public class AesTextDecryptor : ITextDecryptor
{
    private const short KeySize = 256;
    private readonly IBufferedCipher _cipher;
    private readonly KeyParameter _keyParam;
    private readonly SecureRandom _random;

    
    public AesTextDecryptor(string key, string salt = "deadbeef", bool strong = false)
    {
        _random = new SecureRandom();
        _cipher = strong
            ? CipherUtilities.GetCipher("AES/GCM/NoPadding")
            : CipherUtilities.GetCipher("AES/CBC/PKCS5Padding");

        var saltBytes = GetSaltBytes(salt);
        var keyBytes =  KeyDerivation.Pbkdf2(key, saltBytes, KeyDerivationPrf.HMACSHA1, 1024, KeySize / 8);
        _keyParam = new KeyParameter(keyBytes);
    }

    private static byte[] GetSaltBytes(string salt)
    {
        try
        {
            return Convert.FromHexString(salt);
        }
        catch
        {
            return Encoding.UTF8.GetBytes(salt);
        }
    }

    public string Decrypt(string cipher)
    {
        var fullCipher = Convert.FromHexString(cipher);
        var clearTextBytes = Decrypt(fullCipher);
        return Encoding.UTF8.GetString(clearTextBytes);
    }
  

    public string Encrypt(string text)
    {
        var cipherBytes = Encoding.UTF8.GetBytes(text);
        var fullCipher = Encrypt(cipherBytes);
        return Convert.ToHexString(fullCipher);
    }

    public byte[] Encrypt(byte[] bytes)
    {
        var iv = new byte[16];
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
        var bytesRead = ms.Read(iv);
        if (bytesRead != iv.Length)
        {
            throw new DecryptException("Error reading IV from stream");
        }
        bytesRead = ms.Read(cipherBytes);
        if (bytesRead != cipherBytes.Length)
        {
            throw new DecryptException("Error reading cipherBytes from stream");
        }
        
        InitializeCipher(false, iv);

        return _cipher.DoFinal(cipherBytes);
    }

    private void InitializeCipher(bool decrypt, byte[] iv)
    {
        var keyParameters = new ParametersWithIV(_keyParam, iv);
        _cipher.Init(decrypt, keyParameters);
    }
}