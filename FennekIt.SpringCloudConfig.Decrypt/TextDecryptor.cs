using Microsoft.AspNetCore.Cryptography.KeyDerivation;
using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;


namespace Fennekit.SpringCloudConfig.Decrypt;

public class TextDecryptor : ITextDecryptor
{
    private readonly byte[] _key;
    private readonly byte[] _salt;
    private readonly string _algorithm;
    private readonly IBufferedCipher _cipher;

    public TextDecryptor(string key, string salt = "deadbeef", string algorithm="DEFAULT", bool strong=false)
    {
        
        _cipher = strong ? CipherUtilities.GetCipher("AES/GCM/NoPadding"):CipherUtilities.GetCipher("AES/CBC/PKCS5Padding") ;
        _salt = Convert.FromHexString(salt);
        _key = KeyDerivation.Pbkdf2(key, _salt, KeyDerivationPrf.HMACSHA1, 1024, 256/8);
        _algorithm = algorithm;
    }
    
    public TextDecryptor(byte[] key, string salt = "deadbeef", string algorithm="DEFAULT")
    {
        _salt = Convert.FromHexString(salt);
        _key = key;
        _algorithm = algorithm;
    }
    

    public string Decrypt(string cipher)
    {
        var fullCipher = Convert.FromHexString(cipher);
        
       return Decrypt(fullCipher);
    }
    
    public string Decrypt(byte[] fullCipher)
    {
        var iv = new byte[16];
        var cipherBytes = new byte[fullCipher.Length-16];
         
        Buffer.BlockCopy(fullCipher, 0, iv, 0, iv.Length);
        Buffer.BlockCopy(fullCipher, iv.Length, cipherBytes, 0, cipherBytes.Length);
        
        var keyParam = new KeyParameter(_key);
        var keyParameters = new ParametersWithIV(keyParam, iv);
        
        _cipher.Init(false, keyParameters);
        var clearTextBytes = _cipher.DoFinal(cipherBytes);
        return UTF8Encoding.Default.GetString(clearTextBytes);
    }
}