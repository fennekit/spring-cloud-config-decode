using System.Buffers.Binary;
using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;

namespace Fennekit.SpringCloudConfig.Decrypt;

public class RsaKeyStoreDecryptor : ITextDecryptor
{
    private readonly string _alias;
    private readonly string _salt;
    private readonly bool _strong;
    private readonly KeyProvider _keyprovider;
    private readonly IBufferedCipher _cipher;
    private SecureRandom _random;


    public RsaKeyStoreDecryptor(string filename, string password, string alias, string salt = "deadbeaf",
        bool strong = false, string algorithm = "DEFAULT")
    {
        _random = new SecureRandom();
        _alias = alias;
        _salt = salt;
        _strong = strong;
        _keyprovider = new KeyProvider(filename, password); 
        _cipher = GetCyper(algorithm);
    }

    private IBufferedCipher GetCyper(string algorithm)
    {
        switch (algorithm.ToUpper())
        {
            case "DEFAULT":
                return CipherUtilities.GetCipher("RSA/NONE/PKCS1Padding");
            case "OAEP": 
                return CipherUtilities.GetCipher("RSA/ECB/PKCS1");
        }

        throw new ArgumentException("algortithm should be one of DEFAULT or OAEP");
    }

    public string Decrypt(string cipher)
    {
        var fullCipher = Convert.FromBase64String(cipher);
        var clearTextBytes =  Decrypt(fullCipher);
        return UTF8Encoding.Default.GetString(clearTextBytes);

    }

    public string Encrypt(string text)
    {
        var cipherBytes = UTF8Encoding.Default.GetBytes(text);
        var fullCipher = Encrypt(cipherBytes);
        return Convert.ToBase64String(fullCipher);
    }

    public byte[] Decrypt(byte[] fullCipher)
    {
        _cipher.Init(false, _keyprovider.GetKey(_alias));
   
        using var ms = new MemoryStream(fullCipher);
        var secretLength = ReadSecretLenght(ms);
        byte[] secretBytes = new byte[secretLength];
        byte[] cipherTextBytes = new byte[fullCipher.Length - secretBytes.Length - 2]; 
        ms.Read(secretBytes);
        ms.Read(cipherTextBytes);
      
        var key = _cipher.DoFinal(secretBytes);
        var hexKey = Convert.ToHexString(key).ToLower();
        var decryptor = new AesTextDecryptor(hexKey, salt: _salt, strong: _strong);
        return decryptor.Decrypt(cipherTextBytes);
    }

    public byte[] Encrypt(byte[] clearText)
    {
        _cipher.Init(true, _keyprovider.GetKey(_alias));
       
        byte[] key = new byte[16];
        _random.NextBytes(key);
        var encryptedSecret = _cipher.DoFinal(key);
      
        var hexKey = Convert.ToHexString(key).ToLower();
        var decryptor = new AesTextDecryptor(hexKey, salt: _salt, strong: _strong);
        var cipherTextBytes = decryptor.Encrypt(clearText);
        byte[] fullCipher = new byte[cipherTextBytes.Length + encryptedSecret.Length + 2];
        
        using var ms = new MemoryStream(fullCipher);
        WriteSecretLenght(ms, (short)encryptedSecret.Length);
        ms.Write(encryptedSecret);
        ms.Write(cipherTextBytes);

        return fullCipher;
    }

    private void WriteSecretLenght(MemoryStream ms, short length)
    {
        byte[] b = new byte[2];
        BinaryPrimitives.WriteInt16BigEndian(b, length);
        ms.Write(b);
    }
    
    private int ReadSecretLenght(MemoryStream ms)
    {
        byte[] b = new byte[2];
        ms.Read(b);
        return BinaryPrimitives.ReadInt16BigEndian(b);
    }
}