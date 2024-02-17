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
    private readonly SecureRandom _random;

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

    private static IBufferedCipher GetCyper(string algorithm)
    {
        return algorithm.ToUpper() switch
        {
            "DEFAULT" => CipherUtilities.GetCipher("RSA/NONE/PKCS1Padding"),
            "OAEP" => CipherUtilities.GetCipher("RSA/ECB/PKCS1"),
            _ => throw new ArgumentException("algortithm should be one of DEFAULT or OAEP")
        };
    }

    public string Decrypt(string cipher)
    {
        var fullCipher = Convert.FromBase64String(cipher);
        var clearTextBytes =  Decrypt(fullCipher);
        return Encoding.UTF8.GetString(clearTextBytes);

    }

    public string Encrypt(string text)
    {
        var cipherBytes = Encoding.UTF8.GetBytes(text); 
        var fullCipher = Encrypt(cipherBytes);
        return Convert.ToBase64String(fullCipher);
    }

    public byte[] Decrypt(byte[] fullCipher)
    {
        _cipher.Init(false, _keyprovider.GetPrivateKey(_alias));
        using var ms = new MemoryStream(fullCipher);
        var secretLength = ReadSecretLenght(ms);
        if (secretLength < 0)
        {
            throw new DecryptException($"Incorrect secret length {secretLength}.");
        }

        var cipherTextLength = fullCipher.Length - secretLength - 2;
        if (cipherTextLength < 0)
        {
            throw new DecryptException($"Incorrect cipher length.");
        }
        
        var secretBytes = new byte[secretLength];
        var cipherTextBytes = new byte[cipherTextLength]; 
        var bytesRead = ms.Read(secretBytes);
        if (bytesRead != secretBytes.Length)
        {
            throw new DecryptException("Error reading secretBytes from stream");
        }
        bytesRead = ms.Read(cipherTextBytes);
        if (bytesRead != cipherTextBytes.Length)
        {
            throw new DecryptException("Error reading cipherTextBytes from stream");
        }
      
        var key = _cipher.DoFinal(secretBytes);
        var hexKey = Convert.ToHexString(key).ToLower();
        var decryptor = new AesTextDecryptor(hexKey, salt: _salt, strong: _strong);
        return decryptor.Decrypt(cipherTextBytes);
    }

    public byte[] Encrypt(byte[] clearText)
    {
        _cipher.Init(true, _keyprovider.GetPublicKey(_alias));
        var key = CreateSecureKey();

        // Encrypt text
        var hexKey = Convert.ToHexString(key).ToLower();
        var decryptor = new AesTextDecryptor(hexKey, salt: _salt, strong: _strong);
        var cipherTextBytes = decryptor.Encrypt(clearText);
        
        // Encrypt key with RSA
        var encryptedSecret = _cipher.DoFinal(key);
        var fullCipher = new byte[cipherTextBytes.Length + encryptedSecret.Length + 2];
        
        // Create result
        using var ms = new MemoryStream(fullCipher);
        WriteSecretLength(ms, (short)encryptedSecret.Length);
        ms.Write(encryptedSecret);
        ms.Write(cipherTextBytes);

        return fullCipher;
    }

    private byte[] CreateSecureKey()
    {
        var key = new byte[16];
        _random.NextBytes(key);
        return key;
    }

    private static void WriteSecretLength(Stream ms, short length)
    {
        var b = new byte[2];
        BinaryPrimitives.WriteInt16BigEndian(b, length);
        ms.Write(b);
    }
    
    private static int ReadSecretLenght(Stream ms)
    {
        var b = new byte[2];
        var bytesRead = ms.Read(b);
        if (bytesRead != 2)
        {
            throw new DecryptException("Error reading length from stream");
        }
        
        return BinaryPrimitives.ReadInt16BigEndian(b);
    }
}