using System.Buffers.Binary;
using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;

namespace Fennekit.SpringCloudConfig.Decrypt;

public class RsaKeyStoreDecryptor : ITextDecryptor
{
    private readonly string _salt;
    private readonly bool _strong;
    private readonly KeyProvider _keyprovider;
    private readonly IBufferedCipher _cipher;

    public RsaKeyStoreDecryptor(string filename, string password, string alias, string salt = "deadbeaf",
        bool strong = false, string algorithm = "DEFAULT")
    {
        _salt = salt;
        _strong = strong;
        _keyprovider = new KeyProvider(filename, password); 
        _cipher = GetCyper(algorithm);
        _cipher.Init(false, _keyprovider.GetKey(alias));
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
        throw new NotImplementedException();
    }

    public byte[] Decrypt(byte[] fullCipher)
    {
        using var ms = new MemoryStream(fullCipher);

        var secretLength = ReadSecretLenght(ms);
        byte[] secretBytes = new byte[secretLength];
        byte[] cipherTextBytes = new byte[fullCipher.Length - secretBytes.Length - 2];
        
        ms.Read(secretBytes);
        ms.Read(cipherTextBytes);

        var secret = Convert.ToHexString(_cipher.DoFinal(secretBytes)).ToLower();
        AesTextDecryptor decryptor = new AesTextDecryptor(secret, salt: _salt, strong: _strong);
        return decryptor.Decrypt(cipherTextBytes);
    }

    public byte[] Encrypt(byte[] fullCipher)
    {
        throw new NotImplementedException();
    }

    private int ReadSecretLenght(MemoryStream ms)
    {
        byte[] b = new byte[2];
        ms.Read(b);
        return BinaryPrimitives.ReadInt16BigEndian(b);
    }
}