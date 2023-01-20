using System.Runtime.Intrinsics.X86;
using System.Text;
using System.Text.Unicode;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Encoders;

namespace Fennekit.SpringCloudConfig.Decrypt;

public class KeyStoreDecryptor : ITextDecryptor
{
    private readonly IBufferedCipher _cipher;
    private readonly string _salt;
    private readonly bool _strong;

    public KeyStoreDecryptor(string filename, string password, string alias, string salt = "deadbeaf", bool strong = false)
    {
        _salt = salt;
        _strong = strong;
        var keyProvider = new KeyProvider(filename, password);
        var asymmetricKeyParameter = keyProvider.GetKey(alias);
        _cipher = CipherUtilities.GetCipher("RSA/ECB/PKCS1");
        _cipher.Init(false, asymmetricKeyParameter);
    }

    public string Decrypt(string cipher)
    {
        var fullCipher = Convert.FromBase64String(cipher);
        using var msDecrypt = new MemoryStream(fullCipher);
        var length = readInt(msDecrypt);
        byte[] random = new byte[length];
        msDecrypt.Read(random);
        var secret =  Convert.ToHexString(_cipher.DoFinal(random)).ToLower();
        
        byte[] buffer = new byte[fullCipher.Length - random.Length - 2];
        msDecrypt.Read(buffer);
        
        TextDecryptor decryptor = new TextDecryptor(secret, salt: _salt, strong: _strong);
        return decryptor.Decrypt(buffer);
    }

    private int readInt(MemoryStream msDecrypt)
    {
        byte[] b = new byte[2];
        msDecrypt.Read(b);
        return (b[0] & 255) << 8 | b[1] & 255;
    }
}