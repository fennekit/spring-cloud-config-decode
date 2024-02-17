using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Pkcs;

namespace Fennekit.SpringCloudConfig.Decrypt;

public class KeyProvider
{
    private readonly Pkcs12Store _pkcs12;

    public KeyProvider(string fileName, string pfxPassword)
    {
        _pkcs12 = new Pkcs12StoreBuilder().Build();
        _pkcs12.Load(new FileStream(fileName, FileMode.Open, FileAccess.Read), pfxPassword.ToArray());
    }

    public AsymmetricKeyParameter GetPrivateKey(string keyAlias)
    {
        var key = _pkcs12.GetKey(keyAlias)?.Key;
        if (key is null)
        {
            throw new DecryptException($"No private key found with alias '{keyAlias}'");
        }

        return key;
    }
    
    public AsymmetricKeyParameter GetPublicKey(string keyAlias)
    {
        var key = _pkcs12.GetCertificate(keyAlias)?.Certificate?.GetPublicKey();
        if (key is null)
        {
            throw new DecryptException($"No public key found with alias '{keyAlias}'");
        }

        return key;
    }
}