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

    public AsymmetricKeyParameter GetKey(string keyAlias)
    {
        return _pkcs12.GetKey(keyAlias).Key;
    }
}