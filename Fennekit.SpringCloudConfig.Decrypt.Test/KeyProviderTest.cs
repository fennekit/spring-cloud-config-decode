using Fennekit.SpringCloudConfig.Decrypt;
using NUnit.Framework;

namespace Fennekit.SpringCloudConfig.Decrypt.Test;

[TestFixture]
[TestOf(typeof(KeyProvider))]
public class KeyProviderTest
{

    [Test]
    public void TestPrivateKey()
    {
        var provider = new KeyProvider("server.jks", "letmein");
        Assert.That(provider.GetPrivateKey("mytestkey"), Is.Not.Null);
        
    }
   
    [Test]
    public void TestPublicKey()
    {
        var provider = new KeyProvider("server.jks", "letmein");
        Assert.That(provider.GetPublicKey("mytestkey"), Is.Not.Null);
        
    }
    
    [Test]
    public void TestPrivateKeyNotExists()
    {
        var provider = new KeyProvider("server.jks", "letmein");
        Assert.Throws(typeof(DecryptException), () => provider.GetPrivateKey("nokey"));
    }
    
    [Test]
    public void TestPublicKeyNotExists()
    {
        var provider = new KeyProvider("server.jks", "letmein");
        Assert.Throws(typeof(DecryptException), () => provider.GetPublicKey("nokey"));

        
    }
}