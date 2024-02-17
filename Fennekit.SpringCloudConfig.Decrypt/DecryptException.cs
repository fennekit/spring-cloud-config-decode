namespace Fennekit.SpringCloudConfig.Decrypt;

public class DecryptException : Exception
{
    public DecryptException(string message, Exception exception) : base(message, exception)
    {
    }

    public DecryptException(string message) : base(message)
    {
    }
}