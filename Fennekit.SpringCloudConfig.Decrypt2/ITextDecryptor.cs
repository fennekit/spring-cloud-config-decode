namespace Fennekit.SpringCloudConfig.Decrypt;

public interface ITextDecryptor
{
    string Decrypt(string cipher);
}