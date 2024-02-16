namespace Fennekit.SpringCloudConfig.Decrypt;

public interface ITextDecryptor
{
    string Decrypt(string cipher);
    string Encrypt(string text);
    byte[] Decrypt(byte[] bytes);
    byte[] Encrypt(byte[] fullCipher);
}