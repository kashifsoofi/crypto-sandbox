using System;
using System.Security.Cryptography;
using System.Text;

namespace Sandbox.Crypto
{
    public class RsaCrypto
    {
        public (string privateKeyXml, string publicKeyXml) GenerateXmlKeyPair(int keySize)
        {
            using (var rsa = RSA.Create())
            {
                rsa.KeySize = keySize;                

                var privateKeyXml = rsa.ToXmlString(true);
                var publicKeyXml = rsa.ToXmlString(false);
                return (privateKeyXml, publicKeyXml);
            }
        }

        public string Encrypt(string plainText, string publicKeyXml)
        {
            using (var rsa = RSA.Create())
            {
                rsa.FromXmlString(publicKeyXml);

                var dataToEncrypt = Encoding.UTF8.GetBytes(plainText);
                var encryptedData = rsa.Encrypt(dataToEncrypt, RSAEncryptionPadding.Pkcs1);
                return Convert.ToBase64String(encryptedData);
            }
        }

        public string Decrypt(string encryptedData, string privateKeyXml)
        {
            using (var rsa = RSA.Create())
            {
                rsa.FromXmlString(privateKeyXml);

                var dataToDecrypt = Convert.FromBase64String(encryptedData);
                var decryptedData = rsa.Decrypt(dataToDecrypt, RSAEncryptionPadding.Pkcs1);
                return Encoding.UTF8.GetString(decryptedData);
            }
        }
    }
}
