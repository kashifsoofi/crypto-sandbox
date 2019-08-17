using System;
using System.Security.Cryptography;
using System.Text;
using Newtonsoft.Json;

namespace Sandbox.Crypto
{
    public class RsaCrypto
    {
        public (string privateKeyJson, string publicKeyJson) GenerateKeyPair(int keySize)
        {
            using (var rsa = RSA.Create())
            {
                rsa.KeySize = keySize;

                var privateKey = rsa.ExportParameters(true);
                var publicKey = rsa.ExportParameters(false);

                var privateKeyJson = JsonConvert.SerializeObject(privateKey);
                var publicKeyJson = JsonConvert.SerializeObject(publicKey);
                return (privateKeyJson, publicKeyJson);
            }
        }

        public string Encrypt(string plainText, string publicKeyJson)
        {
            using (var rsa = RSA.Create())
            {
                var rsaParameters = JsonConvert.DeserializeObject<RSAParameters>(publicKeyJson);
                rsa.ImportParameters(rsaParameters);

                var dataToEncrypt = Encoding.UTF8.GetBytes(plainText);
                var encryptedData = rsa.Encrypt(dataToEncrypt, RSAEncryptionPadding.Pkcs1);
                return Convert.ToBase64String(encryptedData);
            }
        }

        public string Decrypt(string encryptedData, string privateKeyJson)
        {
            using (var rsa = RSA.Create())
            {
                var rsaParameters = JsonConvert.DeserializeObject<RSAParameters>(privateKeyJson);
                rsa.ImportParameters(rsaParameters);

                var dataToDecrypt = Convert.FromBase64String(encryptedData);
                var decryptedData = rsa.Decrypt(dataToDecrypt, RSAEncryptionPadding.Pkcs1);
                return Encoding.UTF8.GetString(decryptedData);
            }
        }

        public string SignData(string data, string privateKeyJson)
        {
            using (var rsa = RSA.Create())
            {
                var rsaParameters = JsonConvert.DeserializeObject<RSAParameters>(privateKeyJson);
                rsa.ImportParameters(rsaParameters);

                var dataToSign = Encoding.UTF8.GetBytes(data);
                var signature = rsa.SignData(dataToSign, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1);
                return Convert.ToBase64String(signature);
            }
        }

        public bool VerifySignature(string data, string signature, string publicKeyJson)
        {
            using (var rsa = RSA.Create())
            {
                var rsaParameters = JsonConvert.DeserializeObject<RSAParameters>(publicKeyJson);
                rsa.ImportParameters(rsaParameters);

                var dataToVerify = Encoding.UTF8.GetBytes(data);
                var signatureData = Convert.FromBase64String(signature);
                return rsa.VerifyData(dataToVerify, signatureData, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1);
            }
        }
    }
}
