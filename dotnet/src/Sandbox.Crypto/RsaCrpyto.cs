using System;
using System.Security.Cryptography;
using System.Text;
using Newtonsoft.Json;

namespace Sandbox.Crypto
{
    public class RsaCrypto
    {
        public (string privateKeyParametersJson, string publicKeyParametersJson) GenerateKeyPair(int keySize)
        {
            using (var rsa = RSA.Create())
            {
                rsa.KeySize = keySize;

                var privateKeyParameters = rsa.ExportParameters(true).ToPrivateKeyParameters();
                var publicKeyParameters = rsa.ExportParameters(false).ToPublicKeyParameters();

                var privateKeyParametersJson = JsonConvert.SerializeObject(privateKeyParameters);
                var publicKeyParametersJson = JsonConvert.SerializeObject(publicKeyParameters);
                return (privateKeyParametersJson, publicKeyParametersJson);
            }
        }

        public string Encrypt(string plainText, string publicKeyJson)
        {
            using (var rsa = RSA.Create())
            {
                var rsaParameters = JsonConvert.DeserializeObject<RsaPublicKeyParameters>(publicKeyJson).ToRSAParameters();
                rsa.ImportParameters(rsaParameters);

                var dataToEncrypt = Encoding.UTF8.GetBytes(plainText);
                var encryptedData = rsa.Encrypt(dataToEncrypt, RSAEncryptionPadding.OaepSHA256);
                return Convert.ToBase64String(encryptedData);
            }
        }

        public string Decrypt(string encryptedData, string privateKeyJson)
        {
            using (var rsa = RSA.Create())
            {
                var rsaParameters = JsonConvert.DeserializeObject<RsaPrivateKeyParameters>(privateKeyJson).ToRSAParameters();
                rsa.ImportParameters(rsaParameters);

                var dataToDecrypt = Convert.FromBase64String(encryptedData);
                var decryptedData = rsa.Decrypt(dataToDecrypt, RSAEncryptionPadding.OaepSHA256);
                return Encoding.UTF8.GetString(decryptedData);
            }
        }

        public string SignData(string data, string privateKeyJson)
        {
            using (var rsa = RSA.Create())
            {
                var rsaParameters = JsonConvert.DeserializeObject<RsaPrivateKeyParameters>(privateKeyJson).ToRSAParameters();
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
                var rsaParameters = JsonConvert.DeserializeObject<RsaPublicKeyParameters>(publicKeyJson).ToRSAParameters();
                rsa.ImportParameters(rsaParameters);

                var dataToVerify = Encoding.UTF8.GetBytes(data);
                var signatureData = Convert.FromBase64String(signature);
                return rsa.VerifyData(dataToVerify, signatureData, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1);
            }
        }
    }
}
