using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using Newtonsoft.Json;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Security;

namespace Sandbox.Crypto
{
    public class RsaBcCrypto
    {
        private const string Algorithm = "RSA/ECB/OAEPWithSHA256AndMGF1Padding";
        private const string SignatureAlgorithm = "SHA512WITHRSA";
        private const int DefaultRsaBlockSize = 190;

        public (string privateKeyParametersJson, string publicKeyParametersJson) GenerateKeyPair(int keySize)
        {
            var random = new SecureRandom();
            var keyGenerationParameters = new KeyGenerationParameters(random, keySize);
            RsaKeyPairGenerator generator = new RsaKeyPairGenerator();
            generator.Init(keyGenerationParameters);

            var keyPair = generator.GenerateKeyPair();

            var privateKeyParametersJson = JsonConvert.SerializeObject(keyPair.Private.ToPrivateKeyParameters());
            var publicKeyParametersJson = JsonConvert.SerializeObject(keyPair.Public.ToPublicKeyParameters());
            return (privateKeyParametersJson, publicKeyParametersJson);
        }

        public string Encrypt(string plainText, string publicKeyJson)
        {
            var encryptionKey = JsonConvert.DeserializeObject<RsaPublicKeyParameters>(publicKeyJson).ToRsaKeyParameters();

            var cipher = CipherUtilities.GetCipher(Algorithm);
            cipher.Init(true, encryptionKey);

            var dataToEncrypt = Encoding.UTF8.GetBytes(plainText);
            var encryptedData = ApplyCipher(dataToEncrypt, cipher, DefaultRsaBlockSize);
            return Convert.ToBase64String(encryptedData);
        }

        public string Decrypt(string encryptedData, string privateKeyJson)
        {
            var decryptionKey = JsonConvert.DeserializeObject<RsaPrivateKeyParameters>(privateKeyJson).ToRsaPrivateCrtKeyParameters();

            var cipher = CipherUtilities.GetCipher(Algorithm);
            cipher.Init(false, decryptionKey);

            int blockSize = decryptionKey.Modulus.BitLength / 8;

            var dataToDecrypt = Convert.FromBase64String(encryptedData);
            var decryptedData = ApplyCipher(dataToDecrypt, cipher, blockSize);
            return Encoding.UTF8.GetString(decryptedData);
        }

        public string SignData(string data, string privateKeyJson)
        {
            var signatureKey = JsonConvert.DeserializeObject<RsaPrivateKeyParameters>(privateKeyJson).ToRsaPrivateCrtKeyParameters();

            var dataToSign = Encoding.UTF8.GetBytes(data);

            var signer = SignerUtilities.GetSigner(SignatureAlgorithm);
            signer.Init(true, signatureKey);
            signer.BlockUpdate(dataToSign, 0, dataToSign.Length);

            var signature = signer.GenerateSignature();
            return Convert.ToBase64String(signature);
        }

        public bool VerifySignature(string data, string signature, string publicKeyJson)
        {
            var signatureKey = JsonConvert.DeserializeObject<RsaPublicKeyParameters>(publicKeyJson).ToRsaKeyParameters();

            var dataToVerify = Encoding.UTF8.GetBytes(data);
            var binarySignature = Convert.FromBase64String(signature);

            var signer = SignerUtilities.GetSigner(SignatureAlgorithm);
            signer.Init(false, signatureKey);
            signer.BlockUpdate(dataToVerify, 0, dataToVerify.Length);

            return signer.VerifySignature(binarySignature);
        }

        private byte[] ApplyCipher(byte[] data, IBufferedCipher cipher, int blockSize)
        {
            var inputStream = new MemoryStream(data);
            var outputBytes = new List<byte>();

            int index;
            var buffer = new byte[blockSize];
            while ((index = inputStream.Read(buffer, 0, blockSize)) > 0)
            {
                var cipherBlock = cipher.DoFinal(buffer, 0, index);
                outputBytes.AddRange(cipherBlock);
            }

            return outputBytes.ToArray();
        }
    }
}
