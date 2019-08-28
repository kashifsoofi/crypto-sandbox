using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using System;
using System.Text;

namespace Sandbox.Crypto
{
    public class AesBcCrypto
    {
        private const byte AesIvSize = 16;
        private const byte GcmTagSize = 16; // in bytes
        private const string Algorithm = "AES/GCM/NoPadding";

        public byte[] GenerateSecretKey(int keySize = 128)
        {
            var random = new SecureRandom();
            var generator = GeneratorUtilities.GetKeyGenerator("AES");
            generator.Init(new KeyGenerationParameters(random, keySize));
            var key = generator.GenerateKey();
            return key;
        }

        public string Encrypt(string plainText, byte[] key)
        {
            var keyParameter = new KeyParameter(key);

            var random = new SecureRandom();
            var aeadParameter = new AeadParameters(keyParameter, GcmTagSize * 8, random.GenerateSeed(AesIvSize));
            var cipher = CipherUtilities.GetCipher(Algorithm);
            cipher.Init(true, aeadParameter);

            var plainTextData = Encoding.UTF8.GetBytes(plainText);
            var cipherText = cipher.DoFinal(plainTextData);

            var data = new byte[cipherText.Length + AesIvSize + 2];
            data[0] = AesIvSize;
            data[1] = GcmTagSize;
            Array.Copy(aeadParameter.GetNonce(), 0, data, 2, AesIvSize);
            Array.Copy(cipherText, 0, data, AesIvSize + 2, cipherText.Length);

            return Convert.ToBase64String(data);
        }

        public string Decrypt(string cipherText, byte[] key)
        {
            var data = Convert.FromBase64String(cipherText);
            byte ivSize = data[0];
            byte tagSize = data[1];
            byte[] ivData = new byte[ivSize];
            Array.Copy(data, 2, ivData, 0, ivSize);
            byte[] encrypted = new byte[data.Length - ivSize - 2];
            Array.Copy(data, ivSize + 2, encrypted, 0, encrypted.Length);

            var keyParameter = new KeyParameter(key);
            var aeadParameter = new AeadParameters(keyParameter, tagSize * 8, ivData);
            var cipher = CipherUtilities.GetCipher(Algorithm);
            cipher.Init(false, aeadParameter);

            var decryptedData = cipher.DoFinal(encrypted);
            return Encoding.UTF8.GetString(decryptedData);
        }
    }
}
