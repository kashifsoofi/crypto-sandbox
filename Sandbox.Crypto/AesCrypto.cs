using System;
using System.IO;
using System.Security.Cryptography;

namespace Sandbox.Crypto
{
    public class AesCrypto
    {
        public string Encrypt(string plainText, byte[] key)
        {
            using (var aes = Aes.Create())
            {
                aes.Key = key;

                var cryptoTransform = aes.CreateEncryptor(aes.Key, aes.IV);

                var cipherText = Encrypt(plainText, cryptoTransform);

                var data = new byte[cipherText.Length + aes.IV.Length + 1];
                data[0] = (byte) aes.IV.Length;
                Array.Copy(aes.IV, 0, data, 1, aes.IV.Length);
                Array.Copy(cipherText, 0, data, aes.IV.Length + 1, cipherText.Length);
                return Convert.ToBase64String(data);
            }
        }

        public string Decrypt(string cipherText, byte[] key)
        {
            var data = Convert.FromBase64String(cipherText);
            byte ivSize = data[0];
            var iv = new byte[ivSize];
            Array.Copy(data, 1, iv, 0, ivSize);
            var encrypted = new byte[data.Length - ivSize - 1];
            Array.Copy(data, ivSize + 1, encrypted, 0, encrypted.Length);

            using (var aes = Aes.Create())
            {
                aes.Key = key;
                aes.IV = iv;

                var cryptoTransform = aes.CreateDecryptor(aes.Key, aes.IV);
                return Decrypt(encrypted, cryptoTransform);
            }
        }

        private byte[] Encrypt(string data, ICryptoTransform cryptoTransform)
        {
            if (data == null || data.Length <= 0)
                throw new ArgumentException(nameof(data));

            using (var memoryStream = new MemoryStream())
            {
                using (var cryptoStream = new CryptoStream(memoryStream, cryptoTransform, CryptoStreamMode.Write))
                {
                    using (var writer = new StreamWriter(cryptoStream))
                    {
                        writer.Write(data);
                    }
                }

                return memoryStream.ToArray();
            }
        }

        private string Decrypt(byte[] data, ICryptoTransform cryptoTransform)
        {
            if (data == null || data.Length <= 0)
                throw new ArgumentException(nameof(data));

            using (var memoryStream = new MemoryStream(data))
            {
                using (var cryptoStream = new CryptoStream(memoryStream, cryptoTransform, CryptoStreamMode.Read))
                {
                    using (var reader = new StreamReader(cryptoStream))
                    {
                        return reader.ReadToEnd();
                    }
                }
            }
        }
    }
}