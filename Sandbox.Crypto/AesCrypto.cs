using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Sandbox.Crypto
{
    public class AesCrypto
    {

        public string Encrypt(string plainText, string key)
        {
            var keyBytes = Encoding.UTF8.GetBytes(key);
            using (var aes = Aes.Create())
            {
                aes.Key = keyBytes;

                var cryptoTransform = aes.CreateEncryptor(aes.Key, aes.IV);

                var plainTextAsBytes = Encoding.UTF8.GetBytes(plainText);
                var cipherText = Encrypt(plainTextAsBytes, cryptoTransform);

                var data = new byte[cipherText.Length + aes.IV.Length + 1];
                data[0] = (byte) aes.IV.Length;
                Array.Copy(aes.IV, 0, data, 1, aes.IV.Length);
                Array.Copy(cipherText, 0, data, aes.IV.Length + 1, cipherText.Length);
                return Convert.ToBase64String(data);
            }
        }

        public string Decrypt(string cipherText, string key)
        {
            var data = Convert.FromBase64String(cipherText);
            byte ivSize = data[0];
            var iv = new byte[ivSize];
            Array.Copy(data, 1, iv, 0, ivSize);
            var encrypted = new byte[data.Length - ivSize - 1];
            Array.Copy(data, ivSize + 1, encrypted, 0, encrypted.Length);

            var keyBytes = Encoding.UTF8.GetBytes(key);
            using (var aes = Aes.Create())
            {
                aes.Key = keyBytes;
                aes.IV = iv;

                var cryptoTransform = aes.CreateEncryptor(aes.Key, aes.IV);
                return Decrypt(encrypted, cryptoTransform);
            }
        }

        private byte[] Encrypt(byte[] data, ICryptoTransform cryptoTransform)
        {
            if (data == null || data.Length <= 0)
                throw new ArgumentException(nameof(data));

            using (MemoryStream memoryStream = new MemoryStream())
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

            using (MemoryStream memoryStream = new MemoryStream())
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