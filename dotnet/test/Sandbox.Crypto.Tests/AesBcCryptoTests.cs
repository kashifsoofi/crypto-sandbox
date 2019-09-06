using System;
using System.Text;
using FluentAssertions;
using Xunit;

namespace Sandbox.Crypto.Tests
{
    public class AesBcCryptoTests
    {
        private readonly string _plainText = "Here is some data to encrypt!";

        [Fact]
        public void Encrypt_should_encrypt_plainText_with_GCM_NOPADDING()
        {
            var aesBcCrypto = new AesBcCrypto();

            var key = Encoding.UTF8.GetBytes(Guid.NewGuid().ToString("N"));
            var encrypted = aesBcCrypto.Encrypt(_plainText, key);

            encrypted.Should().NotBeNullOrWhiteSpace();
            encrypted.Should().NotBe(_plainText);
            

            var decrypted = aesBcCrypto.Decrypt(encrypted, key);

            decrypted.Should().NotBeNullOrWhiteSpace();
            decrypted.Should().Be(_plainText);
        }

        [Theory]
        // Encrypted with BC AES/GCM/NoPadding
        [InlineData("EBA6cMY4KY9Ry9xR6U5TZlCGqHpFSIEOqvxIkFX4QvSotaWj6XztRRTsUa+FQTKICat7RU+CIGR5VS+J9uvh", "40f5dca1-81a8-44a0-8667-dbe2d5393a65")]
        // Encrypted with Java AES/GCM/NoPadding
        [InlineData("EBBnZdJcwfZxC9kdwRMt8YVADEXHa0VOpb3HkImm7nytjHsFiQs09Cfv48vZ9fJTX/oot6saYFPkoMDSScM7", "9b71be77-c730-47c6-841c-d597282792ef")]
        // Encrypted with Go NewGCM
        [InlineData("DBBJlLBym6tNgE5vMT2Vz45ChQLqsYFwXM4jKXVtRsLKbySgM5bkdxUjhwEjEVgzAALmthebr3bZWs8=", "c1b7232d-cd93-4baa-b6a0-64dccb3f1583")]
        // Microsoft does not support GCM in .netstandard 2.0 (its coming in .netstandard 2.1)
        public void Decrypt_should_decrypt_cipherText_GCM_NOPADDING(string cipherText, string key)
        {
            var aesBcCrypto = new AesBcCrypto();

            var encodedKey = Encoding.UTF8.GetBytes(Guid.Parse(key).ToString("N"));
            var decrypted = aesBcCrypto.Decrypt(cipherText, encodedKey);

            decrypted.Should().NotBeNullOrWhiteSpace();
            decrypted.Should().Be(_plainText);
        }

        [Fact]
        public void Encrypt_should_encrypt_plainText_with_CBC_PKCS7()
        {
            var aesBcCrypto = new AesBcCrypto(CipherMode.CBC, Padding.PKCS7);

            var key = Encoding.UTF8.GetBytes(Guid.NewGuid().ToString("N"));
            var encrypted = aesBcCrypto.Encrypt(_plainText, key);

            encrypted.Should().NotBeNullOrWhiteSpace();
            encrypted.Should().NotBe(_plainText);


            var decrypted = aesBcCrypto.Decrypt(encrypted, key);

            decrypted.Should().NotBeNullOrWhiteSpace();
            decrypted.Should().Be(_plainText);
        }

        [Theory]
        // Encrypted with Microsoft AES
        [InlineData("EFb6BdUqhHJQRsVxnD53sSDfflNfWjntak2paSCpgJCsp0u46vIbHsK4mwX3g32UeA==", "b963fdc3-4580-468b-88be-04f6630ef700")]
        // Encrypted with BC AES/CBC/PKCS7
        [InlineData("EFLPMGDLwsFlXqLXuM350XZv8S5DSomV7FyixHlDVI/POFKJ0IY3LzzaxUZ2jDFhIQ==", "850c8111-339e-453b-afdd-89a99cad849b")]
        // Encrypted with Java AES/CBC/Pkcs5
        [InlineData("EFtp6J1Fy1zVlewstk14Klg4oV7BLtGIgdnNwfHHlHbRv2fLVUgHpo+v8CwO2QimCw==", "458d1677-f515-4287-868a-fb1904e2fa10")]
        public void Decrypt_should_decrypt_cipherText_CBC_PKCS7(string cipherText, string key)
        {
            var aesBcCrypto = new AesBcCrypto(CipherMode.CBC, Padding.PKCS7);

            var encodedKey = Encoding.UTF8.GetBytes(Guid.Parse(key).ToString("N"));
            var decrypted = aesBcCrypto.Decrypt(cipherText, encodedKey);

            decrypted.Should().NotBeNullOrWhiteSpace();
            decrypted.Should().Be(_plainText);
        }
    }
}
