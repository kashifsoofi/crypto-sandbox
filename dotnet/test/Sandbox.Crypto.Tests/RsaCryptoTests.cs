using System;
using Xunit;
using Sandbox.Crypto;

namespace Sandbox.Crypto.Tests
{
    public class RsaCryptoTests
    {
        [Fact]
        public void Test1()
        {
            var rsaCrypto = new RsaCrypto();

            var cipherText = rsaCrypto.Encrypt("TEST", "TEST");

            Assert.NotEmpty(cipherText);
            Assert.NotEqual("TEST", cipherText);            
        }
    }
}
