using FluentAssertions;
using Xunit;

namespace Sandbox.Crypto.Tests
{
    public class RsaBcCryptoTests
    {
        private readonly string _plainText = "Here is some data to encrypt!";

        [Fact]
        public void Should_Generate_KeyPair()
        {
            var rsaCrypto = new RsaBcCrypto();

            var (privateKeyJson, publicKeyJson) = rsaCrypto.GenerateKeyPair(2048);

            privateKeyJson.Should().NotBeNullOrWhiteSpace();
            publicKeyJson.Should().NotBeNullOrWhiteSpace();
        }

        [Fact]
        public void Should_Encrypt_And_Decrypt_With_Generated_Key()
        {
            var rsaCrypto = new RsaBcCrypto();
            var (privateKeyJson, publicKeyJson) = rsaCrypto.GenerateKeyPair(2048);

            var encrypted = rsaCrypto.Encrypt(_plainText, publicKeyJson);

            encrypted.Should().NotBeNullOrWhiteSpace();
            encrypted.Should().NotBe(_plainText);

            var decrypted = rsaCrypto.Decrypt(encrypted, privateKeyJson);

            decrypted.Should().NotBeNullOrWhiteSpace();
            decrypted.Should().Be(_plainText);
        }

        [Theory]
        // Microsoft RSA Key
        //[InlineData("{\"D\":null,\"DP\":null,\"DQ\":null,\"Exponent\":\"AQAB\",\"InverseQ\":null,\"Modulus\":\"vSPpZZ4r5zhM3rlaS75i33l6wgQjk9YR1y/QV6+r2NoJS8I17dLZrqk6ivSCgOkRT08/wNUvAUO6vuvaSKo5mG9AalzwVA1EM5FOaaWxYqs3mSnIqft1leL8Q/DHx1A4RFW/SVq+3n8WXV0w+NW4p33yH3eLKD6O3aeCBj9kgkOammeu5uYqcPpu/UQd4tcTEuwE6d1Mcyf6VeBK4J9DMDAcrY43mWc4s/3Vh4AJQXs/iEtqxxlpk8Zv0BNoucomkbw8ZsvdGW+FcnCmcCvBsWBZhI/PZflQGr7FNcsL2LHGQxeIZ1epNzCeTcyVcjZjnNuBcGBL1kymOwOyGN5NPQ==\",\"P\":null,\"Q\":null}")]
        // BouncyCastle RSA Key
        [InlineData("{\"Modulus\":\"pUcAviqTeZlTTevWP4fJziy5wdEHBBvWhyVxtIDG4BNv3DuFPKWEUxQVfbMBRy8HzZwulUoNxRuXeEgDcrZXzKADRkywklazN4KN0UTINurP37UXqnvdPllVBTzI+2acrMg4iVd97pa918BhWvpfmuAatcSY8UNOB9FKpdJtC3GEegPhP4DQ0QD7JEN9OrviCXebPcdJbgsI7zUqNs7kXXf0RWIMgP1HgI42Wbcmlc6ce41zv7xouBaY0bsuJfZOiR1E0+aCJ34L+JFbZahGZKuoYcugIIvFo5rXhIJ48UiLWO2uThttX4gTZmmfQVYXB3xvLWxXtc1U70jEG9hqnQ==\",\"Exponent\":\"AQAB\"}")]
        public void Should_Encrypt_PlainText_With_PublicKey(string publicKeyJson)
        {
            var rsaCrypto = new RsaBcCrypto();

            var encrypted = rsaCrypto.Encrypt(_plainText, publicKeyJson);

            encrypted.Should().NotBeNullOrWhiteSpace();
            encrypted.Should().NotBe(_plainText);
        }

        [Theory]
        // Encrypted with Microsoft RSA/OaepSHA256
        //[InlineData("GZWfOpQ01uILRKnBMTkAbQheVu1PlUD2T599GI5VALihsETOW6pw/QZl8ScTER3sRIAs56bZODrnvnFvfVtGzIIBTuz84AIB2Mb/YsNeDo+qF4qdy9FJHhXOuaSDlDm2iHaE7taFbFxl2POvmfmM694/UQse4/8ultRLH9Mbw5kYGWiHQgBoEm54wbWK19c0I5868fo3kzDkYlY2/mr1qecHWytXJp8s7qUnVRw8beI0di9w+IavQ2zApic9GdxhxTWqFxOmo/VA+tH3bQJF9lcBdUft/EHn5I/6gsJP+xOs70ykvV2Z5zMiX1gGXuyI5cKKR3qdhEtEYGaytvvbUQ==",
            // "{\"D\":\"iyAyW3QomTEZoi83U0XdFsMV4EcJIIKzptTd7NIklyNy+Q4He0PAqbCDhpjqsgY+nFcP7zkhFU4LvMpiS1cjfJRBDrwEb98+TqxQwHeH7qtA/2Hz380/JhzMMPGZEmxYpzNnvH6KrcFP4ydckX0sEdAb3LejXdv+XN8NTqkstn/bqDmgRTkfjCaslVd/HcVO3jYHPBx6bryjU+4SK2XnBZj5nnkDxTynF+T9C4Wi3np2/xUBOfynIV8O6GrhRgKlhecpMLfXiD8nz0HJ7ahWLltMD75RWgjE+YxQsqFQiRe5OJtMcYDqPBe4vi65+QJ2eddi7Kw3iZr/C37tSLxpBQ==\",\"DP\":\"qthpbiC8IDTGfQ5eym2mRPPrzsRrog3Gp4/pakhBL4H++pQN1ZJV2emLK/vMJEdPbLfhOOT9UDczcGZJr6C9grUp0eaVCxMFEvwau155JENjsCuwTiU9hzch0T46uIXcE1Wse3mRsAA0AiLX0epi9lSSrb+5jWK2GoFcyKkL8E0=\",\"DQ\":\"XXh0vJP0HQ8yc6qFZIw21ATUnzRvJJc+MCmklhkCtZOnlmxj4+tShNzskpbj0mrZTE63db0vfpj2+x1DsTz0pO+vnwcn7KGhndqYyClao9B9D9rORkFfYir9vHbK14kRr8hiN7lGdq419N7h9J7e49vZnYeQYm4/lT636+3YrqE=\",\"Exponent\":\"AQAB\",\"InverseQ\":\"tICa95haC4FO7JFr/XF9VXemso/Rq3yDUGb1tn0wfooht6OmsN+QZNHzPzW6/dsaerCT+czeOB9GhCLHl5iMTlELb8r8Ri1pmp6SSanl0h6TarxobEYGfdYhigpNKsXAVKVuJIDzFMVzdkmjrSyepEgZWYVyrlc2F8esSGQyUFQ=\",\"Modulus\":\"vSPpZZ4r5zhM3rlaS75i33l6wgQjk9YR1y/QV6+r2NoJS8I17dLZrqk6ivSCgOkRT08/wNUvAUO6vuvaSKo5mG9AalzwVA1EM5FOaaWxYqs3mSnIqft1leL8Q/DHx1A4RFW/SVq+3n8WXV0w+NW4p33yH3eLKD6O3aeCBj9kgkOammeu5uYqcPpu/UQd4tcTEuwE6d1Mcyf6VeBK4J9DMDAcrY43mWc4s/3Vh4AJQXs/iEtqxxlpk8Zv0BNoucomkbw8ZsvdGW+FcnCmcCvBsWBZhI/PZflQGr7FNcsL2LHGQxeIZ1epNzCeTcyVcjZjnNuBcGBL1kymOwOyGN5NPQ==\",\"P\":\"+UUFEGRdnDjk5K69Ju21lRJA34EIqmS+kY0hiR9mZE10toflVi911AVdDhgY5RW8P0fhABenNlEn28MwcX9uTPSX0sXZmKk/GjZEUeTf1mX4nHnI6O0/XfwbioEIB2O6tCE8tC1ZnOlrZiic3wOG85WWwlA4EHvajSI/o2LFlxM=\",\"Q\":\"wj9FZgdosbUNqTaf4PiPIh/C/NORBeWGv8V2D9OFgjHaJ+gOKOgnWyxuhtjTyQxvG7ruwv4YH8KcSGEknWyAFI6E3DUMf+H7lG0GpX0ZsaQMuznIayafAYNPrdIUo0uJfQeMqhxMwruncdEq49JwgEgx0kpn/N8n5wxyH70EhG8=\"}")]
        // Encrypted with BouncyCastle RSA/ECB/OAEPWithSHA256AndMGF1Padding
        [InlineData("SGlvKXEs3uR2u11xJqnuRjXbWTICcb6h+u1ULu21jso1ux6guz0Et7v9IxkdGNQmd+7UiZlgt2DWofVMjCe3X/8zD/FxmM2sJKR9Sv1M0JcaiR4TYV8SI8MY6EgLNR3TN3jzwCWO0b+0VbY8BZEFD9KiRbxdlSP60p+s54t+Pck/OVaV8fj2TaSoxbD8L85eg8ggyf72bHVqREzfS9ozr2r/PwfNXutHscpJWjKEiGfjnp6Jaj3PyIuAmfhCYUPdV4UyWLLimZ2h9A0pVh5gLgP1G3acp0iC1/wPuFp2uRSIyr3WoP7Bp8xQa4766NqGcdFSWOk5Xz674PIwX29/UA==",
            "{\"D\":\"P0EPXbh5vJ4brcTGuIXFjGy9oxnWr5Hf5tVD0Ss/8d4+f3EgKvfFzu3u067AnHe5as2NXoF7B6bpr5UQDMUQkTXkSvFq2nboHCSRFjhWz/3KFPn/1rWVFRmnWlvLJ7w71jzCtn2PqtJyUbJFEEamdGW0k0BssFlr8b397by9ExV+5VXlduO8OzosLWYj3SYk3pFwZyXtlXm66Nar5M8IpZUw/6BVFwflyYqUKhABeAtmtv7MRP4U0CYDUF69Sxd5vCzJ62oF8WcULmlw2+GtS3a/wBQ/lXTZh4BoBafOykqNyqN5E2phTktjjZmjC8KaEzfvdODnna0XLaeVB8O/2Q==\",\"P\":\"4NqqvWWJ0qPkck38L0/MThYIAEt8TTz4W1eJJA/2qp6HYcWD4KeMQt18DWODB0GBUfwvz2btRTPJUB2j1AGrU81c6JaDySoGgArHF3lv5oYSL784Px2mqiRTXA5x/Bw/bvqfks5mJ7S8SO/my9bjtH91zvR9UDDKnr34+OVVSoc=\",\"Q\":\"vCu9tPrrbXqN72BJs0FdVrRbQ5KX2moISK9a+g1W2m5ZxnE9EHDv4HiGwyfDxhU8tTZ/Bloh5SxK9l+ux46ywDux7WUW73+xGGA1hd0hJyFJ2RQICv5mT9piIEu/+VnJzyI3c6yU3oiY3KQPkTO5GOx6dofYy2WwlM9Hzii5trs=\",\"DP\":\"HvJ5pW+gNHmSK5lIKErXV7f4ifHZvdeyZv/5RBleXcVL5M0GhZkJ2Poa5MzZb9o4LkyDWAxWg7vI7Vnm/nrsVbBiJTDyGnHKSz0wga6ZFCVHw4KR/z3ZfnlZb8YdMhHBOUkNRWta7AQYFgHOxidhV6pjUISd6reMa6TB65/EyWk=\",\"DQ\":\"CvcVj/VLQM7ydG+M++gkM0hBRTfGp5CkOPAXAhlC5Wmmy5yPrWSXZeJAICEyFFnqdrjdQBaCgSNKnv7GZZSYMAGKhcXtRzmOrVf15n4TT39uGTtEmLdoaODV9QHVBwfHbc2Vo6T769fT6I+a5KA5+gzVuhCCfp/HYXSOv6G56L8=\",\"InverseQ\":\"jVR5DS/wO0qEnxkMcjboLFA4WuMGkchzvPJOnE8jDtATTvLT554qCSoo+ait3WOjdHCDDILCEFWUpquFY/5NlSk4Yi9ECPIXTGdwBzURETU3Pi97DJ6eZY/0x6foyNm8GN75dhOCPcXcorvX9RxMtUT/j5mRfszfzsrLfjFx1Ww=\",\"Modulus\":\"pUcAviqTeZlTTevWP4fJziy5wdEHBBvWhyVxtIDG4BNv3DuFPKWEUxQVfbMBRy8HzZwulUoNxRuXeEgDcrZXzKADRkywklazN4KN0UTINurP37UXqnvdPllVBTzI+2acrMg4iVd97pa918BhWvpfmuAatcSY8UNOB9FKpdJtC3GEegPhP4DQ0QD7JEN9OrviCXebPcdJbgsI7zUqNs7kXXf0RWIMgP1HgI42Wbcmlc6ce41zv7xouBaY0bsuJfZOiR1E0+aCJ34L+JFbZahGZKuoYcugIIvFo5rXhIJ48UiLWO2uThttX4gTZmmfQVYXB3xvLWxXtc1U70jEG9hqnQ==\",\"Exponent\":\"AQAB\"}")]
        public void Should_Decrypt_CipherText_With_PrivateKey(string cipherText, string privateKeyJson)
        {
            var rsaCrypto = new RsaBcCrypto();

            var decrypted = rsaCrypto.Decrypt(cipherText, privateKeyJson);

            decrypted.Should().NotBeNullOrWhiteSpace();
            decrypted.Should().Be(_plainText);
        }

        [Theory]
        // Microsoft RSA Private Key
        [InlineData("{\"D\":\"iyAyW3QomTEZoi83U0XdFsMV4EcJIIKzptTd7NIklyNy+Q4He0PAqbCDhpjqsgY+nFcP7zkhFU4LvMpiS1cjfJRBDrwEb98+TqxQwHeH7qtA/2Hz380/JhzMMPGZEmxYpzNnvH6KrcFP4ydckX0sEdAb3LejXdv+XN8NTqkstn/bqDmgRTkfjCaslVd/HcVO3jYHPBx6bryjU+4SK2XnBZj5nnkDxTynF+T9C4Wi3np2/xUBOfynIV8O6GrhRgKlhecpMLfXiD8nz0HJ7ahWLltMD75RWgjE+YxQsqFQiRe5OJtMcYDqPBe4vi65+QJ2eddi7Kw3iZr/C37tSLxpBQ==\",\"DP\":\"qthpbiC8IDTGfQ5eym2mRPPrzsRrog3Gp4/pakhBL4H++pQN1ZJV2emLK/vMJEdPbLfhOOT9UDczcGZJr6C9grUp0eaVCxMFEvwau155JENjsCuwTiU9hzch0T46uIXcE1Wse3mRsAA0AiLX0epi9lSSrb+5jWK2GoFcyKkL8E0=\",\"DQ\":\"XXh0vJP0HQ8yc6qFZIw21ATUnzRvJJc+MCmklhkCtZOnlmxj4+tShNzskpbj0mrZTE63db0vfpj2+x1DsTz0pO+vnwcn7KGhndqYyClao9B9D9rORkFfYir9vHbK14kRr8hiN7lGdq419N7h9J7e49vZnYeQYm4/lT636+3YrqE=\",\"Exponent\":\"AQAB\",\"InverseQ\":\"tICa95haC4FO7JFr/XF9VXemso/Rq3yDUGb1tn0wfooht6OmsN+QZNHzPzW6/dsaerCT+czeOB9GhCLHl5iMTlELb8r8Ri1pmp6SSanl0h6TarxobEYGfdYhigpNKsXAVKVuJIDzFMVzdkmjrSyepEgZWYVyrlc2F8esSGQyUFQ=\",\"Modulus\":\"vSPpZZ4r5zhM3rlaS75i33l6wgQjk9YR1y/QV6+r2NoJS8I17dLZrqk6ivSCgOkRT08/wNUvAUO6vuvaSKo5mG9AalzwVA1EM5FOaaWxYqs3mSnIqft1leL8Q/DHx1A4RFW/SVq+3n8WXV0w+NW4p33yH3eLKD6O3aeCBj9kgkOammeu5uYqcPpu/UQd4tcTEuwE6d1Mcyf6VeBK4J9DMDAcrY43mWc4s/3Vh4AJQXs/iEtqxxlpk8Zv0BNoucomkbw8ZsvdGW+FcnCmcCvBsWBZhI/PZflQGr7FNcsL2LHGQxeIZ1epNzCeTcyVcjZjnNuBcGBL1kymOwOyGN5NPQ==\",\"P\":\"+UUFEGRdnDjk5K69Ju21lRJA34EIqmS+kY0hiR9mZE10toflVi911AVdDhgY5RW8P0fhABenNlEn28MwcX9uTPSX0sXZmKk/GjZEUeTf1mX4nHnI6O0/XfwbioEIB2O6tCE8tC1ZnOlrZiic3wOG85WWwlA4EHvajSI/o2LFlxM=\",\"Q\":\"wj9FZgdosbUNqTaf4PiPIh/C/NORBeWGv8V2D9OFgjHaJ+gOKOgnWyxuhtjTyQxvG7ruwv4YH8KcSGEknWyAFI6E3DUMf+H7lG0GpX0ZsaQMuznIayafAYNPrdIUo0uJfQeMqhxMwruncdEq49JwgEgx0kpn/N8n5wxyH70EhG8=\"}")]
        // BouncyCastle RSA Private Key
        [InlineData("{\"D\":\"P0EPXbh5vJ4brcTGuIXFjGy9oxnWr5Hf5tVD0Ss/8d4+f3EgKvfFzu3u067AnHe5as2NXoF7B6bpr5UQDMUQkTXkSvFq2nboHCSRFjhWz/3KFPn/1rWVFRmnWlvLJ7w71jzCtn2PqtJyUbJFEEamdGW0k0BssFlr8b397by9ExV+5VXlduO8OzosLWYj3SYk3pFwZyXtlXm66Nar5M8IpZUw/6BVFwflyYqUKhABeAtmtv7MRP4U0CYDUF69Sxd5vCzJ62oF8WcULmlw2+GtS3a/wBQ/lXTZh4BoBafOykqNyqN5E2phTktjjZmjC8KaEzfvdODnna0XLaeVB8O/2Q==\",\"P\":\"4NqqvWWJ0qPkck38L0/MThYIAEt8TTz4W1eJJA/2qp6HYcWD4KeMQt18DWODB0GBUfwvz2btRTPJUB2j1AGrU81c6JaDySoGgArHF3lv5oYSL784Px2mqiRTXA5x/Bw/bvqfks5mJ7S8SO/my9bjtH91zvR9UDDKnr34+OVVSoc=\",\"Q\":\"vCu9tPrrbXqN72BJs0FdVrRbQ5KX2moISK9a+g1W2m5ZxnE9EHDv4HiGwyfDxhU8tTZ/Bloh5SxK9l+ux46ywDux7WUW73+xGGA1hd0hJyFJ2RQICv5mT9piIEu/+VnJzyI3c6yU3oiY3KQPkTO5GOx6dofYy2WwlM9Hzii5trs=\",\"DP\":\"HvJ5pW+gNHmSK5lIKErXV7f4ifHZvdeyZv/5RBleXcVL5M0GhZkJ2Poa5MzZb9o4LkyDWAxWg7vI7Vnm/nrsVbBiJTDyGnHKSz0wga6ZFCVHw4KR/z3ZfnlZb8YdMhHBOUkNRWta7AQYFgHOxidhV6pjUISd6reMa6TB65/EyWk=\",\"DQ\":\"CvcVj/VLQM7ydG+M++gkM0hBRTfGp5CkOPAXAhlC5Wmmy5yPrWSXZeJAICEyFFnqdrjdQBaCgSNKnv7GZZSYMAGKhcXtRzmOrVf15n4TT39uGTtEmLdoaODV9QHVBwfHbc2Vo6T769fT6I+a5KA5+gzVuhCCfp/HYXSOv6G56L8=\",\"InverseQ\":\"jVR5DS/wO0qEnxkMcjboLFA4WuMGkchzvPJOnE8jDtATTvLT554qCSoo+ait3WOjdHCDDILCEFWUpquFY/5NlSk4Yi9ECPIXTGdwBzURETU3Pi97DJ6eZY/0x6foyNm8GN75dhOCPcXcorvX9RxMtUT/j5mRfszfzsrLfjFx1Ww=\",\"Modulus\":\"pUcAviqTeZlTTevWP4fJziy5wdEHBBvWhyVxtIDG4BNv3DuFPKWEUxQVfbMBRy8HzZwulUoNxRuXeEgDcrZXzKADRkywklazN4KN0UTINurP37UXqnvdPllVBTzI+2acrMg4iVd97pa918BhWvpfmuAatcSY8UNOB9FKpdJtC3GEegPhP4DQ0QD7JEN9OrviCXebPcdJbgsI7zUqNs7kXXf0RWIMgP1HgI42Wbcmlc6ce41zv7xouBaY0bsuJfZOiR1E0+aCJ34L+JFbZahGZKuoYcugIIvFo5rXhIJ48UiLWO2uThttX4gTZmmfQVYXB3xvLWxXtc1U70jEG9hqnQ==\",\"Exponent\":\"AQAB\"}")]
        public void Should_SignData_With_PrivateKey(string privateKeyJson)
        {
            var rsaCrypto = new RsaBcCrypto();

            var signature = rsaCrypto.SignData(_plainText, privateKeyJson);

            signature.Should().NotBeNullOrWhiteSpace();
            signature.Should().NotBe(_plainText);
        }

        [Theory]
        // Signed with Microsoft RSA Public Key
        [InlineData("UbGDuwPp3WmJkzUvnlYckI5yYFg2J3QI6/jymO823j860Z0eNpnUHMTz5QF/qwvV3iafNkFoJuaNznmelW3up32jSJUzm8NfUR3YDrSUqtLjzhKMV6iaoNmfAZChQQRYteid82omBXLemApVmuxANcK4ESnQVKNF/lw3u7UGsvY4TkfFLeVWZoZ6vHeLgxixQAEO38uBNzM0qFlORKI8bwBedzRZg62txEeYWB4U7ZnPo6HIpbGpym1qlJZ2SIDYC/g2CJNMvNW40Jk5CGv7R25yEohKo/RRHu6wgn4X/629E9XZLH/8y+gAJiJRvhBgceKMPA3IMirpfxE0NhdUAA==",
            "{\"D\":null,\"DP\":null,\"DQ\":null,\"Exponent\":\"AQAB\",\"InverseQ\":null,\"Modulus\":\"vSPpZZ4r5zhM3rlaS75i33l6wgQjk9YR1y/QV6+r2NoJS8I17dLZrqk6ivSCgOkRT08/wNUvAUO6vuvaSKo5mG9AalzwVA1EM5FOaaWxYqs3mSnIqft1leL8Q/DHx1A4RFW/SVq+3n8WXV0w+NW4p33yH3eLKD6O3aeCBj9kgkOammeu5uYqcPpu/UQd4tcTEuwE6d1Mcyf6VeBK4J9DMDAcrY43mWc4s/3Vh4AJQXs/iEtqxxlpk8Zv0BNoucomkbw8ZsvdGW+FcnCmcCvBsWBZhI/PZflQGr7FNcsL2LHGQxeIZ1epNzCeTcyVcjZjnNuBcGBL1kymOwOyGN5NPQ==\",\"P\":null,\"Q\":null}")]
        // Signed with BouncyCastle RSA Public Key
        [InlineData("oqChJWK+pHY/iAMrK1qBBfD/u8uhZa+RkvfdD01kppRmunlsdO6LWrjOhsqQfLp770mAbSwLdwA5upf5/Gww1QsDmjTBN4Kd/Cs4BHw/eKO6aC2qpaEMvXrI+Ehw/YxMM9RZu9Wv1f8FKg1po4tLhPiStACE3Eg7EFEEDRAA31jbxaE2K4FbbaOtpfmpKkoEWgmyWvXgrVqHaorJ9unYDDoJ7sLvKIRhsE7PDkNxwoI2qGk4bXp+oRIUSJkKGLXLkyjRhZQknQciZZx1zBxLM0VChq8OqvcOVqMB+A2k3xEUW38ZiEqngEah++yC/Q/mssVr2DdlC8JZvfyqoU+mIA==",
            "{\"Modulus\":\"pUcAviqTeZlTTevWP4fJziy5wdEHBBvWhyVxtIDG4BNv3DuFPKWEUxQVfbMBRy8HzZwulUoNxRuXeEgDcrZXzKADRkywklazN4KN0UTINurP37UXqnvdPllVBTzI+2acrMg4iVd97pa918BhWvpfmuAatcSY8UNOB9FKpdJtC3GEegPhP4DQ0QD7JEN9OrviCXebPcdJbgsI7zUqNs7kXXf0RWIMgP1HgI42Wbcmlc6ce41zv7xouBaY0bsuJfZOiR1E0+aCJ34L+JFbZahGZKuoYcugIIvFo5rXhIJ48UiLWO2uThttX4gTZmmfQVYXB3xvLWxXtc1U70jEG9hqnQ==\",\"Exponent\":\"AQAB\"}")]
        public void Should_VerifySignautre_With_PublicKey(string signature, string publicKeyJson)
        {
            var rsaCrypto = new RsaBcCrypto();

            var verified = rsaCrypto.VerifySignature(_plainText, signature, publicKeyJson);

            verified.Should().BeTrue();
        }
    }
}
