package rsacrypto

import (
	"testing"
)

const plainText = "Here is some data to encrypt!"

func TestGenerateKeyPair(t *testing.T) {
	rsaCrypto := RsaCrypto { }
	privateKeyJson, publicKeyJson, err := rsaCrypto.GenerateKeyPair(2048)
	if err != nil {
		t.Errorf("%s", err);
	}
	
	if "" == privateKeyJson || "" == publicKeyJson {
		t.Errorf("Error generating key pair")
	}
}

func TestEncryptAndDecryptWithGeneratedKey(t *testing.T) {
	rsaCrypto := RsaCrypto { }
	privateKeyJson, publicKeyJson, err := rsaCrypto.GenerateKeyPair(2048)
	if err != nil {
		t.Errorf("%s", err);
		return
	}

	encrypted, err := rsaCrypto.Encrypt(plainText, publicKeyJson)
	if err != nil {
		t.Errorf("%s", err);
		return
	}

	decrypted, err := rsaCrypto.Decrypt(encrypted, privateKeyJson, "go")
	if err != nil {
		t.Errorf("%s", err);
		return
	}

	if decrypted != plainText {
		t.Errorf("Decrypt error, got: %s, want: %s", decrypted, plainText)
	}
}

func TestDecryptWithPrivateKey(t *testing.T) {
	var testData = []struct {
		CipherText string
		Key string
		Provider string
	} {
		{
			"GZWfOpQ01uILRKnBMTkAbQheVu1PlUD2T599GI5VALihsETOW6pw/QZl8ScTER3sRIAs56bZODrnvnFvfVtGzIIBTuz84AIB2Mb/YsNeDo+qF4qdy9FJHhXOuaSDlDm2iHaE7taFbFxl2POvmfmM694/UQse4/8ultRLH9Mbw5kYGWiHQgBoEm54wbWK19c0I5868fo3kzDkYlY2/mr1qecHWytXJp8s7qUnVRw8beI0di9w+IavQ2zApic9GdxhxTWqFxOmo/VA+tH3bQJF9lcBdUft/EHn5I/6gsJP+xOs70ykvV2Z5zMiX1gGXuyI5cKKR3qdhEtEYGaytvvbUQ==",
			"{\"D\":\"iyAyW3QomTEZoi83U0XdFsMV4EcJIIKzptTd7NIklyNy+Q4He0PAqbCDhpjqsgY+nFcP7zkhFU4LvMpiS1cjfJRBDrwEb98+TqxQwHeH7qtA/2Hz380/JhzMMPGZEmxYpzNnvH6KrcFP4ydckX0sEdAb3LejXdv+XN8NTqkstn/bqDmgRTkfjCaslVd/HcVO3jYHPBx6bryjU+4SK2XnBZj5nnkDxTynF+T9C4Wi3np2/xUBOfynIV8O6GrhRgKlhecpMLfXiD8nz0HJ7ahWLltMD75RWgjE+YxQsqFQiRe5OJtMcYDqPBe4vi65+QJ2eddi7Kw3iZr/C37tSLxpBQ==\",\"DP\":\"qthpbiC8IDTGfQ5eym2mRPPrzsRrog3Gp4/pakhBL4H++pQN1ZJV2emLK/vMJEdPbLfhOOT9UDczcGZJr6C9grUp0eaVCxMFEvwau155JENjsCuwTiU9hzch0T46uIXcE1Wse3mRsAA0AiLX0epi9lSSrb+5jWK2GoFcyKkL8E0=\",\"DQ\":\"XXh0vJP0HQ8yc6qFZIw21ATUnzRvJJc+MCmklhkCtZOnlmxj4+tShNzskpbj0mrZTE63db0vfpj2+x1DsTz0pO+vnwcn7KGhndqYyClao9B9D9rORkFfYir9vHbK14kRr8hiN7lGdq419N7h9J7e49vZnYeQYm4/lT636+3YrqE=\",\"Exponent\":\"AQAB\",\"InverseQ\":\"tICa95haC4FO7JFr/XF9VXemso/Rq3yDUGb1tn0wfooht6OmsN+QZNHzPzW6/dsaerCT+czeOB9GhCLHl5iMTlELb8r8Ri1pmp6SSanl0h6TarxobEYGfdYhigpNKsXAVKVuJIDzFMVzdkmjrSyepEgZWYVyrlc2F8esSGQyUFQ=\",\"Modulus\":\"vSPpZZ4r5zhM3rlaS75i33l6wgQjk9YR1y/QV6+r2NoJS8I17dLZrqk6ivSCgOkRT08/wNUvAUO6vuvaSKo5mG9AalzwVA1EM5FOaaWxYqs3mSnIqft1leL8Q/DHx1A4RFW/SVq+3n8WXV0w+NW4p33yH3eLKD6O3aeCBj9kgkOammeu5uYqcPpu/UQd4tcTEuwE6d1Mcyf6VeBK4J9DMDAcrY43mWc4s/3Vh4AJQXs/iEtqxxlpk8Zv0BNoucomkbw8ZsvdGW+FcnCmcCvBsWBZhI/PZflQGr7FNcsL2LHGQxeIZ1epNzCeTcyVcjZjnNuBcGBL1kymOwOyGN5NPQ==\",\"P\":\"+UUFEGRdnDjk5K69Ju21lRJA34EIqmS+kY0hiR9mZE10toflVi911AVdDhgY5RW8P0fhABenNlEn28MwcX9uTPSX0sXZmKk/GjZEUeTf1mX4nHnI6O0/XfwbioEIB2O6tCE8tC1ZnOlrZiic3wOG85WWwlA4EHvajSI/o2LFlxM=\",\"Q\":\"wj9FZgdosbUNqTaf4PiPIh/C/NORBeWGv8V2D9OFgjHaJ+gOKOgnWyxuhtjTyQxvG7ruwv4YH8KcSGEknWyAFI6E3DUMf+H7lG0GpX0ZsaQMuznIayafAYNPrdIUo0uJfQeMqhxMwruncdEq49JwgEgx0kpn/N8n5wxyH70EhG8=\"}",
			"Microsoft RSA/OaepSHA256",
		},
		{
			"SGlvKXEs3uR2u11xJqnuRjXbWTICcb6h+u1ULu21jso1ux6guz0Et7v9IxkdGNQmd+7UiZlgt2DWofVMjCe3X/8zD/FxmM2sJKR9Sv1M0JcaiR4TYV8SI8MY6EgLNR3TN3jzwCWO0b+0VbY8BZEFD9KiRbxdlSP60p+s54t+Pck/OVaV8fj2TaSoxbD8L85eg8ggyf72bHVqREzfS9ozr2r/PwfNXutHscpJWjKEiGfjnp6Jaj3PyIuAmfhCYUPdV4UyWLLimZ2h9A0pVh5gLgP1G3acp0iC1/wPuFp2uRSIyr3WoP7Bp8xQa4766NqGcdFSWOk5Xz674PIwX29/UA==",
			"{\"D\":\"P0EPXbh5vJ4brcTGuIXFjGy9oxnWr5Hf5tVD0Ss/8d4+f3EgKvfFzu3u067AnHe5as2NXoF7B6bpr5UQDMUQkTXkSvFq2nboHCSRFjhWz/3KFPn/1rWVFRmnWlvLJ7w71jzCtn2PqtJyUbJFEEamdGW0k0BssFlr8b397by9ExV+5VXlduO8OzosLWYj3SYk3pFwZyXtlXm66Nar5M8IpZUw/6BVFwflyYqUKhABeAtmtv7MRP4U0CYDUF69Sxd5vCzJ62oF8WcULmlw2+GtS3a/wBQ/lXTZh4BoBafOykqNyqN5E2phTktjjZmjC8KaEzfvdODnna0XLaeVB8O/2Q==\",\"P\":\"4NqqvWWJ0qPkck38L0/MThYIAEt8TTz4W1eJJA/2qp6HYcWD4KeMQt18DWODB0GBUfwvz2btRTPJUB2j1AGrU81c6JaDySoGgArHF3lv5oYSL784Px2mqiRTXA5x/Bw/bvqfks5mJ7S8SO/my9bjtH91zvR9UDDKnr34+OVVSoc=\",\"Q\":\"vCu9tPrrbXqN72BJs0FdVrRbQ5KX2moISK9a+g1W2m5ZxnE9EHDv4HiGwyfDxhU8tTZ/Bloh5SxK9l+ux46ywDux7WUW73+xGGA1hd0hJyFJ2RQICv5mT9piIEu/+VnJzyI3c6yU3oiY3KQPkTO5GOx6dofYy2WwlM9Hzii5trs=\",\"DP\":\"HvJ5pW+gNHmSK5lIKErXV7f4ifHZvdeyZv/5RBleXcVL5M0GhZkJ2Poa5MzZb9o4LkyDWAxWg7vI7Vnm/nrsVbBiJTDyGnHKSz0wga6ZFCVHw4KR/z3ZfnlZb8YdMhHBOUkNRWta7AQYFgHOxidhV6pjUISd6reMa6TB65/EyWk=\",\"DQ\":\"CvcVj/VLQM7ydG+M++gkM0hBRTfGp5CkOPAXAhlC5Wmmy5yPrWSXZeJAICEyFFnqdrjdQBaCgSNKnv7GZZSYMAGKhcXtRzmOrVf15n4TT39uGTtEmLdoaODV9QHVBwfHbc2Vo6T769fT6I+a5KA5+gzVuhCCfp/HYXSOv6G56L8=\",\"InverseQ\":\"jVR5DS/wO0qEnxkMcjboLFA4WuMGkchzvPJOnE8jDtATTvLT554qCSoo+ait3WOjdHCDDILCEFWUpquFY/5NlSk4Yi9ECPIXTGdwBzURETU3Pi97DJ6eZY/0x6foyNm8GN75dhOCPcXcorvX9RxMtUT/j5mRfszfzsrLfjFx1Ww=\",\"Modulus\":\"pUcAviqTeZlTTevWP4fJziy5wdEHBBvWhyVxtIDG4BNv3DuFPKWEUxQVfbMBRy8HzZwulUoNxRuXeEgDcrZXzKADRkywklazN4KN0UTINurP37UXqnvdPllVBTzI+2acrMg4iVd97pa918BhWvpfmuAatcSY8UNOB9FKpdJtC3GEegPhP4DQ0QD7JEN9OrviCXebPcdJbgsI7zUqNs7kXXf0RWIMgP1HgI42Wbcmlc6ce41zv7xouBaY0bsuJfZOiR1E0+aCJ34L+JFbZahGZKuoYcugIIvFo5rXhIJ48UiLWO2uThttX4gTZmmfQVYXB3xvLWxXtc1U70jEG9hqnQ==\",\"Exponent\":\"AQAB\"}",
			"BouncyCastle RSA/ECB/OAEPWithSHA256AndMGF1Padding",
		},
		{
			"UR7USnP1BMqoo0XtUEnNqcMiF/ArTooUn8Vd9v+iIfvO31rPvidg3XPEhM5y2GiCMqkn1Q018QISUygr+ekPXx7otSegOBChhZvRCD7/WtdV+UPNAI64b2aCOm6g2zaLz+E8OsFuzehzVaVnasKRhfl0pG5IkY8sWYIZFVJoFdRO3XV3xz7+xwgSePyi7ElGzBq8b3kxsjDEisuO1U43UIIEc2ldx67ErZ+HZqcCOn5L5pht2gdHD6RKVxdc1e2K5Tnv0wxo0DpjvUmOiORNe2NkAJG7sMhx9olOtmZuHjg1nSaXcrqb2w8Hy0COKto65zszvM/Nk2BUXT4J1QVbRw==",
			"{\"D\":\"m+rZQXZ0Y3T17lHRCqcDldI6GEGlrX8obEPNGeU3XRnfXiA1V0cYcOwe9vidyVO/AXnYQFfK5mi0/PR2PE/c5Ql8TfXZ289mn2VrYWIdO3LdzACEEnyWzjOhjjeBufZCi6/z3c3vaKcRCVk8XgBDI9/daxy6zldEXvpv6BiQ4UKbyCenuZJCSZiX8uasVbXd0qAGWod4Tztb/zvT90SkkcYfElapB9mUiFDfRezl9ZbGBAlPRAkVtt+5Sl8/NZGL/2K8hcRmTywt7VeBXmhdWsiFmj+lpyMx/pGWyBncRaH5ads5yq8G2GmSnH4a7p5LRp/O9WzLxEjnMogQ24YtAQ==\",\"P\":\"yluJKli0Ju6yAjDjYTCmhOCA6KfQ4M1PVv8xaaIKArVOXBhP8s8E8fjRPysrYKQ0cPh98WZX61a4BJ5wVScdc+E/yVbPoLN2QsIZersyQre3iUER+N93826nkuz/3FkTbIXr6SQmXLYv0gfcW0Xs0IJbzUYWtU30jPHXM8FqTaE=\",\"Q\":\"zjoJZAAU2r0Tt9mCBKBy62PFf/+QpUzJqtmBQrgBNPCDDWhRHvWiwZgu9/5PE8S8CC+r262xJKJN4rI7o8C2vWEjusv81WPsVOwAigamoCQvkkz3//8cQAT9/UqEjRpnSqp9QK5yre5RdDHGALS1Vg3DGVCImwByCEARxc8CrY8=\",\"DP\":\"OTfGwi2Qyw1lUg9Gy/14qEvex2pkOpxzGbNQ4oCJ+hgQDyRkvtBgopbre8QWIN5tYaAx5Gc+5vF/WPb/5mQIBPMlGSYt0U/NWbUOhVCXNpxCDlJS5Z8yiKe6RGY1NrYNMvtvKF4rZr2xKd9FJJ3SB2dE0/dEhoGDa7MaWa0QBOE=\",\"DQ\":\"ry2RiIahMGXoeAWlcjSxKc7ol6AJyMB/lkeIi5ouPEAJsrvoHLpfdL/HNhWqKoq1huanv8W9cfcE3gq0qpcrI5d+eFCLBuEIgeKvWo/nvqS+XDJRf/2+i4syDZTdH9dL4psMJoOJGsIUIvWc0kCuwNiT388PG0u3kdaKwlLkXXU=\",\"InverseQ\":\"uw+UQ9jz3o0b37+4YjiF4G8SOcuJyZAA9iGppbltUzyk//4RDmkjolcIVjIh6rOeXeM0IY+Y1ICqIOafoiO1T+QwJJEfCGzkRs4AD6zbjhLBLJOMVVemtk3y+eD4wVVFc66JT+9V4CmxZWTe+CvrUXEOFGeNXu+qgS8C90xCaWI=\",\"Modulus\":\"owOIiWqdndwAVxHBKF3CyvLIrjBQLFKeV3JwSJsyPgx/ttA7TBgtDfQCTLYyjR2mqfZWEQWuirTikcmdTTZKBYwvE+waJOyehMt1bxccEkvvM7qa+YRwwwcrpAh+k5x3pvJj7xVW80SiULVq0T/L32fio+P9440jEOcdqPbW7DR8lFhRazyMwRo9Gf3CdZQJoVT31QfqqRWjjMSXKQ4PJQEI5M7bO5uEMzSvSpeIPEvazt5Ti2ttk8uZ9PKl227Z0SjN9b99q2Hco+GWztuQdQsQheilgJoWJv84ZuTcUrf82D+epgU9k17NM2nE9N8wd145pSkHvx8HhxUcqxkp7w==\",\"Exponent\":\"AQAB\"}",
			"go",
		},
	}

	rsaCrypto := RsaCrypto { }

	for _, testData := range testData {
		decrypted, err := rsaCrypto.Decrypt(testData.CipherText, testData.Key, testData.Provider)
		if err != nil {
			t.Errorf("%s", err);
			continue
		}
	
		if decrypted != plainText {
			t.Errorf("Decrypt error for provider: %s, got: %s, want: %s", testData.Provider, decrypted, plainText)
		}
	}
}