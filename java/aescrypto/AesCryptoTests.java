import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.util.UUID;

import org.junit.Test;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

public class AesCryptoTests {
	private final String PlainText = "Here is some data to encrypt!";

	@Test
	public void should_EncryptAndDecrypt_WithGcmNoPadding()
		throws UnsupportedEncodingException, InvalidKeyException, InvalidAlgorithmParameterException, Exception {
		AesCrypto aesCrypto = new AesCrypto(AesCrypto.CipherMode.GCM, AesCrypto.Padding.NoPadding);

		String uuid = UUID.randomUUID().toString();
		byte[] key = uuid.replace("-", "").getBytes("UTF8");

		String encrypted = aesCrypto.encrypt(PlainText, key);

		assertNotNull(encrypted);

		String decrypted = aesCrypto.decrypt(encrypted, key);

		assertNotNull(decrypted);
		assertEquals(decrypted, PlainText);
	}

	@Test
	public void shouldDecrypt_WithGcmNoPadding()
		throws UnsupportedEncodingException, InvalidKeyException, InvalidAlgorithmParameterException, Exception {
		String cipherText = "EBBnZdJcwfZxC9kdwRMt8YVADEXHa0VOpb3HkImm7nytjHsFiQs09Cfv48vZ9fJTX/oot6saYFPkoMDSScM7";
		String encryptionKey = "9b71be77-c730-47c6-841c-d597282792ef";
		byte[] key = encryptionKey.replace("-", "").getBytes("UTF8");

		AesCrypto aesCrypto = new AesCrypto(AesCrypto.CipherMode.GCM, AesCrypto.Padding.NoPadding);
		String decrypted = aesCrypto.decrypt(cipherText, key);

		assertNotNull(decrypted);
		assertEquals(decrypted, PlainText);
	}

	@Test
	public void shouldDecrypt_WithGcmNoPadding_EncryptedByBouncyCastleCSharp()
		throws UnsupportedEncodingException, InvalidKeyException, InvalidAlgorithmParameterException, Exception {
		String cipherText = "EBA6cMY4KY9Ry9xR6U5TZlCGqHpFSIEOqvxIkFX4QvSotaWj6XztRRTsUa+FQTKICat7RU+CIGR5VS+J9uvh";
		String encryptionKey = "40f5dca1-81a8-44a0-8667-dbe2d5393a65";
		byte[] key = encryptionKey.replace("-", "").getBytes("UTF8");

		AesCrypto aesCrypto = new AesCrypto(AesCrypto.CipherMode.GCM, AesCrypto.Padding.NoPadding);
		String decrypted = aesCrypto.decrypt(cipherText, key);

		assertNotNull(decrypted);
		assertEquals(decrypted, PlainText);
	}

	@Test
	public void shouldDecrypt_WithGcmNoPadding_EncryptedByGoNewGCM()
		throws UnsupportedEncodingException, InvalidKeyException, InvalidAlgorithmParameterException, Exception {
		String cipherText = "DBBJlLBym6tNgE5vMT2Vz45ChQLqsYFwXM4jKXVtRsLKbySgM5bkdxUjhwEjEVgzAALmthebr3bZWs8=";
		String encryptionKey = "c1b7232d-cd93-4baa-b6a0-64dccb3f1583";
		byte[] key = encryptionKey.replace("-", "").getBytes("UTF8");

		AesCrypto aesCrypto = new AesCrypto(AesCrypto.CipherMode.GCM, AesCrypto.Padding.NoPadding);
		String decrypted = aesCrypto.decrypt(cipherText, key);

		assertNotNull(decrypted);
		assertEquals(decrypted, PlainText);
	}

	@Test
	public void should_EncryptAndDecrypt_WithCbcPkcs5()
		throws UnsupportedEncodingException, InvalidKeyException, InvalidAlgorithmParameterException, Exception {
		AesCrypto aesCrypto = new AesCrypto(AesCrypto.CipherMode.CBC, AesCrypto.Padding.PKCS5Padding);

		String uuid = UUID.randomUUID().toString();
		byte[] key = uuid.replace("-", "").getBytes("UTF8");

		String encrypted = aesCrypto.encrypt(PlainText, key);

		assertNotNull(encrypted);

		String decrypted = aesCrypto.decrypt(encrypted, key);

		assertNotNull(decrypted);
		assertEquals(decrypted, PlainText);
	}

	@Test
	public void shouldDecrypt_WithCbcPkcs5()
		throws UnsupportedEncodingException, InvalidKeyException, InvalidAlgorithmParameterException, Exception {
		String cipherText = "EFtp6J1Fy1zVlewstk14Klg4oV7BLtGIgdnNwfHHlHbRv2fLVUgHpo+v8CwO2QimCw==";
		String encryptionKey = "458d1677-f515-4287-868a-fb1904e2fa10";
		byte[] key = encryptionKey.replace("-", "").getBytes("UTF8");

		AesCrypto aesCrypto = new AesCrypto(AesCrypto.CipherMode.CBC, AesCrypto.Padding.PKCS5Padding);
		String decrypted = aesCrypto.decrypt(cipherText, key);

		assertNotNull(decrypted);
		assertEquals(decrypted, PlainText);
	}

	@Test
	public void shouldDecrypt_WithCbcPkcs5_EncryptedByBouncyCastleCSharp()
		throws UnsupportedEncodingException, InvalidKeyException, InvalidAlgorithmParameterException, Exception {
		String cipherText = "EFLPMGDLwsFlXqLXuM350XZv8S5DSomV7FyixHlDVI/POFKJ0IY3LzzaxUZ2jDFhIQ==";
		String encryptionKey = "850c8111-339e-453b-afdd-89a99cad849b";
		byte[] key = encryptionKey.replace("-", "").getBytes("UTF8");

		AesCrypto aesCrypto = new AesCrypto(AesCrypto.CipherMode.CBC, AesCrypto.Padding.PKCS5Padding);
		String decrypted = aesCrypto.decrypt(cipherText, key);

		assertNotNull(decrypted);
		assertEquals(decrypted, PlainText);
	}


	@Test
	public void shouldDecrypt_WithCbcPkcs5_EncryptedByMicrosoftAes()
		throws UnsupportedEncodingException, InvalidKeyException, InvalidAlgorithmParameterException, Exception {
		String cipherText = "EFb6BdUqhHJQRsVxnD53sSDfflNfWjntak2paSCpgJCsp0u46vIbHsK4mwX3g32UeA==";
		String encryptionKey = "b963fdc3-4580-468b-88be-04f6630ef700";
		byte[] key = encryptionKey.replace("-", "").getBytes("UTF8");

		AesCrypto aesCrypto = new AesCrypto(AesCrypto.CipherMode.CBC, AesCrypto.Padding.PKCS5Padding);
		String decrypted = aesCrypto.decrypt(cipherText, key);

		assertNotNull(decrypted);
		assertEquals(decrypted, PlainText);
	}
}