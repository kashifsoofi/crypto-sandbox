package aescrypto;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import org.testng.annotations.*;

import org.junit.jupiter.api.Test;

public class AesCryptoTests {
	private final String PlainText = "Here is some data to encrypt!";

	@Test
	public void testEncryptAndDecryptWithGCM_NoPadding() {
		AesCrypto aesCrypto = new AesCrypto();

		String uuid = UUID.randomUUID().toString().replace("-", "");
		byte[] key = uuid.getBytes("UTF_8");
		byte[] encrypted = aesBcCrypto.encrypt(PlainText, key);

		assertNotNull(encrypted);

		byte[] decrypted = aesBcCrypto.decrypt(encrypted, key);

		assertNotNull(decrypted);
		assertEquals(PlainText, decrypted);
	}

	@Test
	public void testDecryptWithGCM_NoPadding_EncryptedByBouncyCastleCSharp() {
		String cipherText = "EBA6cMY4KY9Ry9xR6U5TZlCGqHpFSIEOqvxIkFX4QvSotaWj6XztRRTsUa+FQTKICat7RU+CIGR5VS+J9uvh";
		String key = "40f5dca181a844a08667dbe2d5393a65";

		AesCrypto aesCrypto = new AesCrypto();
		var decrypted = aesBcCrypto.decrypt(cipherText, key);

		assertNotNull(decrypted);
		assertEquals(PlainText, decrypted);
	}
}