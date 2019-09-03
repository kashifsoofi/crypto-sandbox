import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.util.UUID;

import org.junit.Test;
import static org.junit.Assert.assertEquals;

public class AesCryptoTests {
	private final String PlainText = "Here is some data to encrypt!";

	@Test
	public void testEncryptAndDecryptWithGCM_NoPadding()
		throws UnsupportedEncodingException, InvalidKeyException, InvalidAlgorithmParameterException, Exception {
		AesCrypto aesCrypto = new AesCrypto(AesCrypto.CipherMode.GCM, AesCrypto.Padding.NoPadding);

		String uuid = UUID.randomUUID().toString().replace("-", "");
		byte[] key = uuid.getBytes("UTF8");

		String encrypted = aesCrypto.encrypt(PlainText, key);

		// assertNotNull(encrypted);

		String decrypted = aesCrypto.decrypt(encrypted, key);

		// assertNotNull(decrypted);
		assertEquals(decrypted, PlainText);
	}

	// @Test
	public void testDecryptWithGCM_NoPadding_EncryptedByBouncyCastleCSharp() 
		throws UnsupportedEncodingException, InvalidKeyException, InvalidAlgorithmParameterException, Exception {
		String cipherText = "EBA6cMY4KY9Ry9xR6U5TZlCGqHpFSIEOqvxIkFX4QvSotaWj6XztRRTsUa+FQTKICat7RU+CIGR5VS+J9uvh";
		String encryptionKey = "40f5dca181a844a08667dbe2d5393a65";
		byte[] key = encryptionKey.getBytes("UTF8");

		AesCrypto aesCrypto = new AesCrypto(AesCrypto.CipherMode.GCM, AesCrypto.Padding.NoPadding);
		String decrypted = aesCrypto.decrypt(cipherText, key);

		// assertNotNull(decrypted);
		assertEquals(decrypted, PlainText);
	}
}