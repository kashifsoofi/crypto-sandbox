import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.UUID;

import org.junit.Test;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

public class RsaCryptoTests {
	private final String PlainText = "Here is some data to encrypt!";

	@Test
	public void should_Generate_KeyPair()
		throws NoSuchAlgorithmException
	{
		RsaCrypto rsaCrypto = new RsaCrypto();
		String[] privateAndPublicKeyJson = rsaCrypto.generateKeyPair(2048);

		assertEquals(privateAndPublicKeyJson.length, 2);
		assertNotNull(privateAndPublicKeyJson[0]);
		assertNotNull(privateAndPublicKeyJson[1]);
	}

	@Test
	public void should_EncryptAndDecrypt_WithGeneratedKey()
		throws UnsupportedEncodingException, InvalidKeyException, InvalidAlgorithmParameterException, Exception {
		RsaCrypto rsaCrypto = new RsaCrypto();
		String[] privateAndPublicKeyJson = rsaCrypto.generateKeyPair(2048);

		String privateKeyJson = privateAndPublicKeyJson[0];
		String publicKeyJson = privateAndPublicKeyJson[1];

		String encrypted = rsaCrypto.encrypt(PlainText, publicKeyJson);

		assertNotNull(encrypted);

		String decrypted = rsaCrypto.decrypt(encrypted, privateKeyJson);

		assertNotNull(decrypted);
		assertEquals(decrypted, PlainText);
	}
}