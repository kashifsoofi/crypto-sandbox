import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.KeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class AesCrypto {

	public enum CipherMode {
		CBC,
		GCM
	}

	public enum Padding {
		NoPadding,
		PKCS5Padding
	}

	private final String ALGORITHM = "AES";
	private final byte AesIvSize = 16;
	private final byte GcmTagSize = 16;

	private CipherMode cipherMode;
	private Padding padding;

	private String getTransformation() {
		return ALGORITHM + "/" + cipherMode.toString() + "/" + padding.toString();
	}

	public AesCrypto(CipherMode cipherMode, Padding padding) {
		this.cipherMode = cipherMode;
		this.padding = padding;
	}

	public String encrypt(String plainText, 
						  byte[] key)
				   throws InvalidKeyException,
							 InvalidAlgorithmParameterException,
							 Exception {
		SecretKey secretKey = new SecretKeySpec(key, ALGORITHM);

		SecureRandom random = new SecureRandom();
		byte[] iv = random.generateSeed(AesIvSize);

		Cipher cipher = Cipher.getInstance(getTransformation());
		cipher.init(Cipher.ENCRYPT_MODE, secretKey, createParameterSpec(iv, GcmTagSize * 8));

		byte[] plainTextBytes = plainText.getBytes("UTF8");
		byte[] encryptedBytes = cipher.doFinal(plainTextBytes);
		return packCipherData(encryptedBytes, iv);
	}

	public String decrypt(String cipherText, 
						  byte[] key)
				   throws InvalidKeyException,
						  InvalidAlgorithmParameterException,
						  Exception {
		SecretKey secretKey = new SecretKeySpec(key, ALGORITHM);

		List<Object> cipherData = unpackCipherData(cipherText);
		byte[] encryptedBytes = (byte[])cipherData.get(0);
		byte[] iv = (byte[])cipherData.get(1);
		byte gcmTagSize = (byte)cipherData.get(2);

		Cipher cipher = Cipher.getInstance(getTransformation());
		cipher.init(Cipher.DECRYPT_MODE, secretKey, createParameterSpec(iv, gcmTagSize * 8));

		byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
		return new String(decryptedBytes, "UTF8");
	}

	private AlgorithmParameterSpec createParameterSpec(byte[] iv, int macSize) 
		throws Exception {
		if (cipherMode == CipherMode.CBC) {
			return new IvParameterSpec(iv);
		}
		else if (cipherMode == CipherMode.GCM) {
			return new GCMParameterSpec(macSize, iv);
		}

		throw new Exception("Unsupported CipherMode");
	}

	private String packCipherData(byte[] encryptedBytes, byte[] iv) {
		int capacity = encryptedBytes.length + iv.length + 1;
		if (cipherMode == CipherMode.GCM) {
			capacity += 1;
		}

		ByteBuffer buffer = ByteBuffer.allocate(capacity);
		buffer.put(AesIvSize);
		if (cipherMode == CipherMode.GCM) {
			buffer.put(GcmTagSize);
		}
		buffer.put(iv);
		buffer.put(encryptedBytes);
		byte[] data = buffer.array();
		return Base64.getEncoder().encodeToString(data);
	}

	private List<Object> unpackCipherData(String cipherText) {
		byte[] cipherData = Base64.getDecoder().decode(cipherText);
		ByteBuffer buffer = ByteBuffer.wrap(cipherData);
		byte ivLength = buffer.get();
		byte gcmTagSize = 0;
		if (cipherMode == CipherMode.GCM) {
			gcmTagSize = buffer.get();
		}

		byte[] iv = new byte[ivLength];
		buffer.get(iv);
		byte[] encryptedBytes = new byte[buffer.remaining()];
		buffer.get(encryptedBytes);

		return Arrays.asList(encryptedBytes, iv, gcmTagSize);
	}
}