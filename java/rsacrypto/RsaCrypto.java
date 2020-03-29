import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;

import javax.crypto.Cipher;

import com.google.gson.Gson;

public class RsaCrypto {

	public enum CipherMode {
		ECB
	}

	public enum Padding {
		OAEPWithSHA256AndMGF1Padding
	}

	private final String ALGORITHM = "RSA";

	private CipherMode cipherMode;
	private Padding padding;

	private String getTransformation() {
		return ALGORITHM + "/" + cipherMode.toString() + "/" + padding.toString();
	}

	public RsaCrypto() {
		this.cipherMode = CipherMode.ECB;
		this.padding = Padding.OAEPWithSHA256AndMGF1Padding;
	}

	public String[] generateKeyPair(int keySize)
		throws NoSuchAlgorithmException {
		String[] privateAndPublicKeyJson = new String[2];

		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(ALGORITHM);
		keyPairGenerator.initialize(keySize);
		KeyPair keyPair = keyPairGenerator.genKeyPair();

		privateAndPublicKeyJson[0] = new RsaPrivateKeyParameters((RSAPrivateCrtKey)keyPair.getPrivate()).toJson();
		privateAndPublicKeyJson[1] = new RsaPublicKeyParameters((RSAPublicKey)keyPair.getPublic()).toJson();

		return privateAndPublicKeyJson;
	}

	public String encrypt(String plainText,
						  String publicKeyJson)
				   throws InvalidKeyException,
							 InvalidAlgorithmParameterException,
							 Exception {
		RsaPublicKeyParameters publicKeyParameters = toRsaPublicKeyParameters(publicKeyJson);

		Cipher cipher = Cipher.getInstance(getTransformation());
		cipher.init(Cipher.ENCRYPT_MODE, publicKeyParameters.toRSAPublicKey());

		byte[] plainTextBytes = plainText.getBytes("UTF8");
		byte[] encryptedBytes = cipher.doFinal(plainTextBytes);
		return encode(encryptedBytes);
	}

	public String decrypt(String cipherText, 
						  String privateKeyJson)
				   throws InvalidKeyException,
						  InvalidAlgorithmParameterException,
						  Exception {
		RsaPrivateKeyParameters privateKeyParameters = toRsaPrivateKeyParameters(privateKeyJson);

		byte[] encryptedBytes = decode(cipherText);

		Cipher cipher = Cipher.getInstance(getTransformation());
		cipher.init(Cipher.DECRYPT_MODE, privateKeyParameters.toRSAPrivateCrtKey());

		byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
		return new String(decryptedBytes, "UTF8");
	}

    private String encode(byte[] data) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(data);
    }

    private byte[] decode(String serialized) {
        return Base64.getUrlDecoder().decode(serialized);
	}
	
	private RsaPrivateKeyParameters toRsaPrivateKeyParameters(String json) {
		Gson gson = new Gson();
		return gson.fromJson(json, RsaPrivateKeyParameters.class);
	}

	private RsaPublicKeyParameters toRsaPublicKeyParameters(String json) {
		Gson gson = new Gson();
		return gson.fromJson(json, RsaPublicKeyParameters.class);
	}

    public class RsaPrivateKeyParameters {
        public byte[] D;
        public byte[] P;
        public byte[] Q;
        public byte[] DP;
        public byte[] DQ;
        public byte[] InverseQ;
        public byte[] Modulus;
		public byte[] Exponent;
		
		public RsaPrivateKeyParameters(RSAPrivateCrtKey privateKey) {
			D = privateKey.getPrivateExponent().toByteArray();
			P = privateKey.getPrimeP().toByteArray();
			Q = privateKey.getPrimeQ().toByteArray();
			DP = privateKey.getPrimeExponentP().toByteArray();
			DQ = privateKey.getPrimeExponentQ().toByteArray();
			InverseQ = privateKey.getCrtCoefficient().toByteArray();
			Modulus = privateKey.getModulus().toByteArray();
			Exponent = privateKey.getPublicExponent().toByteArray();
		}

		public RSAPrivateCrtKey toRSAPrivateCrtKey()
			throws NoSuchAlgorithmException, InvalidKeySpecException {
			RSAPrivateCrtKeySpec keySpec = new RSAPrivateCrtKeySpec(
				new BigInteger(Modulus),
				new BigInteger(Exponent),
				new BigInteger(D),
				new BigInteger(P),
				new BigInteger(Q),
				new BigInteger(DP),
				new BigInteger(DQ),
				new BigInteger(InverseQ));
			KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
			return (RSAPrivateCrtKey) keyFactory.generatePrivate(keySpec);
		}

		public String toJson() {
			Gson gson = new Gson();
			return gson.toJson(this);
		}
    }

    public class RsaPublicKeyParameters {
        public byte[] Modulus;
		public byte[] Exponent;
		
		public RsaPublicKeyParameters(RSAPublicKey publicKey) {
			Modulus = publicKey.getModulus().toByteArray();
			Exponent = publicKey.getPublicExponent().toByteArray();
		}

		public RSAPublicKey toRSAPublicKey()
			throws NoSuchAlgorithmException, InvalidKeySpecException {
			RSAPublicKeySpec keySpec = new RSAPublicKeySpec(
				new BigInteger(Modulus),
				new BigInteger(Exponent));

			KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
			return (RSAPublicKey) keyFactory.generatePublic(keySpec);
	}

		public String toJson() {
			Gson gson = new Gson();
			return gson.toJson(this);
		}
	}	
}