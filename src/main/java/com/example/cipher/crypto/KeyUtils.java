package com.example.cipher.crypto;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.nio.file.Files;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class KeyUtils {

    private static String SECRET_KEY_FACTORY_ALGORITHM = "PBKDF2WithHmacSHA256";
    public static String SECRET_KEY_ALGORITHM = "AES";
    private static int ITERATION_COUNT = 65536;
    private static int KEY_LENGTH = 256;
    private static final String MASTER_ENCRYPTION_KEY = "Master encryption key (MEK).";
    private static final byte[] INITIALIZATION_VECTOR = {80, 53, 60, 77, 30, -11, 44, -41, -56, -29, -25, -92, -27, 57, -5, 45}; //secured, randomly generated values - can be public
    private static final int TAG_LENGTH_BIT = 128;

    // 128/256 bits AES secret key
    public static SecretKey getAESKey(int keySize) throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance(SECRET_KEY_ALGORITHM);
        keyGen.init(keySize, SecureRandom.getInstanceStrong());
        return keyGen.generateKey();
    }
    /**
     * Symmetric key
     * Disposable 256
     * A key is randomly generated to ensure the security
     *
     * AES key derived from a password (MEK)
     */
    public static SecretKey generateSecretKey() throws InvalidKeySpecException, NoSuchAlgorithmException {
        byte[] SALT = getRandomNonceCBC();

        SecretKeyFactory factory = SecretKeyFactory.getInstance(SECRET_KEY_FACTORY_ALGORITHM);
        KeySpec spec = new PBEKeySpec(MASTER_ENCRYPTION_KEY.toCharArray(), SALT, ITERATION_COUNT, KEY_LENGTH);

        SecretKey tmp = factory.generateSecret(spec);
        SecretKeySpec secretKey = new SecretKeySpec(tmp.getEncoded(), SECRET_KEY_ALGORITHM);

        return secretKey;
    }

    // 16 bytes IV
    public static byte[] getRandomNonceCBC() {
        byte[] nonce = new byte[16];
        new SecureRandom().nextBytes(nonce);
        return nonce;
    }

    public static IvParameterSpec getIvParameterSpec() {
        return new IvParameterSpec(INITIALIZATION_VECTOR);
    }

    public static GCMParameterSpec getGCMParameterSpec() {
        return new GCMParameterSpec(TAG_LENGTH_BIT, INITIALIZATION_VECTOR);
    }

    public static PrivateKey getPrivate(String filename) throws Exception {
        byte[] keyBytes = Files.readAllBytes(new File(filename).toPath());
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePrivate(spec);
    }

    public static PublicKey getPublic(String filename) throws Exception {
        byte[] keyBytes = Files.readAllBytes(new File(filename).toPath());
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePublic(spec);
    }
}
