package com.example.cipher.crypto;

import javax.crypto.*;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.AlgorithmParameterSpec;

public class CryptoUtils {

    public static final String RSA = "RSA";
    /**
     * AES-CBC-PKCS#5  is algorithm that uses blocks of 128bits for encrypting, meaning each block is the same(128)
     * <p>
     * AES/CBC/PKCS5Padding (128) is cipher algorithm for encrypting that uses padding by adding random phrases,
     * and changing the length of the original text, so making it harder for attacker to decipher
     */
    public static final String AES_CBC_PADDING = "AES/CBC/PKCS5Padding";
    /**
     * AES-GCM is a more secure cipher than AES-CBC, because AES-CBC, operates by XOR'ing (eXclusive OR)
     * each block with the previous block and cannot be written in parallel. ...
     * AES-GCM is written in parallel which means throughput is significantly higher than AES-CBC by lowering encryption overheads.
     */
    public static final String AES_GCM_NO_PADDING = "AES/GCM/NoPadding";

    public static byte[] encrypt(byte[] contentToEncrypt, SecretKey secretKey, AlgorithmParameterSpec algorithmParameterSpec) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException {
        Cipher cipher = Cipher.getInstance(AES_GCM_NO_PADDING);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, algorithmParameterSpec);
        try {
            byte[] encryptedBytes = cipher.doFinal(contentToEncrypt);
            return encryptedBytes;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public static byte[] encrypt(byte[] msg, PrivateKey key)
            throws NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException,
            BadPaddingException, InvalidKeyException {
        Cipher cipher = Cipher.getInstance(RSA);
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(msg);
    }
}
