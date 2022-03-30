package com.ControlSystem.util.crypto;

import com.ControlSystem.config.CryptographyProperties;
import org.springframework.stereotype.Component;

import javax.crypto.*;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

@Component
public class SymmetricCryptography {
    private Cipher cipher;
    private final CryptographyProperties cryptographyProperties;
    private final CryptographyKeyFactory cryptographyKeyFactory;

    public SymmetricCryptography(CryptographyProperties cryptographyProperties, CryptographyKeyFactory cryptographyKeyFactory) {
        this.cryptographyProperties = cryptographyProperties;
        this.cryptographyKeyFactory = cryptographyKeyFactory;
    }


    public byte[] encrypt(byte[] content, SecretKey secretKey) throws NoSuchPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, InvalidKeyException {
        byte[] encryptedBytes;

        cipher = Cipher.getInstance(cryptographyProperties.getSymmetricCipherEncryption());
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, cryptographyKeyFactory.getGCMParameterSpec());
        encryptedBytes = cipher.doFinal(content);

        return encryptedBytes;
    }

    public byte[] decrypt(byte[] encryptedBytes, SecretKey secretKey) throws NoSuchPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, InvalidKeyException {
        byte[] decryptedBytes;

        cipher = Cipher.getInstance(cryptographyProperties.getSymmetricCipherEncryption());
        cipher.init(Cipher.DECRYPT_MODE, secretKey, cryptographyKeyFactory.getGCMParameterSpec());
        decryptedBytes = cipher.doFinal(encryptedBytes);

        return decryptedBytes;

    }
}
