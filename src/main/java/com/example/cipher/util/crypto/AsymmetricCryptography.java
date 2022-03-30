package com.ControlSystem.util.crypto;

import com.ControlSystem.config.CryptographyProperties;
import org.springframework.stereotype.Component;

import javax.crypto.*;
import java.security.*;

@Component
public class AsymmetricCryptography {

    private Cipher cipher;
    private final CryptographyProperties cryptographyProperties;

    public AsymmetricCryptography(CryptographyProperties cryptographyProperties) {
        this.cryptographyProperties = cryptographyProperties;
    }


    public byte[] encrypt(byte[] contentToEncrypt, PrivateKey privateKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {

        byte[] encryptedBytes = null;

        cipher = Cipher.getInstance(cryptographyProperties.getKeyPairAlgorithm());
        cipher.init(Cipher.ENCRYPT_MODE, privateKey);
        encryptedBytes = cipher.doFinal(contentToEncrypt);

        return encryptedBytes;
    }


    public byte[] decrypt(byte[] encryptedBytes, PublicKey publicKey) throws NoSuchPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {

        byte[] decryptedBytes = null;

        cipher = Cipher.getInstance(cryptographyProperties.getKeyPairAlgorithm());
        cipher.init(Cipher.DECRYPT_MODE, publicKey);
        decryptedBytes = cipher.doFinal(encryptedBytes);

        return decryptedBytes;

    }
}
