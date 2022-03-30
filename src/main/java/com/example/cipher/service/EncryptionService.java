package com.ControlSystem.service;

import com.ControlSystem.config.CryptographyProperties;
import com.ControlSystem.util.crypto.AsymmetricCryptography;
import com.ControlSystem.util.crypto.CryptographyKeyFactory;
import com.ControlSystem.util.crypto.SymmetricCryptography;
import com.ControlSystem.model.ControlBlock;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.time.ZonedDateTime;

@Slf4j
@Service
@AllArgsConstructor
public class EncryptionService {

    private final CryptographyKeyFactory cryptographyKeyFactory;
    private final CryptographyProperties cryptographyProperties;
    private final SymmetricCryptography symmetricCryptography;
    private final AsymmetricCryptography asymmetricCryptography;

    /**
     * Takes content in byte array form and encrypts it with randomly generated SecretKey AES-256 and returns an
     * object ControlBlock that contains the encrypted content, encrypted SecretKey, and TimeStamp
     *
     * @param compressedData
     * @return ControlBlock
     */
    public ControlBlock encryptCompressedData(byte[] compressedData) {

        SecretKey secretKey = cryptographyKeyFactory.generateSecretKey();
        byte[] encryptedCompressedData = null;
        byte[] encryptedSecretKey = null;

        try {

            encryptedCompressedData = symmetricCryptography.encrypt(compressedData, secretKey);

            encryptedSecretKey = asymmetricCryptography.encrypt(secretKey.getEncoded(), cryptographyKeyFactory.getPrivateKey());

        } catch (InvalidAlgorithmParameterException e) {
            log.error(e.getMessage());
        } catch (NoSuchPaddingException e) {
            log.error(e.getMessage());
        } catch (IllegalBlockSizeException e) {
            log.error(e.getMessage());
        } catch (NoSuchAlgorithmException e) {
            log.error(e.getMessage());
        } catch (BadPaddingException e) {
            log.error(e.getMessage());
        } catch (InvalidKeyException e) {
            log.error(e.getMessage());
        }

        return new ControlBlock(encryptedCompressedData, encryptedSecretKey, ZonedDateTime.now());
    }

    /**
     * Encrypts ControlBlock with existing Secret Key
     *
     * @param compressedData
     * @param secretKey
     * @return ControlBlock
     */
    public ControlBlock encryptCompressedDataWithExistingSecretKey(byte[] compressedData, SecretKey secretKey) {

        byte[] encryptedCompressedData = null;
        byte[] encryptedSecretKey = null;

        try {

            encryptedCompressedData = symmetricCryptography.encrypt(compressedData, secretKey);

            encryptedSecretKey = asymmetricCryptography.encrypt(secretKey.getEncoded(), cryptographyKeyFactory.getPrivateKey());

        } catch (InvalidAlgorithmParameterException e) {
            log.error(e.getMessage());
        } catch (NoSuchPaddingException e) {
            log.error(e.getMessage());
        } catch (IllegalBlockSizeException e) {
            log.error(e.getMessage());
        } catch (NoSuchAlgorithmException e) {
            log.error(e.getMessage());
        } catch (BadPaddingException e) {
            log.error(e.getMessage());
        } catch (InvalidKeyException e) {
            log.error(e.getMessage());
        }

        return new ControlBlock(encryptedCompressedData, encryptedSecretKey, ZonedDateTime.now());
    }

    /**
     * returns decrypted ControlBlock
     *
     * @param controlBlock
     * @return ControlBlock
     */
    public ControlBlock decryptCompressedData(ControlBlock controlBlock) {

        ControlBlock encryptedControlBlock = controlBlock;

        SecretKeySpec secretKey = null;
        byte[] decryptedCompressedData = null;
        byte[] decryptedSecretKey;
        try {
            decryptedSecretKey = asymmetricCryptography.decrypt(encryptedControlBlock.getEncryptedSecretKey(), cryptographyKeyFactory.getPublicKey());
            secretKey = new SecretKeySpec(decryptedSecretKey, cryptographyProperties.getSecretKeyAlgorithm());

            decryptedCompressedData = symmetricCryptography.decrypt(encryptedControlBlock.getCompressedFile(), secretKey);

        } catch (InvalidAlgorithmParameterException e) {
            log.error(e.getMessage());
        } catch (NoSuchPaddingException e) {
            log.error(e.getMessage());
        } catch (IllegalBlockSizeException e) {
            log.error(e.getMessage());
        } catch (NoSuchAlgorithmException e) {
            log.error(e.getMessage());
        } catch (BadPaddingException e) {
            log.error(e.getMessage());
        } catch (InvalidKeyException e) {
            log.error(e.getMessage());
        }

        return new ControlBlock(decryptedCompressedData, secretKey.getEncoded(), ZonedDateTime.now());
    }


}
