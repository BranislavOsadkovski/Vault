package com.ControlSystem.util.crypto;

import com.ControlSystem.config.CryptographyProperties;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

@Slf4j
@Component
public class CryptographyKeyFactory {

    private static SecretKey MASTER_ENCRYPTION_KEY;
    private static byte[] SALT; // to prevent rainbow attacks
    private final CryptographyProperties cryptographyProperties;
    private final ResourceLoader resourceLoader;

    public CryptographyKeyFactory(CryptographyProperties cryptographyProperties, ResourceLoader resourceLoader) {
        this.cryptographyProperties = cryptographyProperties;
        this.resourceLoader = resourceLoader;
    }

    /**
     * A key is randomly generated to ensure the security
     * Symmetric AES 256 key derived from a password or a Master Encryption Key
     */
    public SecretKey generateSecretKey() {
        SecretKeySpec secretKey = null;
        try {
            SALT = getRandomNonce();
            MASTER_ENCRYPTION_KEY = getMasterEncryptionKey();

            SecretKeyFactory factory = SecretKeyFactory.getInstance(cryptographyProperties.getSecretKeyFactoryAlgorithm());
            KeySpec spec = new PBEKeySpec(Arrays.toString(MASTER_ENCRYPTION_KEY.getEncoded()).toCharArray(), SALT, cryptographyProperties.getIterationCount(), cryptographyProperties.getSecretKeyLength());
            SecretKey tmp = factory.generateSecret(spec);
            secretKey = new SecretKeySpec(tmp.getEncoded(), cryptographyProperties.getSecretKeyAlgorithm());

        } catch (InvalidKeySpecException e) {
            log.error(e.getMessage());
        } catch (NoSuchAlgorithmException e) {
            log.error(e.getMessage());
        }

        return secretKey;
    }


    private SecretKey getMasterEncryptionKey() {
        Resource masterEncryptionKeyProperty = resourceLoader.getResource(ResourceLoader.CLASSPATH_URL_PREFIX + cryptographyProperties.getMasterEncryptionKey());

        byte[] keyBytes = new byte[0];
        try {
            File masterEncryptionKey = new File(masterEncryptionKeyProperty.getFile().getPath());
            keyBytes = Files.readAllBytes(masterEncryptionKey.toPath());
        } catch (IOException e) {
            log.error(e.getMessage());
        }
        SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, cryptographyProperties.getSecretKeyAlgorithm());
        return secretKeySpec;
    }

    private static byte[] getRandomNonce() {
        byte[] nonce = new byte[16];
        new SecureRandom().nextBytes(nonce);
        return nonce;
    }


    public GCMParameterSpec getGCMParameterSpec() {
        return new GCMParameterSpec(cryptographyProperties.getTagLengthBit(), cryptographyProperties.getInitializationVector());
    }


    public PrivateKey getPrivateKey() {
        Resource privateKeyProperty = resourceLoader.getResource(ResourceLoader.CLASSPATH_URL_PREFIX + cryptographyProperties.getPrivateKey());

        PrivateKey privateKey = null;
        try {
            byte[] keyBytes = Files.readAllBytes(new File(privateKeyProperty.getFile().getPath()).toPath());
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
            KeyFactory kf = KeyFactory.getInstance(cryptographyProperties.getKeyPairAlgorithm());
            privateKey = kf.generatePrivate(spec);
        } catch (IOException e) {
            log.error(e.getMessage());
        } catch (NoSuchAlgorithmException e) {
            log.error(e.getMessage());
        } catch (InvalidKeySpecException e) {
            log.error(e.getMessage());
        }
        return privateKey;
    }


    public PublicKey getPublicKey() {
        Resource publicKeyProperty = resourceLoader.getResource(ResourceLoader.CLASSPATH_URL_PREFIX + cryptographyProperties.getPublicKey());
        PublicKey publicKey = null;
        try {
            byte[] keyBytes = Files.readAllBytes(new File(publicKeyProperty.getFile().getPath()).toPath());
            X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
            KeyFactory kf = KeyFactory.getInstance(cryptographyProperties.getKeyPairAlgorithm());
            publicKey = kf.generatePublic(spec);
        } catch (IOException e) {
            log.error(e.getMessage());
        } catch (NoSuchAlgorithmException e) {
            log.error(e.getMessage());
        } catch (InvalidKeySpecException e) {
            log.error(e.getMessage());
        }
        return publicKey;
    }
}

