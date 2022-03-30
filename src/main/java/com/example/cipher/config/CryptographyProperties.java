package com.ControlSystem.config;

import lombok.AllArgsConstructor;
import lombok.Getter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.ConstructorBinding;

@AllArgsConstructor
@Getter
@ConstructorBinding
@ConfigurationProperties(prefix = "cryptography")
public class CryptographyProperties {

    private final String secretKeyAlgorithm;
    private final String keyPairAlgorithm;
    private final String masterEncryptionKey;
    private final String secretKeyFactoryAlgorithm;
    private final int iterationCount;
    private final int secretKeyLength;
    private final byte[] initializationVector;
    private final int tagLengthBit;
    private final String privateKey;
    private final String publicKey;
    private final String symmetricCipherEncryption;
}
