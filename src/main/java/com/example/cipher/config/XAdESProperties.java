package com.ControlSystem.config;

import lombok.AllArgsConstructor;
import lombok.Getter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.ConstructorBinding;

@AllArgsConstructor
@Getter
@ConstructorBinding
@ConfigurationProperties(prefix = "xades")
public class XAdESProperties {

    private final String certFolderPath;
    private final String certName;
    private final String certPass;
    private final String keyStoreFolderPath;
    private final String keyStoreName;
    private final String keyStorePass;

    private final String tsaUrl;

    public String getKeyStoreFilePath() {
        return keyStoreFolderPath + keyStoreName;
    }

    public String getCertFilePath() {
        return certFolderPath + certName;
    }
}
