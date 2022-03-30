package com.ControlSystem.config;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@EnableConfigurationProperties({XAdESProperties.class, XMLSchemaValidatorProperties.class, CryptographyProperties.class})
@Configuration
public class AppConfig {

}
