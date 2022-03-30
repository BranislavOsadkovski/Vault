package com.ControlSystem.service;

import com.ControlSystem.config.XMLSchemaValidatorProperties;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.stereotype.Service;
import org.xml.sax.SAXException;

import javax.xml.XMLConstants;
import javax.xml.transform.stream.StreamSource;
import javax.xml.validation.SchemaFactory;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;

@Slf4j
@AllArgsConstructor
@Service
public class XmlValidationService {

    private final ResourceLoader resourceLoader;
    private final XMLSchemaValidatorProperties xmlSchemaValidatorProperties;

    public boolean isValid(byte[] xml) throws IOException {
        Resource xsdSchema = resourceLoader.getResource(ResourceLoader.CLASSPATH_URL_PREFIX + xmlSchemaValidatorProperties.getSchema());
        return isValid(xml, new File(xsdSchema.getFile().getPath()));
    }

    public boolean isValid(byte[] xml, File xmlSchema) {
        try (ByteArrayInputStream bais = new ByteArrayInputStream(xml)) {
            SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI)
                    .newSchema(xmlSchema)
                    .newValidator()
                    .validate(new StreamSource(bais));
        } catch (IOException | SAXException e) {
            log.error(e.getMessage(), e);
            return false;
        }
        return true;
    }
}
