package com.ControlSystem.util.signature;

import org.apache.xml.security.utils.Constants;
import org.w3c.dom.Element;
import xades4j.algorithms.EnvelopedSignatureTransform;
import xades4j.production.DataObjectReference;
import xades4j.production.SignedDataObjects;
import xades4j.properties.DataObjectDesc;
import xades4j.providers.KeyingDataProvider;
import xades4j.providers.impl.FileSystemKeyStoreKeyingDataProvider;
import xades4j.providers.impl.PKIXCertificateValidationProvider;
import xades4j.utils.FileSystemDirectoryCertStore;
import xades4j.verification.XadesVerificationProfile;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.io.File;
import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;

public class XmlSigningUtil {

    public static final String KEY_STORE_JKS = "jks";
    public static final String CERT_PKCS12 = "PKCS12";

    public static DocumentBuilder getDocumentBuilder() {
        try {
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            dbf.setNamespaceAware(true);
            return dbf.newDocumentBuilder();
        } catch (ParserConfigurationException ex) {
            throw new NullPointerException("SignatureServicesTestBase init failed:" + ex.getMessage());
        }
    }

    public static KeyingDataProvider createFileSystemKeyingDataProvider(
            String certType,
            String certFilePath,
            String certPass,
            boolean returnFullChain) throws KeyStoreException {
        certFilePath = toPlatformSpecificFilePath(certFilePath);
        return new FileSystemKeyStoreKeyingDataProvider(certType, certFilePath,
                new FirstCertificateSelector(),
                new DirectPasswordProvider(certPass),
                new DirectPasswordProvider(certPass),
                returnFullChain);
    }

    public static XadesVerificationProfile getXadesVerificationProfile(String keyStoreFolder, String keyStoreFilePath, String keyStorePass) throws Exception {
        FileSystemDirectoryCertStore certStore = new FileSystemDirectoryCertStore(keyStoreFolder);
        KeyStore ks = createAndLoadJKSKeyStore(keyStoreFilePath, keyStorePass);
        return new XadesVerificationProfile(new PKIXCertificateValidationProvider(ks, false, certStore.getStore()));
    }

    public static Element getSignatureElement(Element element) {
        return (Element) element.getElementsByTagNameNS(Constants.SignatureSpecNS, Constants._TAG_SIGNATURE).item(0);
    }

    private static KeyStore createAndLoadJKSKeyStore(String path, String pass) throws Exception {
        try (FileInputStream fis = new FileInputStream(path)) {
            KeyStore ks = KeyStore.getInstance(KEY_STORE_JKS);
            ks.load(fis, pass.toCharArray());
            return ks;
        }
    }

    public static SignedDataObjects getSignedDataObjects(Element elem) {
        DataObjectDesc documentId = new DataObjectReference("#" + elem.getAttribute("Id"))
                .withTransform(new EnvelopedSignatureTransform());
        return new SignedDataObjects().withSignedDataObject(documentId);
    }

    private static String toPlatformSpecificFilePath(String path) {
        return path.replace('/', File.separatorChar);
    }
}
