package com.ControlSystem.service;

import com.ControlSystem.config.XAdESProperties;
import com.ControlSystem.util.signature.XmlSigningUtil;
import lombok.AllArgsConstructor;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.stereotype.Service;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import xades4j.production.SignedDataObjects;
import xades4j.production.XadesBesSigningProfile;
import xades4j.production.XadesSigner;
import xades4j.production.XadesTSigningProfile;
import xades4j.providers.KeyingDataProvider;
import xades4j.providers.impl.*;
import xades4j.utils.DOMHelper;
import xades4j.utils.XadesProfileResolutionException;
import xades4j.verification.XAdESVerificationResult;

import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.*;

@AllArgsConstructor
@Service
public class XmlSigningService {

    private final ResourceLoader resourceLoader;
    private final XAdESProperties signingProperties;

    public byte[] sign(byte[] xmlDocument, XmlSigningType type) throws Exception {
        Resource certResource = resourceLoader.getResource(signingProperties.getCertFilePath());
        return sign(xmlDocument, type, certResource.getFile().getPath(), signingProperties.getCertPass(), signingProperties.getTsaUrl());
    }

    public byte[] sign(byte[] xmlDocument, XmlSigningType type, String certFilePath, String certPass, String timestampingAuthorityUrl) throws Exception {
        Document doc = XmlSigningUtil.getDocumentBuilder().parse(new ByteArrayInputStream(xmlDocument));
        Element element = getDocumentElement(doc);
        KeyingDataProvider keyingDataProvider = XmlSigningUtil.createFileSystemKeyingDataProvider(XmlSigningUtil.CERT_PKCS12, certFilePath, certPass, true);
        SignedDataObjects data = XmlSigningUtil.getSignedDataObjects(element);
        getSignProfileByType(type, keyingDataProvider, timestampingAuthorityUrl).sign(data, element);

        try (ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream()) {
            outputDOM(doc, byteArrayOutputStream);
            return byteArrayOutputStream.toByteArray();
        }
    }

    public XAdESVerificationResult verify(byte[] xmlDocument) throws Exception {
        Resource keyStoreFolderResource = resourceLoader.getResource(signingProperties.getKeyStoreFolderPath());
        Resource keyStoreFileResource = resourceLoader.getResource(signingProperties.getKeyStoreFilePath());
        return verify(xmlDocument, keyStoreFolderResource.getFile().getPath(), keyStoreFileResource.getFile().getPath(), signingProperties.getKeyStorePass());
    }

    public XAdESVerificationResult verify(byte[] xmlDocument, String keyStoreFolder, String keyStoreFilePath, String keyStorePass) throws Exception {
        Document doc = XmlSigningUtil.getDocumentBuilder().parse(new ByteArrayInputStream(xmlDocument));
        Element element = getDocumentElement(doc);
        Element signatureElement = XmlSigningUtil.getSignatureElement(element);
        return XmlSigningUtil.getXadesVerificationProfile(keyStoreFolder, keyStoreFilePath, keyStorePass)
                .newVerifier().verify(signatureElement, null);
    }

    private XadesSigner getSignProfileByType(XmlSigningType type, KeyingDataProvider keyingDataProvider, String timestampingAuthorityUrl) throws XadesProfileResolutionException {
        XadesSigner signer;
        switch (type) {
            case BES_T:
                DefaultMessageDigestProvider defaultMessageDigestProvider = new DefaultMessageDigestProvider();
                TSAHttpData tsaHttpData = new TSAHttpData(timestampingAuthorityUrl);
                signer = new XadesTSigningProfile(keyingDataProvider)
                        .withTimeStampTokenProvider(new HttpTimeStampTokenProvider(defaultMessageDigestProvider, tsaHttpData))
                        .newSigner();
                break;
            case BES:
            default:
                signer = new XadesBesSigningProfile(keyingDataProvider).newSigner();
                break;
        }
        return signer;
    }

    private static void outputDOM(Node dom, OutputStream os) throws Exception {
        TransformerFactory.newInstance()
                .newTransformer()
                .transform(new DOMSource(dom), new StreamResult(os));
    }

    private Element getDocumentElement(Document doc) {
        Element elem = doc.getDocumentElement();
        DOMHelper.useIdAsXmlId(elem);
        return elem;
    }

}
