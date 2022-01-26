package com.example.cipher.crypto;

import lombok.extern.slf4j.Slf4j;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Base64;

@Slf4j
public class Ciphers {
    static String PATH = System.getProperty("user.dir");

    public static void printToConsole(byte[] array) {
        int a = 0;
        System.out.println();
        while (a < array.length) {
            System.out.print((char) array[a]);
            a++;
        }
        System.out.println();
        System.out.println();
    }

    public static void runTest() {
        byte[] encryptedFileBytes;
        byte[] decryptedFileBytes;
        File file = new File(PATH + "/src/main/resources/data/dummy.xml");
        SecretKey secretKey;
        byte[] encryptedSecretKey;

        try {
            secretKey = KeyUtils.generateSecretKey();
            System.out.println("GENERATING AES");
            log.info("ORIGINAL SECRET KEY");
            printToConsole(secretKey.getEncoded());


            try {
                FileInputStream fileInputStream = new FileInputStream(file);
                byte[] fileBytes = fileInputStream.readAllBytes();
                fileInputStream.close();
                log.info("ORIGINAL FILE bytes");
                printToConsole(fileBytes);//logging to console

                encryptedFileBytes = CryptoUtils.encrypt(fileBytes, secretKey, KeyUtils.getGCMParameterSpec());
                log.info("ENCRYPTED FILE bytes");
                printToConsole(encryptedFileBytes);//logging to console

                encryptedSecretKey = CryptoUtils.encrypt(secretKey.getEncoded(), KeyUtils.getPrivate(PATH + "/src/main/resources/keypair/privatekey"));
                log.info("ENCRYPTED SecretKey");
                printToConsole(encryptedSecretKey);//logging to console


                Cipher cipher = CryptoUtils.getCipher(CryptoUtils.RSA);
                cipher.init(Cipher.DECRYPT_MODE, KeyUtils.getPublic(PATH + "/src/main/resources/keypair/publickey"));
                SecretKeySpec decryptedSecretKey = new SecretKeySpec(cipher.doFinal(encryptedSecretKey), KeyUtils.SECRET_KEY_ALGORITHM);
                log.info("DECRYPTED SecretKey");
                printToConsole(decryptedSecretKey.getEncoded());//logging to console

                Cipher cipher2 = Cipher.getInstance(CryptoUtils.AES_GCM_NO_PADDING);
                cipher2.init(Cipher.DECRYPT_MODE, decryptedSecretKey, KeyUtils.getGCMParameterSpec());
                decryptedFileBytes = cipher2.doFinal(encryptedFileBytes);
                log.info("DECRYPTED FileBytes");
                printToConsole(decryptedFileBytes);


            } catch (Exception e) {
                e.printStackTrace();
            }

        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

    }

    public static void runDummySecretKey() {
        try (FileOutputStream fileOutputStream =
                     new FileOutputStream(PATH + "/src/main/resources/secretKeys/DummySecretKey");
        ) {
            fileOutputStream.write(KeyUtils.generateSecretKey().getEncoded());

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void runAsymmetricCryptography() {
        byte[] encryptedBytes;
        try {
            File file = new File(PATH + "/src/main/resources/secretKeys/DummySecretKey");
            FileInputStream fileInputStream = new FileInputStream(file);
            byte[] fileBytes = fileInputStream.readAllBytes();
            fileInputStream.close();


            encryptedBytes = CryptoUtils.encrypt(fileBytes, KeyUtils.getPrivate(PATH + "/src/main/resources/keypair/privatekey"));

            try (FileOutputStream fileOutputStream =
                         new FileOutputStream(PATH + "/src/main/resources/encrypted-data/RSA-" + file.getName());
            ) {
                fileOutputStream.write(encryptedBytes);

            } catch (Exception e) {
                e.printStackTrace();
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
        // Decrypt part
        // cipher.init(Cipher.DECRYPT_MODE, publickey);
    }

    public static void runSymmetricCryptography() {

        File file = new File(PATH + "/src/main/resources/data/dummy.xml");

        SecretKey key;
        try {
            key = KeyUtils.generateSecretKey();

            FileInputStream fileInputStream = new FileInputStream(file);
            byte[] fileBytes = fileInputStream.readAllBytes();
            fileInputStream.close();

            byte[] encryptedBytes = CryptoUtils.encrypt(fileBytes, key, KeyUtils.getGCMParameterSpec());

            try (FileOutputStream fileOutputStream =
                         new FileOutputStream(PATH + "/src/main/resources/encrypted-data/cipherStream-5-" + file.getName());
                 CipherOutputStream cipherOutputStream = new CipherOutputStream(fileOutputStream, CryptoUtils.getCipher(key, KeyUtils.getGCMParameterSpec()))) {
                cipherOutputStream.write(encryptedBytes);

            } catch (Exception e) {
                e.printStackTrace();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }


    }

    // Generate session key
    private static final String SECRET_KEY = "my_super_secret_key";
    //SAlt the algorhitm
    private static final String SALT = "saaaaaaaaaaaaaaltyyy";


    public static String encryptText(String strToEncrypt) {
        try {
            byte[] iv = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};//
            IvParameterSpec ivspec = new IvParameterSpec(iv);

            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            KeySpec spec = new PBEKeySpec(SECRET_KEY.toCharArray(), SALT.getBytes(), 65536, 256);
            SecretKey tmp = factory.generateSecret(spec);
            SecretKeySpec secretKey = new SecretKeySpec(tmp.getEncoded(), "AES");

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivspec);

            return
                    cipher.doFinal(strToEncrypt.getBytes(StandardCharsets.UTF_8)).toString();

        } catch (Exception e) {
            System.out.println("Error while encrypting: " + e.toString());
        }
        return null;
    }

    public static File encryptFile(File fileToEncrypt) {


        try {

            FileInputStream fileInputStream = new FileInputStream(fileToEncrypt);
            byte[] fileBytes = fileInputStream.readAllBytes();
            fileInputStream.close();

            byte[] iv = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}; //16 bytes are required!

            /**
             * Initialization Vector
             *
             * Examples which use IVs are ciphers in feedback mode, e.g., DES in CBC mode and RSA ciphers with OAEP encoding operation.
             * IV length: must be 16 bytes long
             */
            IvParameterSpec ivSpec = new IvParameterSpec(iv);

            //AES Key
            /**
             * Symmetric key
             * Disposable 256 - session key
             * A session key is randomly generated to ensure the security
             */
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            KeySpec spec = new PBEKeySpec(SECRET_KEY.toCharArray(), SALT.getBytes(), 65536, 256);
            SecretKey tmp = factory.generateSecret(spec);
            SecretKeySpec secretKey = new SecretKeySpec(tmp.getEncoded(), "AES");

            /**
             * AES-CBC-PKCS#5  is algorithm that uses blocks of 128bits for encrypting, meaning each block is the same(128)
             *
             * AES/CBC/PKCS5Padding (128) is cipher algorithm for encrypting that uses padding by adding random phrases,
             * and changing the length of the original text, so making it harder for attacker to decipher
             */
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);

            byte[] encryptedBytes = cipher.doFinal(fileBytes);

            FileOutputStream fileOutputStream =
                    new FileOutputStream(PATH + "/src/main/resources/encrypted-data/" + fileToEncrypt.getName());
            fileOutputStream.write(encryptedBytes);
            fileOutputStream.close();

            return null;

        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public static String decryptFile(File fileToDecrypt) {

        String decryptedContent = null;

        try (FileInputStream fileInputStream = new FileInputStream(fileToDecrypt)) {

            byte[] fileBytes = fileInputStream.readAllBytes();
            fileInputStream.close();

            byte[] iv = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
            //Initialization Vector
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            //Key
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            KeySpec spec = new PBEKeySpec(SECRET_KEY.toCharArray(), SALT.getBytes(), 65536, 256);
            SecretKey tmp = factory.generateSecret(spec);
            SecretKeySpec secretKey = new SecretKeySpec(tmp.getEncoded(), "AES");

            //Cipher DECRYPT_MODE
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding"); //AES/CBC/PKCS5Padding
            cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec); //, ivSpec

            byte[] decryptedBytes = cipher.doFinal(fileBytes);

            FileOutputStream fileOutputStream =
                    new FileOutputStream(PATH + "/src/main/resources/decrypted-data/" + fileToDecrypt.getName());
            fileOutputStream.write(decryptedBytes);
            fileOutputStream.close();

            return null;

        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }


    public static File encryptFileCipherStream(File fileToEncrypt) {


        try {

            FileInputStream fileInputStream = new FileInputStream(fileToEncrypt);
            byte[] fileBytes = fileInputStream.readAllBytes();
            fileInputStream.close();

            byte[] iv = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
            //Initialization Vector
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            //Key
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            KeySpec spec = new PBEKeySpec(SECRET_KEY.toCharArray(), SALT.getBytes(), 65536, 256);
            SecretKey tmp = factory.generateSecret(spec);
            SecretKeySpec secretKey = new SecretKeySpec(tmp.getEncoded(), "AES");

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

            cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);

            byte[] encryptedBytes = cipher.doFinal(Base64.getEncoder().encode(fileBytes));

            try (FileOutputStream fileOutputStream =
                         new FileOutputStream(PATH + "/src/main/resources/encrypted-data/cipherStream-encrypted-" + fileToEncrypt.getName());
                 CipherOutputStream cipherOutputStream = new CipherOutputStream(fileOutputStream, cipher);) {
                fileOutputStream.write(encryptedBytes);

            } catch (Exception e) {
                e.printStackTrace();
            }
            return null;

        } catch (Exception e) {
            System.out.println("Error while encrypting: " + e.toString());
        }
        return null;
    }

    public static String decryptFileCipherStream(File fileToDecrypt) {

        String decryptedContent = null;

        try (FileInputStream fileInputStream = new FileInputStream(fileToDecrypt)
        ) {

//            byte[] fileBytes = fileInputStream.readAllBytes();
//            fileInputStream.close();

            byte[] iv = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

            //Initialization Vector
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            //Key
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            KeySpec spec = new PBEKeySpec(SECRET_KEY.toCharArray(), SALT.getBytes(), 65536, 256);
            SecretKey tmp = factory.generateSecret(spec);
            SecretKeySpec secretKey = new SecretKeySpec(tmp.getEncoded(), "AES");

            //Cipher DECRYPT_MODE
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding"); //AES/CBC/PKCS5Padding
            cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec); //, ivSpec

            try (CipherInputStream cipherInputStream = new CipherInputStream(fileInputStream, cipher);
                 InputStreamReader isr = new InputStreamReader(cipherInputStream);
                 BufferedReader bufferedReader = new BufferedReader(isr);
            ) {
                StringBuilder sb = new StringBuilder();
                String line;
                while ((line = bufferedReader.readLine()) != null) {
                    sb.append(line);
                }
                decryptedContent = sb.toString();
            } catch (Exception e) {
                e.printStackTrace();
            }
            byte[] decryptedBytes = decryptedContent.getBytes(StandardCharsets.UTF_8);//cipher.doFinal(fileBytes);

            FileOutputStream fileOutputStream =
                    new FileOutputStream(PATH + "/src/main/resources/decrypted-data/decryptedStream-" + fileToDecrypt.getName());
            fileOutputStream.write(decryptedBytes);
            fileOutputStream.close();

            return null;

        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

}
