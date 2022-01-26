package com.example.cipher;

import com.example.cipher.crypto.Ciphers;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;


@Slf4j
@SpringBootApplication
public class CipherApplication {

    public static void main(String[] args) {
        SpringApplication.run(CipherApplication.class, args);

        Ciphers.runDummySecretKey();

        Ciphers.runAsymmetricCryptography();

        Ciphers.runSymmetricCryptography();

        Ciphers.runTest();
    }


}
