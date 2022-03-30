package com.ControlSystem.util.compress;

import lombok.extern.slf4j.Slf4j;

import java.io.*;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;

@Slf4j
public class CompressUtil {

    public static byte[] zip(String outputFilename, byte[] output) {
        try (ByteArrayOutputStream baos = new ByteArrayOutputStream();
             ZipOutputStream outputStream = new ZipOutputStream(baos)) {
            outputStream.putNextEntry(new ZipEntry(outputFilename));
            outputStream.write(output, 0, output.length);
            outputStream.closeEntry();
            return baos.toByteArray();
        } catch (IOException e) {
            throw new RuntimeException("Zip failed!", e);
        }
    }

    public static byte[] unzip(byte[] input) {
        try (ByteArrayInputStream bais = new ByteArrayInputStream(input);
             ZipInputStream zipInputStream = new ZipInputStream(bais)) {
            zipInputStream.getNextEntry();
            return zipInputStream.readAllBytes();
        } catch (IOException e) {
            throw new RuntimeException("Unzip failed!", e);
        }
    }
}
