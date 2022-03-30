package com.ControlSystem.util.hash;

import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.lang3.ArrayUtils;

public class HashUtil {

    public static String getSHA256(byte[] data) {
        if (ArrayUtils.isEmpty(data)) {
            throw new RuntimeException("Could not calculate SHA256 from an empty data");
        }
        return DigestUtils.sha256Hex(data);
    }
}
