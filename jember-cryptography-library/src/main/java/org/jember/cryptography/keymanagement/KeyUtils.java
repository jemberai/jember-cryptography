package org.jember.cryptography.keymanagement;

import lombok.SneakyThrows;

import java.security.NoSuchAlgorithmException;
import java.util.UUID;

/**
 * Utility to generate AES and HMAC key values.
 * <p>
 * Created by jt, Spring Framework Guru.
 */
public class KeyUtils {
    public static byte[] generateAESKey() throws NoSuchAlgorithmException {
        javax.crypto.KeyGenerator keyGen = javax.crypto.KeyGenerator.getInstance("AES");
        keyGen.init(256);
        return keyGen.generateKey().getEncoded();
    }

    @SneakyThrows
    public static AesKeyDTO generateAesKeyDTO()  {
        byte[] aesKey = generateAESKey();
        byte[] hmacKey = generateAESKey();
        return new AesKeyDTO(UUID.randomUUID(), aesKey, hmacKey);
    }
}
