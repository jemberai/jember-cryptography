package org.jemberai.cryptography.util;

import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.UUID;

/**
 * Created by jt, Spring Framework Guru.
 */
public class KeyGenerator {

    /**
     * Utility to generate AES and HMAC keys.
     *
     * @param args
     * @throws NoSuchAlgorithmException
     */
    public static void main(String[] args) throws NoSuchAlgorithmException {
        System.out.println("Generating AES and HMAC keys.");
        javax.crypto.KeyGenerator keyGen = javax.crypto.KeyGenerator.getInstance("AES");
        keyGen.init(256);

        var aes = Base64.getEncoder().encodeToString(generateAESKey());
        var hmac = Base64.getEncoder().encodeToString(generateAESKey());
        var keyId = UUID.randomUUID().toString();

        System.out.println("aes: " + aes);
        System.out.println("hmac: " + hmac);
        System.out.println("keyId: " + keyId);
    }

    public static byte[] generateAESKey() throws NoSuchAlgorithmException {
        javax.crypto.KeyGenerator keyGen = javax.crypto.KeyGenerator.getInstance("AES");
        keyGen.init(256);
        return keyGen.generateKey().getEncoded();
    }
}
