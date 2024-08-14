package org.jemberai.cryptography.model;

import java.util.UUID;

/**
 * EncryptedValueDTO record
 * @param provider id of the encryption system
 * @param keyId id of the key used to encrypt this value
 * @param hmac base64 of the HMAC
 * @param encryptedValue base64 of the encrypted value
 * @param initializationVector base64 of the initialization vector of the encrypted value
 */
public record EncryptedValueDTO(String provider,
                                UUID keyId,
                                byte[] hmac,
                                byte[] encryptedValue,
                                byte[] initializationVector) {
}
