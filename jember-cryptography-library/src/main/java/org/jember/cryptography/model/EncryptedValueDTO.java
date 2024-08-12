package org.jember.cryptography.model;

/**
 * EncryptedValueDTO record
 * @param provider id of the encryption system
 * @param keyId id of the key used to encrypt this value
 * @param hmac base64 of the HMAC
 * @param encryptedValue base64 of the encrypted value
 * @param initializationVector base64 of the initialization vector of the encrypted value
 */
public record EncryptedValueDTO(String provider,
                                String keyId,
                                String hmac,
                                String encryptedValue,
                                String initializationVector) {
}
