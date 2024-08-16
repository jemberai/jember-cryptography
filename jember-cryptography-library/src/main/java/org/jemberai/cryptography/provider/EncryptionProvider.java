package org.jemberai.cryptography.provider;

import org.jemberai.cryptography.model.EncryptedValueDTO;

/**
 * Created by jt, Spring Framework Guru.
 */
public interface EncryptionProvider {
    String getKeyProviderId();

    /**
     * Encrypt a value
     *
     * @param value
     * @return an encrypted representation of the value
     * @throws EncryptionException
     */
    String encrypt(String clientId, String value) throws EncryptionException;

    EncryptedValueDTO encrypt(String clientId, byte[] value) throws EncryptionException;
    /**
     * Decrypt a value
     *
     * @param encryptedValue - the encrypted representation of the value
     * @return the decrypted value
     * @throws EncryptionException
     */
    byte[] decrypt(String clientId, String encryptedValue) throws EncryptionException;

    byte[] decrypt(String clientId, EncryptedValueDTO encryptedValueDTO) throws EncryptionException;

    String decryptToString(String clientId, String encryptedValue) throws EncryptionException;
}
