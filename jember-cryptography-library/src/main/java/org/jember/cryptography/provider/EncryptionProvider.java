package org.jember.cryptography.provider;

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
    String encrypt(String value) throws EncryptionException;

    /**
     * Decrypt a value
     *
     * @param encryptedValue - the encrypted representation of the value
     * @return the decrypted value
     * @throws EncryptionException
     */
    byte[] decrypt(String encryptedValue) throws EncryptionException;

    String decryptToString(String encryptedValue) throws EncryptionException;
}
