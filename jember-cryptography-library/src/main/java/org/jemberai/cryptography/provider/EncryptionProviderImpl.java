package org.jemberai.cryptography.provider;

import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;
import lombok.val;
import org.apache.commons.lang3.ArrayUtils;
import org.jemberai.cryptography.MarshallingUtil;
import org.jemberai.cryptography.keymanagement.AesKeyDTO;
import org.jemberai.cryptography.keymanagement.KeyService;
import org.jemberai.cryptography.model.EncryptedValueDTO;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Objects;
import java.util.Random;
import java.util.UUID;

/**
 * Created by jt, Spring Framework Guru.
 */
@Slf4j

public class EncryptionProviderImpl implements EncryptionProvider {

    public static final String ENC_ALGORITHM = "AES/CBC/PKCS5Padding";

    private static final String ID = "DefaultJemberEncryptionProviderV1";
    private static final String NULL_VALUE = "Property Provided is Null";
    private static final Random random = new SecureRandom();

    private final KeyService keyService;

    public EncryptionProviderImpl(@NonNull KeyService keyService) {
        this.keyService = keyService;
    }

    @Override
    public String getKeyProviderId() {
        return ID;
    }

    @Override
    public String encrypt(String clientId, String value) throws EncryptionException {
        if (value == null) { //we can't encrypt null, so pass a string value of 'null' instead
            //decrypt will return null if the value is equal to NULL_VALUE
            value = NULL_VALUE;
            log.warn("Attempting to encrypt a null value.  Encrypting a string value of 'null' instead");
        }

        val encryptedValueDTO = encrypt(clientId, value.getBytes(StandardCharsets.UTF_8));

        return MarshallingUtil.marshal(encryptedValueDTO);
    }

    @Override
    public EncryptedValueDTO encrypt(String clientId, byte[] value) throws EncryptionException {
        try {
            Cipher cipher = Cipher.getInstance(ENC_ALGORITHM);  //Ciphers are not thread-safe
            IvParameterSpec ivSpec = randomIV();
            cipher.init(Cipher.ENCRYPT_MODE, keyService.getDefaultKey(clientId).getAesKeySpec(), ivSpec);

            byte[] ciphertext = cipher.doFinal(value);

            AesKeyDTO key = keyService.getDefaultKey(clientId);

            return new EncryptedValueDTO(ID, key.getKeyId(),
                    hmacHash(key.getClientId(), key.getKeyId(),  ciphertext, ivSpec.getIV()), ciphertext, ivSpec.getIV());

        } catch (RuntimeException | NoSuchAlgorithmException | InvalidKeyException |
                 NoSuchPaddingException | InvalidAlgorithmParameterException |
                 BadPaddingException | IllegalBlockSizeException e) {
            throw new EncryptionException("Error performing encryption", e);
        }
    }

    /**
     * Generate a random Initialization Vector (IV)
     * @return IvParameterSpec
     */
    private static IvParameterSpec randomIV() {
        byte[] iv = new byte[16];
        random.nextBytes(iv);
        return new IvParameterSpec(iv);
    }

    private byte[] hmacHash(String clientId, UUID keyId, byte[] encryptedValue, byte[] initialisationVector) throws EncryptionException {
        try {
            Mac sha256_HMAC = Mac.getInstance("HmacSHA256");
            sha256_HMAC.init(keyService.getKey(clientId, keyId).getHmacKeySpec());

            byte[] data = ArrayUtils.addAll(encryptedValue, initialisationVector);
            return sha256_HMAC.doFinal(data);
        }
        catch (RuntimeException | NoSuchAlgorithmException | InvalidKeyException e) {
            throw new EncryptionException("Error performing HMAC", e);
        }
    }

    @Override
    public byte[] decrypt(@NonNull String clientId, @NonNull String encryptedValue) throws EncryptionException {
        EncryptedValueDTO encryptedValueDTO = MarshallingUtil.unmarshal(encryptedValue);
        return decrypt(clientId, encryptedValueDTO);
    }

    @Override
    public byte[] decrypt(@NonNull String clientId, EncryptedValueDTO encryptedValueDTO) throws EncryptionException {
        try {
            //get key used to decrypt the value
            AesKeyDTO decryptKeyDto = keyService.getKey(clientId, encryptedValueDTO.keyId());

            //verify the HMAC - only proceed to decrypt if the hash of the encrypted value + IV matches the stored hash
            byte[] encBytes = Objects.requireNonNull(encryptedValueDTO).encryptedValue(); //Base64.getDecoder().decode(Objects.requireNonNull(encryptedValueDTO).encryptedValue());
            byte[] encIv = Objects.requireNonNull(encryptedValueDTO.initializationVector());//Base64.getDecoder().decode(encryptedValueDTO.initializationVector());
            byte[] hashBytes = hmacHash(clientId, decryptKeyDto.getKeyId(), encBytes, encIv);

            if (!Arrays.equals(hashBytes, encryptedValueDTO.hmac())) {
                throw new EncryptionException("HMAC of encrypted value/IV does not match computed HMAC.  This may be due to the wrong encryption.VeloEncryptionProviderV1.key.<key-uuid>.hmac");
            }

            /* Decrypt the message, given derived key and initialization vector. */
            Cipher cipher = Cipher.getInstance(ENC_ALGORITHM);  //Ciphers are not thread-safe
            IvParameterSpec ivSpec = new IvParameterSpec(encIv);

            cipher.init(Cipher.DECRYPT_MODE, decryptKeyDto.getAesKeySpec(), ivSpec);

            return cipher.doFinal(encBytes);
        }
        catch (RuntimeException | NoSuchAlgorithmException | InvalidKeyException | NoSuchPaddingException |
               BadPaddingException | IllegalBlockSizeException | InvalidAlgorithmParameterException e) {
            throw new EncryptionException("Error performing decryption", e);
        }
    }

    @Override
    public String decryptToString(@NonNull String clientId, @NonNull String encryptedValue) throws EncryptionException {

        byte[] encBytes = decrypt(clientId, encryptedValue);

        String plaintext = new String(encBytes, StandardCharsets.UTF_8);

        if (NULL_VALUE.equals(plaintext)) {
            plaintext = null;   //'decode' the null
        }

        return plaintext;
    }
}
