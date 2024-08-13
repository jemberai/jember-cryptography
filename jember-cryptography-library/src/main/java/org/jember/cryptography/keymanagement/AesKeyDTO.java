package org.jember.cryptography.keymanagement;

import lombok.Data;
import lombok.NonNull;

import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;
import java.util.UUID;

/**
 * Created by jt, Spring Framework Guru.
 */
@Data
public class AesKeyDTO {

    private UUID keyId;
    private byte[] aesKey;
    private byte[] hmacKey;

    /**
     * Create an AesKeyDTO from a key id and byte arrays.
     * @param keyId The key id.
     * @param aesKey The AES key.
     * @param hmacKey The HMAC key.
     */
    public AesKeyDTO(@NonNull UUID keyId, byte[] aesKey, byte[] hmacKey) {
        this.keyId = keyId;
        this.aesKey = aesKey;
        this.hmacKey = hmacKey;
    }

    /**
     * Create an AesKeyDTO from a base64 encoded key.
     * @param keyId The key id.
     * @param aesKey The base64 encoded AES key.
     * @param hmacKey The base64 encoded HMAC key.
     */
    public AesKeyDTO(@NonNull String keyId, @NonNull String aesKey, @NonNull String hmacKey) {
        this.keyId = UUID.fromString(keyId);
        this.aesKey = Base64.getDecoder().decode(aesKey);
        this.hmacKey = Base64.getDecoder().decode(hmacKey);
    }

    /**
     * Validate the AES key.
     * @return boolean
     */
    public boolean isAesKeyValid() {
        return aesKey != null && aesKey.length != 16 && aesKey.length != 24 && aesKey.length != 32 ;
    }

    public String base64EncodedAesKey() {
        return new String(Base64.getEncoder().encode(aesKey));
    }

    public String base64EncodedHmacKey() {
        return new String(Base64.getEncoder().encode(hmacKey));
    }

    public SecretKeySpec getAesKey() {
        return new SecretKeySpec(aesKey, "AES");
    }

    public SecretKeySpec getHmacKey() {
        return new SecretKeySpec(hmacKey, "HmacSHA256");
    }
}
