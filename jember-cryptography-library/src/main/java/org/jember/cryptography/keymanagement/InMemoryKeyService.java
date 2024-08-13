package org.jember.cryptography.keymanagement;

import lombok.NonNull;

import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

/**
 * InMemoryKeyService is an implementation of KeyService that stores keys in memory. Allows for the
 * testing of multiple keys without the need for a persistent key store.
 * <p>
 * This is mainly intended for testing purposes where a persistent key store is not needed.
 * <p>
 * Created by jt, Spring Framework Guru.
 */
public class InMemoryKeyService implements KeyService {

    private final Map<UUID, AesKeyDTO> keys = new HashMap<>();
    private AesKeyDTO defaultKey;

    /**
     * Create an InMemoryKeyService with a default key.
     *
     * @param defaultKey The default key to use.
     */
    public InMemoryKeyService(@NonNull AesKeyDTO defaultKey) {
        this.setDefaultKey(defaultKey);
    }

    @Override
    public void setDefaultKey(@NonNull AesKeyDTO key) {
        this.defaultKey = key;
        keys.put(defaultKey.getKeyId(), defaultKey);
    }

    @Override
    public AesKeyDTO getDefaultKey() {
        return defaultKey;
    }

    @Override
    public AesKeyDTO getKey(String keyId) {
        return getKey(UUID.fromString(keyId));
    }

    @Override
    public AesKeyDTO getKey(UUID keyId) {
        return keys.get(keyId);
    }
}
