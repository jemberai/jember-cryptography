/*
 *
 *  * Copyright 2023 - 2024 the original author or authors.
 *  *
 *  * Licensed under the Apache License, Version 2.0 (the "License");
 *  * you may not use this file except in compliance with the License.
 *  * You may obtain a copy of the License at
 *  *
 *  * https://www.apache.org/licenses/LICENSE-2.0
 *  *
 *  * Unless required by applicable law or agreed to in writing, software
 *  * distributed under the License is distributed on an "AS IS" BASIS,
 *  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  * See the License for the specific language governing permissions and
 *  * limitations under the License.
 *
 */

package org.jemberai.cryptography.keymanagement;

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

    private final Map<String, Map<UUID, AesKeyDTO>> keys = new HashMap<>();
    private Map<String, AesKeyDTO> defaultKey = new HashMap<>();

    /**
     * Create an InMemoryKeyService with a default key.
     *
     * @param defaultKey The default key to use.
     */
    public InMemoryKeyService(@NonNull AesKeyDTO defaultKey) {
        this.setDefaultKey(defaultKey.getClientId(), defaultKey);
    }

    @Override
    public AesKeyDTO addKey(String clientId, AesKeyDTO key) {
        Map<UUID, AesKeyDTO> clientKeys = keys.getOrDefault(clientId, new HashMap<>());
        clientKeys.put(key.getKeyId(), key);
        keys.put(clientId, clientKeys);
        return key;
    }

    @Override
    public void setDefaultKey(@NonNull String clientId, @NonNull AesKeyDTO key) {
        this.defaultKey.put(clientId, key);
        addKey(clientId, key);
    }

    @Override
    public AesKeyDTO getDefaultKey(String clientId) {
        return defaultKey.get(clientId);
    }

    @Override
    public AesKeyDTO getKey(String clientId, String keyId) {
        return getKey(clientId, UUID.fromString(keyId));
    }

    @Override
    public AesKeyDTO getKey(String clientId, UUID keyId) {
        return keys.get(clientId).get(keyId);
    }
}
