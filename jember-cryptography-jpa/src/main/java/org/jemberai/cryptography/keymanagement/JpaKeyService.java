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
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.jemberai.cryptography.domain.DefaultEncryptionKey;
import org.jemberai.cryptography.domain.EncryptionKeys;
import org.jemberai.cryptography.repositories.DefaultEncryptionKeyRepository;
import org.jemberai.cryptography.repositories.EncryptionKeysRepository;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.transaction.annotation.Transactional;

import java.util.UUID;

/**
 * JPAAesKeyService - JPA implementation of the KeyService. This allows clients to add, get, and set default keys.
 * <p>
 * These keys are used to encrypt and decrypt client data. The keys are encrypted and stored in a database.
 * <p>
 * Created by jt, Spring Framework Guru.
 */
@Slf4j
@RequiredArgsConstructor
public class JpaKeyService implements KeyService {

    private final EncryptionKeysRepository aesKeyRepository;
    private final DefaultEncryptionKeyRepository defaultKeyRepository;

    /**
     * Add a key to the key store. The key is not active until it is set as the default key.
     *
     * @param clientId The client id to associate with the key.
     * @param key      The key to add.
     * @return The key that was added.
     */
    @Transactional
    @Override
    public AesKeyDTO addKey(@NonNull String clientId, @NonNull AesKeyDTO key) {

        if (!clientId.equals(key.getClientId())){
            throw new IllegalArgumentException("Client id does not match key client id");
        }

        aesKeyRepository.findByClientIdAndKeyId(clientId, key.getKeyId())
                .ifPresent(aesKey -> {
                    throw new IllegalArgumentException("Key already exists");
                });

        EncryptionKeys savedKey = aesKeyRepository.saveAndFlush(convert(key));

        log.debug("Key saved with id: {}", savedKey.getKeyId());

        return convert(savedKey);
    }

    /**
     * Set the default key for a client. The default key is used to encrypt and decrypt client data.
     * If the key is not found, it is added to the key store, and then set as the default key.
     * <p>
     * @param clientId The client id.
     * @param key      The key to set as the default.
     */
    @Transactional
    @CacheEvict(value = "defaultKey", key = "#clientId")
    @Override
    public void setDefaultKey(@NonNull String clientId, @NonNull AesKeyDTO key) {

        EncryptionKeys savedKey = aesKeyRepository.findByClientIdAndKeyId(clientId, key.getKeyId())
                .orElseGet(() -> aesKeyRepository.save(convert(key)));

        // delete the existing default key. Simplest way to handle this vs checking if it exists & updating.
        defaultKeyRepository.deleteByClientId(clientId);

        defaultKeyRepository.saveAndFlush(DefaultEncryptionKey.builder()
                .clientId(clientId)
                .defaultKey(savedKey)
                .build());
    }

    @Cacheable(value = "defaultKey", key = "#clientId", unless="#result == null")
    @Override
    public AesKeyDTO getDefaultKey(@NonNull String clientId) {
        AesKeyDTO dto =  defaultKeyRepository.findByClientId(clientId)
                .map(DefaultEncryptionKey::getDefaultKey)
                .map(this::convert)
                .orElse(null);

        if (dto == null) {
            log.warn("Default key not found for client id: {}", clientId);
        } else {
            log.info("Default key found for client id: {}", dto.getClientId());
        }

        return dto;
    }

    @Cacheable("getKeyById")
    @Override
    public AesKeyDTO getKey(@NonNull String clientId, @NonNull String keyId) {
        return aesKeyRepository.findByClientIdAndKeyId(clientId, UUID.fromString(keyId))
                .map(this::convert)
                .orElse(null);
    }

    @Override
    public AesKeyDTO getKey(@NonNull String clientId, @NonNull UUID keyId) {
        return aesKeyRepository.findByClientIdAndKeyId(clientId, keyId)
                .map(this::convert)
                .orElse(null);
    }

    public EncryptionKeys convert(AesKeyDTO aesKeyDTO) {
        return EncryptionKeys.builder()
                .clientId(aesKeyDTO.getClientId())
                .keyId(aesKeyDTO.getKeyId())
                .hmacKey(aesKeyDTO.getHmacKey())
                .aesKey(aesKeyDTO.getAesKey())
                .build();
    }

    public AesKeyDTO convert(EncryptionKeys aesKey) {
        return AesKeyDTO.builder()
                .clientId(aesKey.getClientId())
                .keyId(aesKey.getKeyId())
                .hmacKey(aesKey.getHmacKey())
                .aesKey(aesKey.getAesKey())
                .build();
    }
}
