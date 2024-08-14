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

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.jemberai.cryptography.domain.AesKey;
import org.jemberai.cryptography.domain.DefaultKey;
import org.jemberai.cryptography.repositories.AesKeyRepository;
import org.jemberai.cryptography.repositories.DefaultKeyRepository;

import java.util.UUID;

/**
 * Created by jt, Spring Framework Guru.
 */
@Slf4j
@RequiredArgsConstructor
public class JpaKeyService implements KeyService {

    private final AesKeyRepository aesKeyRepository;
    private final DefaultKeyRepository defaultKeyRepository;

    @Override
    public AesKeyDTO addKey(String clientId, AesKeyDTO key) {

        aesKeyRepository.findByClientIdAndKeyId(clientId, key.getKeyId())
                .ifPresent(aesKey -> {
                    throw new IllegalArgumentException("Key already exists");
                });

        AesKey savedKey = aesKeyRepository.save(convert(key));

        log.debug("Key saved with id: {}", savedKey.getKeyId());

        return convert(savedKey);
    }

    @Override
    public void setDefaultKey(String clientId, AesKeyDTO key) {

        aesKeyRepository.findByClientIdAndKeyId(clientId, key.getKeyId())
                .ifPresentOrElse(aesKey -> {
                    defaultKeyRepository.findByClientId(clientId)
                            .ifPresentOrElse(defaultKey -> {
                                defaultKey.setDefaultKey(aesKey);
                                defaultKeyRepository.save(defaultKey);
                            }, () -> {
                                defaultKeyRepository.save(DefaultKey.builder()
                                        .clientId(clientId)
                                        .defaultKey(aesKey)
                                        .build());
                            });
                }, () -> {
                    AesKey savedKey = aesKeyRepository.save(convert(key));

                    defaultKeyRepository.findByClientId(clientId)
                            .ifPresentOrElse(defaultKey -> {
                                defaultKey.setDefaultKey(savedKey);
                                defaultKeyRepository.save(defaultKey);
                            }, () -> {
                                defaultKeyRepository.save(DefaultKey.builder()
                                        .clientId(clientId)
                                        .defaultKey(savedKey)
                                        .build());
                            });
                });
    }

    @Override
    public AesKeyDTO getDefaultKey(String clientId) {
        return defaultKeyRepository.findByClientId(clientId)
                .map(DefaultKey::getDefaultKey)
                .map(this::convert)
                .orElse(null);
    }

    @Override
    public AesKeyDTO getKey(String clientId, String keyId) {
        return aesKeyRepository.findByClientIdAndKeyId(clientId, UUID.fromString(keyId))
                .map(this::convert)
                .orElse(null);
    }

    @Override
    public AesKeyDTO getKey(String clientId, UUID keyId) {
        return aesKeyRepository.findByClientIdAndKeyId(clientId, keyId)
                .map(this::convert)
                .orElse(null);
    }

    public AesKey convert(AesKeyDTO aesKeyDTO) {
        return AesKey.builder()
                .clientId(aesKeyDTO.getClientId())
                .keyId(aesKeyDTO.getKeyId())
                .hmacKey(aesKeyDTO.getHmacKey())
                .aesKey(aesKeyDTO.getAesKey())
                .build();
    }

    public AesKeyDTO convert(AesKey aesKey) {
        return AesKeyDTO.builder()
                .clientId(aesKey.getClientId())
                .keyId(aesKey.getKeyId())
                .hmacKey(aesKey.getHmacKey())
                .aesKey(aesKey.getAesKey())
                .build();
    }
}
