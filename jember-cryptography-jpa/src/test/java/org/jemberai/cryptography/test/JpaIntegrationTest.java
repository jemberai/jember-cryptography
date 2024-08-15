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

package org.jemberai.cryptography.test;

import org.jemberai.cryptography.domain.DefaultEncryptionKey;
import org.jemberai.cryptography.domain.EncryptionKeys;
import org.jemberai.cryptography.keymanagement.AesKeyDTO;
import org.jemberai.cryptography.keymanagement.KeyService;
import org.jemberai.cryptography.keymanagement.KeyUtils;
import org.jemberai.cryptography.repositories.AesKeyRepository;
import org.jemberai.cryptography.repositories.DefaultKeyRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Created by jt, Spring Framework Guru.
 */
@SpringBootTest
class JpaIntegrationTest {

    @Autowired
    AesKeyRepository aesKeyRepository;

    @Autowired
    DefaultKeyRepository defaultKeyRepository;

    @Autowired
    KeyService keyService;

    @Test
    void testAddAndGetKey() {
        AesKeyDTO aesKeyDTO = KeyUtils.generateAesKeyDTO();

        EncryptionKeys aesKey = EncryptionKeys.builder()
                .clientId("test-client")
                .keyId(aesKeyDTO.getKeyId())
                .aesKey(aesKeyDTO.getAesKey())
                .hmacKey(aesKeyDTO.getHmacKey())
                .build();

        EncryptionKeys savedAesKey = aesKeyRepository.save(aesKey);

        assertNotNull(savedAesKey);
        assertNotNull(savedAesKey.getHmacKey());
        assertNotNull(savedAesKey.getEncryptedAesKeyValue().getKeyId());

        EncryptionKeys retrievedAesKey = aesKeyRepository.findById(savedAesKey.getId()).get();

        assertNotNull(retrievedAesKey);
        assertNotNull(retrievedAesKey.getHmacKey());
        assertNotNull(retrievedAesKey.getEncryptedAesKeyValue().getKeyId());
        assertNotNull(retrievedAesKey.getAesKey());
        assertArrayEquals(aesKeyDTO.getAesKey(), retrievedAesKey.getAesKey());
        assertArrayEquals(aesKeyDTO.getHmacKey(), retrievedAesKey.getHmacKey());
    }

    @Test
    void testJPAKeyService() {
        AesKeyDTO aesKeyDTO = KeyUtils.generateAesKeyDTO();

        EncryptionKeys aesKey = EncryptionKeys.builder()
                .clientId("test-client")
                .keyId(aesKeyDTO.getKeyId())
                .aesKey(aesKeyDTO.getAesKey())
                .hmacKey(aesKeyDTO.getHmacKey())
                .build();

        EncryptionKeys savedAesKey = aesKeyRepository.save(aesKey);

        assertThat(savedAesKey).isNotNull();
        assertThat(savedAesKey.getKeyId()).isEqualTo(aesKeyDTO.getKeyId());

        keyService.setDefaultKey("test-client", aesKeyDTO);

        List<DefaultEncryptionKey> aesKeys = defaultKeyRepository.findAll();
        assertThat(aesKeys).hasSizeGreaterThan(0);

        AesKeyDTO retrievedAesKey = keyService.getDefaultKey("test-client");

        assertEquals(aesKeyDTO.getKeyId(), retrievedAesKey.getKeyId());
    }
}
