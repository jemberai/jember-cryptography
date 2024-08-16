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

import org.jemberai.cryptography.repositories.EncryptionKeysRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

@SpringBootTest
class JpaKeyServiceTest {

    @Autowired
    KeyService keyService;

    @Autowired
    EncryptionKeysRepository encryptionKeysRepository;

    @Test
    void addKey() {
        AesKeyDTO aesKeyDTO = KeyUtils.generateAesKeyDTO();

        AesKeyDTO savedDto = keyService.addKey("test-client-id", aesKeyDTO);

        assertThat(savedDto).isNotNull();
        assertThat(aesKeyDTO.getKeyId()).isEqualTo(savedDto.getKeyId());
    }

    @Test
    void testNullsOnAddKey() {
        assertThrows(NullPointerException.class, () -> keyService.addKey(null, null));
    }

    @Test
    void testNullKeyOnAddKey() {
        assertThrows(NullPointerException.class, () -> keyService.addKey("asdf", null));
    }

    @Test
    void testNullClientOnAddKey() {
        assertThrows(NullPointerException.class, () -> keyService.addKey(null, KeyUtils.generateAesKeyDTO()));
    }

    @Test
    void setDefaultKey() {
        AesKeyDTO aesKeyDTO = KeyUtils.generateAesKeyDTO();

        keyService.setDefaultKey("test-client-id", aesKeyDTO);

        AesKeyDTO defaultKey = keyService.getDefaultKey("test-client-id");

        assertThat(defaultKey).isNotNull();
        assertThat(aesKeyDTO.getKeyId()).isEqualTo(defaultKey.getKeyId());
    }

    @Test
    void testGetDefaultKeyNullClient() {
        assertThrows(NullPointerException.class, () -> keyService.getDefaultKey(null));
    }

    @Test
    void testSetDefaultNulls() {
        assertThrows(NullPointerException.class, () -> keyService.setDefaultKey(null, null));
    }

    @Test
    void testSetDefaultNullClientId() {
        assertThrows(NullPointerException.class, () -> keyService.setDefaultKey(null, KeyUtils.generateAesKeyDTO()));
    }

    @Test
    void testSetDefaultNullKey() {
        assertThrows(NullPointerException.class, () -> keyService.setDefaultKey("asdf", null));
    }

    @Test
    void getKey() {
        AesKeyDTO aesKeyDTO = KeyUtils.generateAesKeyDTO();

        AesKeyDTO savedDto = keyService.addKey("test-client-id", aesKeyDTO);

        AesKeyDTO foundKey = keyService.getKey("test-client-id", savedDto.getKeyId());

        assertThat(foundKey).isNotNull();
        assertThat(savedDto.getKeyId()).isEqualTo(foundKey.getKeyId());
    }

    @Test
    void testAddBadClientId() {
        AesKeyDTO aesKeyDTO = KeyUtils.generateAesKeyDTO();

        assertThrows(IllegalArgumentException.class, () -> keyService.addKey("does not match dto", aesKeyDTO));

    }

    @Test
    void testGetKey() {
        AesKeyDTO aesKeyDTO = KeyUtils.generateAesKeyDTO();

        AesKeyDTO savedDto = keyService.addKey("test-client-id", aesKeyDTO);

        AesKeyDTO foundKey = keyService.getKey("test-client-id", savedDto.getKeyId().toString());

        assertThat(foundKey).isNotNull();
        assertThat(savedDto.getKeyId()).isEqualTo(foundKey.getKeyId());
    }

    @Test
    void testGetKeyNulls() {
        assertThrows(NullPointerException.class, () -> keyService.getKey(null, "null"));
    }
}