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

package org.jemberai.cryptography.domain;

import lombok.val;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.LocalDateTime;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;

class EncryptionKeysTest {

    public static final String TEST = "test";
    public static final UUID KEY_ID = UUID.randomUUID();
    public static final LocalDateTime NOW = LocalDateTime.now();

    EncryptionKeys encryptionKeys = getEncryptionKeys();

    @BeforeEach
    void setUp() {
    }

    @Test
    void testEquals() {
        assertEquals(encryptionKeys, getEncryptionKeys());
    }

    @Test
    void testNotEquals() {
        val testKey = getEncryptionKeys();
        testKey.setId(UUID.randomUUID());

        assertThat(encryptionKeys).isNotEqualTo(testKey);
    }

    @Test
    void testNotEqualsDiffObj() {
        assertThat(encryptionKeys).isNotEqualTo(new Object());
    }

    @Test
    void testHashCode() {
        assertThat(encryptionKeys.hashCode()).isEqualTo(getEncryptionKeys().hashCode());
    }


    EncryptionKeys getEncryptionKeys() {
        return EncryptionKeys.builder()
                .id(KEY_ID)
                .version(1)
                .keyId(KEY_ID)
                .hmacKey(TEST.getBytes())
                .aesKey(TEST.getBytes())
                .clientId(TEST)
                .createdDate(NOW)
                .updateDate(NOW)
                .encryptedAesKeyValue(EncryptedValueWrapper.builder()
                        .encryptedValue(TEST.getBytes())
                        .initializationVector(TEST.getBytes())
                        .provider(TEST)
                        .hmac(TEST.getBytes())
                        .keyId(KEY_ID)
                        .build())
                .encryptedHmacKeyValue(EncryptedValueWrapper.builder()
                        .encryptedValue(TEST.getBytes())
                        .initializationVector(TEST.getBytes())
                        .provider(TEST)
                        .hmac(TEST.getBytes())
                        .keyId(KEY_ID)
                        .build())
                .build();
    }
}