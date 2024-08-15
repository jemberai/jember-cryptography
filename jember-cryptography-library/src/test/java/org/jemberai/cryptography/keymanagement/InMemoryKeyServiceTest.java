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

import lombok.val;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class InMemoryKeyServiceTest {

    InMemoryKeyService inMemoryKeyService;
    AesKeyDTO defaultKey;
    String clientId = "test-client-id";

    @BeforeEach
    void setUp()  {
        defaultKey = KeyUtils.generateAesKeyDTO();
        inMemoryKeyService = new InMemoryKeyService(defaultKey);
    }

    @DisplayName("Test setting default key")
    @Test
    void setDefaultKey() {
        val newKey = KeyUtils.generateAesKeyDTO();
        inMemoryKeyService.setDefaultKey(clientId, newKey);

        assertEquals(newKey, inMemoryKeyService.getDefaultKey(clientId));

        val previousKey = inMemoryKeyService.getKey(clientId, defaultKey.getKeyId());

        assertEquals(defaultKey, previousKey);
    }

    @DisplayName("Test getting default key")
    @Test
    void getDefaultKey() {
        assertEquals(defaultKey, inMemoryKeyService.getDefaultKey(clientId));
    }

    @DisplayName("Test getting key by UUID")
    @Test
    void getKey() {
        assertEquals(defaultKey, inMemoryKeyService.getKey(clientId, defaultKey.getKeyId()));
    }

    @DisplayName("Test getting key by String")
    @Test
    void testGetKey() {
        assertEquals(defaultKey, inMemoryKeyService.getKey(clientId, defaultKey.getKeyId().toString()));
    }
}