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

package org.jemberai.cryptography;

import lombok.val;
import org.jemberai.cryptography.keymanagement.KeyService;
import org.jemberai.cryptography.keymanagement.StaticTestKeyService;
import org.jemberai.cryptography.provider.EncryptionException;
import org.jemberai.cryptography.provider.EncryptionProvider;
import org.jemberai.cryptography.provider.EncryptionProviderImpl;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class MarshallingUtilTest {

    EncryptionProvider encryptionProvider;
    KeyService keyService;
    String clientId = "test-client-id";

    @BeforeEach
    void setUp() {
        keyService = new StaticTestKeyService();
        encryptionProvider = new EncryptionProviderImpl(keyService);
    }

    @Test
    void unmarshalAndUnmarshal() {
        String value = "test";
        val encryptedValue = encryptionProvider.encrypt(clientId, value);
        val marshalled = MarshallingUtil.unmarshal(encryptedValue);

        assertEquals(keyService.getDefaultKey(clientId).getKeyId(), marshalled.keyId());
        System.out.println(marshalled);
    }

    @Test
    void testNullsMarshal() {
        assertThrows(EncryptionException.class, () -> MarshallingUtil.marshal(null));
    }

    @Test
    void invalidJson() {
        assertThrows(EncryptionException.class, () -> MarshallingUtil.unmarshal("invalid json"));
    }

    @Test
    void nullJson() {
        assertNull(MarshallingUtil.unmarshal(null));
    }
}