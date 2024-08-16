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

package org.jemberai.cryptography.provider;

import lombok.val;
import org.jemberai.cryptography.MarshallingUtil;
import org.jemberai.cryptography.keymanagement.AesKeyDTO;
import org.jemberai.cryptography.keymanagement.InMemoryKeyService;
import org.jemberai.cryptography.keymanagement.KeyUtils;
import org.jemberai.cryptography.keymanagement.StaticTestKeyService;
import org.jemberai.cryptography.model.EncryptedValueDTO;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.*;

class EncryptionProviderImplTest {

    @DisplayName("Tests Using StaticTestKeyService")
    @Nested
    class StaticTestKeyServiceTests {
        EncryptionProviderImpl encryptionProvider = new EncryptionProviderImpl(new StaticTestKeyService());
        String clientId = "test-client-id";

        @Test
        void getKeyProviderId() {
            assertThat(encryptionProvider.getKeyProviderId()).isEqualTo("DefaultJemberEncryptionProviderV1");
        }

        @Test
        void encrypt() {
            val someval = "foo";

            val encrypted = encryptionProvider.encrypt(clientId, someval);

            assertNotNull(encrypted);

            EncryptedValueDTO dto = MarshallingUtil.unmarshal(encrypted);

            assertEquals(dto.provider(), encryptionProvider.getKeyProviderId());
            assertNotNull(dto.initializationVector());
            assertNotNull(dto.encryptedValue());
            assertNotNull(dto.hmac());
            assertNotNull(dto.keyId());
        }

        @Test
        void decrypt() {
            val someval = "foo";

            val encrypted = encryptionProvider.encrypt(clientId, someval);

            val decrypted = encryptionProvider.decryptToString(clientId, encrypted);

            assertEquals(someval, decrypted);
        }

        @Test
        void encryptDecryptNull() {
            String someval = null;

            val encrypted = encryptionProvider.encrypt(clientId, someval);

            val decrypted = encryptionProvider.decryptToString(clientId, encrypted);

            assertNull(decrypted);
        }


    }

    @DisplayName("Tests Using InMemoryKeyService")
    @Nested
    class TestInMemoryKeyService  {
        InMemoryKeyService inMemoryKeyService;
        EncryptionProviderImpl encryptionProvider;
        String clientId = "test-client-id";

        @BeforeEach
        void setUp() {
            inMemoryKeyService = new InMemoryKeyService(KeyUtils.generateAesKeyDTO());
            encryptionProvider = new EncryptionProviderImpl(inMemoryKeyService);
        }

        @DisplayName("Test decrypting with one key")
        @Test
        void decrypt() {
            val someval = "foo";

            val encrypted = encryptionProvider.encrypt(clientId, someval);

            val decrypted = encryptionProvider.decryptToString(clientId, encrypted);

            assertEquals(someval, decrypted);
        }

        @DisplayName("Test decrypting altered payload")
        @Test
        void decryptAlteredPayload() {
            val someval = "foo";

            val encrypted = encryptionProvider.encrypt(clientId, someval);

            EncryptedValueDTO dto = MarshallingUtil.unmarshal(encrypted);

            EncryptedValueDTO altered = new EncryptedValueDTO(dto.provider(),
                    dto.keyId(),
                    dto.initializationVector(),
                    "foo bar stuff".getBytes(),
                    dto.hmac());

            String alteredString = MarshallingUtil.marshal(altered);

            assertThrows(EncryptionException.class, () -> encryptionProvider.decryptToString(clientId, alteredString));
        }

        @DisplayName("Test decrypting with multiple keys")
        @Test
        void decryptWithMultipleKeys() {
            val foo = "foo";
            val bar = "bar";

            val encryptedFoo = encryptionProvider.encrypt(clientId, foo);

            val decrypted = encryptionProvider.decryptToString(clientId, encryptedFoo);

            assertEquals(foo, decrypted);

            //add new key
            inMemoryKeyService.setDefaultKey("test-client-id", KeyUtils.generateAesKeyDTO());

            //new key works
            val encryptedBar = encryptionProvider.encrypt(clientId, bar);
            assertEquals(bar, encryptionProvider.decryptToString(clientId, encryptedBar));

            //decrypt with original key
            val decryptedFoo = encryptionProvider.decryptToString(clientId, encryptedFoo);
            assertEquals(foo, decryptedFoo);
        }

        @Test
        void testDtoEquals() {
            val someval = "foo";

            val encrypted = encryptionProvider.encrypt(clientId, someval);

            EncryptedValueDTO dto = MarshallingUtil.unmarshal(encrypted);

            EncryptedValueDTO dto2 = new EncryptedValueDTO(dto.provider(),
                    dto.keyId(),
                    dto.hmac(),
                    dto.encryptedValue(),
                    dto.initializationVector());

            assertEquals(dto, dto2);
            assertThat(dto).hasSameHashCodeAs(dto2);
        }

        @Test
        void testNullAesCreateDtoNulls() {
            assertThrows(NullPointerException.class, () -> AesKeyDTO.builder().build());
        }

        @Test
        void testNullAesCreateDtoNullKeyId() {
            assertThrows(NullPointerException.class, () -> AesKeyDTO.builder().clientId("foo").build());
        }

        @DisplayName("Test decrypting with null value")
        @Test
        void decryptNull() {
            String someval = null;

            val encrypted = encryptionProvider.encrypt(clientId, someval);

            val decrypted = encryptionProvider.decryptToString(clientId, encrypted);

            assertNull(decrypted);
        }

        @DisplayName("Test decrypting invalid client")
        @Test
        void decryptBadClient() {
            assertThrows(EncryptionException.class, () -> encryptionProvider.decryptToString("bad-client-id", "encrypted-value"));
        }
    }
}