package org.jemberai.cryptography.provider;

import lombok.val;
import org.jemberai.cryptography.MarshallingUtil;
import org.jemberai.cryptography.keymanagement.InMemoryKeyService;
import org.jemberai.cryptography.keymanagement.KeyUtils;
import org.jemberai.cryptography.keymanagement.StaticTestKeyService;
import org.jemberai.cryptography.model.EncryptedValueDTO;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class EncryptionProviderImplTest {

    @DisplayName("Tests Using StaticTestKeyService")
    @Nested
    class StaticTestKeyServiceTests {
        EncryptionProviderImpl encryptionProvider = new EncryptionProviderImpl(new StaticTestKeyService());
        String clientId = "test-client-id";

        @Test
        void getKeyProviderId() {
            assertEquals(encryptionProvider.getKeyProviderId(), "DefaultJemberEncryptionProviderV1");
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
    }
}