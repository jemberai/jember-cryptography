package org.jember.cryptography.provider;

import lombok.val;
import org.jember.cryptography.MarshallingUtil;
import org.jember.cryptography.keymanagement.InMemoryKeyService;
import org.jember.cryptography.keymanagement.KeyUtils;
import org.jember.cryptography.keymanagement.StaticTestKeyService;
import org.jember.cryptography.model.EncryptedValueDTO;
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

        @Test
        void getKeyProviderId() {

            assertEquals(encryptionProvider.getKeyProviderId(), "DefaultJemberEncryptionProviderV1");
        }

        @Test
        void encrypt() {
            val someval = "foo";

            val encrypted = encryptionProvider.encrypt(someval);

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

            val encrypted = encryptionProvider.encrypt(someval);

            val decrypted = encryptionProvider.decrypt(encrypted);

            assertEquals(someval, decrypted);
        }

        @Test
        void encryptDecryptNull() {
            String someval = null;

            val encrypted = encryptionProvider.encrypt(someval);

            val decrypted = encryptionProvider.decrypt(encrypted);

            assertNull(decrypted);
        }

        @Test
        void encryptDecryptNullString() {
            assertThrows(NullPointerException.class, () -> {
                encryptionProvider.decrypt(null);
            });
        }
    }

    @DisplayName("Tests Using InMemoryKeyService")
    @Nested
    class TestInMemoryKeyService  {
        InMemoryKeyService inMemoryKeyService;
        EncryptionProviderImpl encryptionProvider;

        @BeforeEach
        void setUp() {
            inMemoryKeyService = new InMemoryKeyService(KeyUtils.generateAesKeyDTO());
            encryptionProvider = new EncryptionProviderImpl(inMemoryKeyService);
        }

        @DisplayName("Test decrypting with one key")
        @Test
        void decrypt() {
            val someval = "foo";

            val encrypted = encryptionProvider.encrypt(someval);

            val decrypted = encryptionProvider.decrypt(encrypted);

            assertEquals(someval, decrypted);
        }

        @DisplayName("Test decrypting with multiple keys")
        @Test
        void decryptWithMultipleKeys() {
            val foo = "foo";
            val bar = "bar";

            val encryptedFoo = encryptionProvider.encrypt(foo);

            val decrypted = encryptionProvider.decrypt(encryptedFoo);

            assertEquals(foo, decrypted);

            //add new key
            inMemoryKeyService.setDefaultKey(KeyUtils.generateAesKeyDTO());

            //new key works
            val encryptedBar = encryptionProvider.encrypt(bar);
            assertEquals(bar, encryptionProvider.decrypt(encryptedBar));

            //decrypt with original key
            val decryptedFoo = encryptionProvider.decrypt(encryptedFoo);
            assertEquals(foo, decryptedFoo);
        }
    }
}