package org.jember.cryptography.provider;

import lombok.val;
import org.jember.cryptography.MarshallingUtil;
import org.jember.cryptography.keymanagement.KeyServiceStaticKeyImpl;
import org.jember.cryptography.model.EncryptedValueDTO;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class EncryptionProviderImplTest {

    EncryptionProviderImpl encryptionProvider = new EncryptionProviderImpl(new KeyServiceStaticKeyImpl());

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