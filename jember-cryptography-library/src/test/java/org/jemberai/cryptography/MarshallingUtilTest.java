package org.jemberai.cryptography;

import lombok.val;
import org.jemberai.cryptography.keymanagement.KeyService;
import org.jemberai.cryptography.keymanagement.StaticTestKeyService;
import org.jemberai.cryptography.provider.EncryptionProvider;
import org.jemberai.cryptography.provider.EncryptionProviderImpl;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

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

}