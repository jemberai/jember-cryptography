package org.jember.cryptography;

import lombok.val;
import org.jember.cryptography.keymanagement.KeyService;
import org.jember.cryptography.keymanagement.StaticTestKeyService;
import org.jember.cryptography.provider.EncryptionProvider;
import org.jember.cryptography.provider.EncryptionProviderImpl;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class MarshallingUtilTest {

    EncryptionProvider encryptionProvider;
    KeyService keyService;
    @BeforeEach
    void setUp() {
        keyService = new StaticTestKeyService();
        encryptionProvider = new EncryptionProviderImpl(keyService);
    }

    @Test
    void unmarshalAndUnmarshal() {
        String value = "test";
        val encryptedValue = encryptionProvider.encrypt(value);
        val marshalled = MarshallingUtil.unmarshal(encryptedValue);

        assertEquals(keyService.getDefaultKey().getKeyId(), marshalled.keyId());
        System.out.println(marshalled);
    }

}