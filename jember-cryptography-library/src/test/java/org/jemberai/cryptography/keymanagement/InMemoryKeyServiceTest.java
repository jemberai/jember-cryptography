package org.jemberai.cryptography.keymanagement;

import lombok.val;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

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