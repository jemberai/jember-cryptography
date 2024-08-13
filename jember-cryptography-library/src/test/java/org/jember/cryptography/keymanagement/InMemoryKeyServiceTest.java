package org.jember.cryptography.keymanagement;

import lombok.val;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.security.NoSuchAlgorithmException;

import static org.junit.jupiter.api.Assertions.*;

class InMemoryKeyServiceTest {

    InMemoryKeyService inMemoryKeyService;
    AesKeyDTO defaultKey;

    @BeforeEach
    void setUp()  {
        defaultKey = KeyUtils.generateAesKeyDTO();
        inMemoryKeyService = new InMemoryKeyService(defaultKey);
    }

    @DisplayName("Test setting default key")
    @Test
    void setDefaultKey() {
        val newKey = KeyUtils.generateAesKeyDTO();
        inMemoryKeyService.setDefaultKey(newKey);

        assertEquals(newKey, inMemoryKeyService.getDefaultKey());

        val previousKey = inMemoryKeyService.getKey(defaultKey.getKeyId());

        assertEquals(defaultKey, previousKey);
    }

    @DisplayName("Test getting default key")
    @Test
    void getDefaultKey() {
        assertEquals(defaultKey, inMemoryKeyService.getDefaultKey());
    }

    @DisplayName("Test getting key by UUID")
    @Test
    void getKey() {
        assertEquals(defaultKey, inMemoryKeyService.getKey(defaultKey.getKeyId()));


    }

    @DisplayName("Test getting key by String")
    @Test
    void testGetKey() {
        assertEquals(defaultKey, inMemoryKeyService.getKey(defaultKey.getKeyId().toString()));
    }
}