package org.jember.cryptography.keymanagement;

import org.junit.jupiter.api.Test;

import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

class StaticTestKeyServiceTest {

    KeyService keyService = new StaticTestKeyService();

    @Test
    void getDefaultKey() {
        assertNotNull(keyService.getDefaultKey());
    }

    @Test
    void getKeyString() {
        assertNotNull(keyService.getKey("19aea7c1-e621-43f6-8bcc-e2851f78a871"));
    }

    @Test
    void getKeyUUID() {
        assertNotNull(keyService.getKey(UUID.randomUUID()));
    }
}