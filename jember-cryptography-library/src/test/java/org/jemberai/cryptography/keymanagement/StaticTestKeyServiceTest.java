package org.jemberai.cryptography.keymanagement;

import org.junit.jupiter.api.Test;

import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

class StaticTestKeyServiceTest {

    KeyService keyService = new StaticTestKeyService();
    String clientId = "test-client-id";

    @Test
    void getDefaultKey() {
        assertNotNull(keyService.getDefaultKey(clientId));
    }

    @Test
    void getKeyString() {
        assertNotNull(keyService.getKey(clientId, "19aea7c1-e621-43f6-8bcc-e2851f78a871"));
    }

    @Test
    void getKeyUUID() {
        assertNotNull(keyService.getKey(clientId, UUID.randomUUID()));
    }
}