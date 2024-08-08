package org.jember.cryptography.keymanagement;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class KeyServiceStaticKeyImplTest {

    KeyService keyService = new KeyServiceStaticKeyImpl();

    @Test
    void getDefaultKey() {
        assertNotNull(keyService.getDefaultKey());
    }

    @Test
    void getKey() {
        assertNotNull(keyService.getKey("19aea7c1-e621-43f6-8bcc-e2851f78a871"));
    }
}