package org.jember.cryptography.keymanagement;

import java.util.UUID;

/**
 * Created by jt, Spring Framework Guru.
 */
public interface KeyService {

    void setDefaultKey(AesKeyDTO key);

    AesKeyDTO getDefaultKey();

    AesKeyDTO getKey(String keyId);

    AesKeyDTO getKey(UUID keyId);
}
