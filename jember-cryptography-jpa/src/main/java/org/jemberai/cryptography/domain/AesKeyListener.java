/*
 *
 *  * Copyright 2023 - 2024 the original author or authors.
 *  *
 *  * Licensed under the Apache License, Version 2.0 (the "License");
 *  * you may not use this file except in compliance with the License.
 *  * You may obtain a copy of the License at
 *  *
 *  * https://www.apache.org/licenses/LICENSE-2.0
 *  *
 *  * Unless required by applicable law or agreed to in writing, software
 *  * distributed under the License is distributed on an "AS IS" BASIS,
 *  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  * See the License for the specific language governing permissions and
 *  * limitations under the License.
 *
 */

package org.jemberai.cryptography.domain;

import jakarta.persistence.PostLoad;
import jakarta.persistence.PrePersist;
import jakarta.persistence.PreUpdate;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.jemberai.cryptography.model.EncryptedValueDTO;
import org.jemberai.cryptography.provider.EncryptionProvider;
import org.springframework.stereotype.Component;

/**
 * Created by jt, Spring Framework Guru.
 */
@Slf4j
@RequiredArgsConstructor
@Component
public class AesKeyListener {

    private final EncryptionProvider encryptionProvider;

    public static final String JEMBER_INTERNAL = "JEMBER_INTERNAL";

    @PrePersist
    public void prePersist(AesKey aesKey){
        setEncryptedFields(aesKey);
    }

    @PreUpdate
    public void preUpdate(AesKey aesKey){
        setEncryptedFields(aesKey);
    }

    @PostLoad
    public void postLoad(AesKey aesKey) {
        log.debug("Decrypting AES Key");
        aesKey.setHmacKey(encryptionProvider.decrypt(JEMBER_INTERNAL, convert(aesKey.getEncryptedHmacKeyValue())));
        aesKey.setAesKey(encryptionProvider.decrypt(JEMBER_INTERNAL, convert(aesKey.getEncryptedAesKeyValue())));
    }

    private void setEncryptedFields(AesKey aesKey){
        log.debug("Encrypting AES Key");
        EncryptedValueDTO aesDto = encryptionProvider.encrypt(JEMBER_INTERNAL, aesKey.getAesKey());
        EncryptedValueDTO hmacDto = encryptionProvider.encrypt(JEMBER_INTERNAL, aesKey.getHmacKey());

        aesKey.setEncryptedAesKeyValue(convert(aesDto));
        aesKey.setEncryptedHmacKeyValue(convert(hmacDto));
    }

    private EncryptedValue convert(EncryptedValueDTO encryptedValueDTO) {
        EncryptedValue encryptedValue = new EncryptedValue();
        encryptedValue.setKeyId(encryptedValueDTO.keyId());
        encryptedValue.setProvider(encryptedValueDTO.provider());
        encryptedValue.setHmac(encryptedValueDTO.hmac());
        encryptedValue.setEncryptedValue(encryptedValueDTO.encryptedValue());
        encryptedValue.setInitializationVector(encryptedValueDTO.initializationVector());

        return encryptedValue;
    }

    private EncryptedValueDTO convert(EncryptedValue encryptedValue) {
        return new EncryptedValueDTO(encryptedValue.getProvider(),
                        encryptedValue.getKeyId(),
                        encryptedValue.getHmac(),
                        encryptedValue.getEncryptedValue(),
                        encryptedValue.getInitializationVector());
    }
}
