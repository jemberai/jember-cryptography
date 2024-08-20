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
import org.jemberai.cryptography.converters.EncryptedValueDtoConverter;
import org.jemberai.cryptography.converters.EncryptedValueWrapperConverter;
import org.jemberai.cryptography.model.EncryptedValueDTO;
import org.jemberai.cryptography.provider.EncryptionProvider;
import org.springframework.core.convert.converter.Converter;
import org.springframework.stereotype.Component;

/**
 * Created by jt, Spring Framework Guru.
 */
@Slf4j
@RequiredArgsConstructor
@Component
public class EncryptionKeysListener {

    private final EncryptionProvider encryptionProvider;

    private final Converter<EncryptedValueDTO, EncryptedValueWrapper> encryptedValueDtoConverter = new EncryptedValueDtoConverter();
    private final Converter<EncryptedValueWrapper, EncryptedValueDTO> encryptedValueWrapperConverter = new EncryptedValueWrapperConverter();

    public static final String JEMBER_INTERNAL = "JEMBER_INTERNAL";

    @PrePersist
    public void prePersist(EncryptionKeys aesKey){
        setEncryptedFields(aesKey);
    }

    @PreUpdate
    public void preUpdate(EncryptionKeys aesKey){
        setEncryptedFields(aesKey);
    }

    @PostLoad
    public void postLoad(EncryptionKeys aesKey) {
        log.debug("Decrypting AES Key");
        aesKey.setHmacKey(encryptionProvider.decrypt(JEMBER_INTERNAL, encryptedValueWrapperConverter.convert(aesKey.getEncryptedHmacKeyValue())));
        aesKey.setAesKey(encryptionProvider.decrypt(JEMBER_INTERNAL, encryptedValueWrapperConverter.convert(aesKey.getEncryptedAesKeyValue())));
    }

    private void setEncryptedFields(EncryptionKeys aesKey){
        log.debug("Encrypting AES Key");
        EncryptedValueDTO aesDto = encryptionProvider.encrypt(JEMBER_INTERNAL, aesKey.getAesKey());
        EncryptedValueDTO hmacDto = encryptionProvider.encrypt(JEMBER_INTERNAL, aesKey.getHmacKey());

        aesKey.setEncryptedAesKeyValue(encryptedValueDtoConverter.convert(aesDto));
        aesKey.setEncryptedHmacKeyValue(encryptedValueDtoConverter.convert(hmacDto));
    }
}
