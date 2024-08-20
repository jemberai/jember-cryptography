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

package org.jemberai.cryptography.converters;

import org.jemberai.cryptography.domain.EncryptedValueWrapper;
import org.jemberai.cryptography.model.EncryptedValueDTO;
import org.springframework.core.convert.converter.Converter;

/**
 * Created by jt, Spring Framework Guru.
 */
public class EncryptedValueDtoConverter implements Converter<EncryptedValueDTO, EncryptedValueWrapper> {

    @Override
    public EncryptedValueWrapper convert(EncryptedValueDTO encryptedValueDTO) {
        EncryptedValueWrapper encryptedValue = new EncryptedValueWrapper();
        encryptedValue.setKeyId(encryptedValueDTO.keyId());
        encryptedValue.setProvider(encryptedValueDTO.provider());
        encryptedValue.setHmac(encryptedValueDTO.hmac());
        encryptedValue.setEncryptedValue(encryptedValueDTO.encryptedValue());
        encryptedValue.setInitializationVector(encryptedValueDTO.initializationVector());

        return encryptedValue;
    }
}
