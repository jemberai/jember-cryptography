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

package org.jemberai.cryptography.model;

import java.util.Arrays;
import java.util.Objects;
import java.util.UUID;

/**
 * EncryptedValueDTO record
 * @param provider id of the encryption system
 * @param keyId id of the key used to encrypt this value
 * @param hmac base64 of the HMAC
 * @param encryptedValue base64 of the encrypted value
 * @param initializationVector base64 of the initialization vector of the encrypted value
 */
public record EncryptedValueDTO(String provider,
                                UUID keyId,
                                byte[] hmac,
                                byte[] encryptedValue,
                                byte[] initializationVector) {

    @Override
    public String toString() {
        return "EncryptedValueDTO{" +
                "provider='" + provider + '\'' +
                ", keyId=" + keyId +
                '}';
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof EncryptedValueDTO(String provider,
                                             UUID keyId,
                                             byte[] hmac,
                                             byte[] encryptedValue,
                                             byte[] initializationVector))) return false;

        EncryptedValueDTO that = (EncryptedValueDTO) o;
        return Objects.equals(keyId, that.keyId) && Arrays.equals(hmac, that.hmac) && Objects.equals(provider, that.provider) && Arrays.equals(encryptedValue, that.encryptedValue) && Arrays.equals(initializationVector, that.initializationVector);
    }

    @Override
    public int hashCode() {
        int result = Objects.hashCode(provider);
        result = 31 * result + Objects.hashCode(keyId);
        result = 31 * result + Arrays.hashCode(hmac);
        result = 31 * result + Arrays.hashCode(encryptedValue);
        result = 31 * result + Arrays.hashCode(initializationVector);
        return result;
    }
}
