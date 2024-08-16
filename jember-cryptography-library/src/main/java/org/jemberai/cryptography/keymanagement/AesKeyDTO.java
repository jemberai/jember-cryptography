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

package org.jemberai.cryptography.keymanagement;

import lombok.Builder;
import lombok.Data;
import lombok.NonNull;

import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;
import java.util.UUID;

/**
 * Created by jt, Spring Framework Guru.
 */
@Builder
@Data
public class AesKeyDTO {

    private String clientId;
    private UUID keyId;
    private byte[] aesKey;
    private byte[] hmacKey;

    /**
     * Create an AesKeyDTO from a key id and byte arrays.
     * @param clientId The client id.
     * @param keyId The key id.
     * @param aesKey The AES key.
     * @param hmacKey The HMAC key.
     */
    public AesKeyDTO(@NonNull String clientId, @NonNull UUID keyId, byte[] aesKey, byte[] hmacKey) {
        this.clientId = clientId;
        this.keyId = keyId;
        this.aesKey = aesKey;
        this.hmacKey = hmacKey;
    }

    /**
     * Create an AesKeyDTO from a base64 encoded key.
     * @param keyId The key id.
     * @param aesKey The base64 encoded AES key.
     * @param hmacKey The base64 encoded HMAC key.
     */
    public AesKeyDTO(@NonNull String clientId, @NonNull String keyId, @NonNull String aesKey, @NonNull String hmacKey) {
        this.clientId = clientId;
        this.keyId = UUID.fromString(keyId);
        this.aesKey = Base64.getDecoder().decode(aesKey);
        this.hmacKey = Base64.getDecoder().decode(hmacKey);
    }

    public SecretKeySpec getAesKeySpec() {
        return new SecretKeySpec(aesKey, "AES");
    }

    public SecretKeySpec getHmacKeySpec() {
        return new SecretKeySpec(hmacKey, "HmacSHA256");
    }
}
