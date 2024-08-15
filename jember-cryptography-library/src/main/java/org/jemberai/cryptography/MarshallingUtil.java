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

package org.jemberai.cryptography;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import org.jemberai.cryptography.model.EncryptedValueDTO;
import org.jemberai.cryptography.provider.EncryptionException;

import java.io.IOException;

/**
 * Created by jt, Spring Framework Guru.
 */
public class MarshallingUtil {
    private static final ObjectMapper objectMapper = new ObjectMapper();

    private MarshallingUtil() {
        throw new IllegalStateException("Utility class");
    }

    static {
        objectMapper.configure(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS, false);
        objectMapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
        objectMapper.registerModule(new JavaTimeModule());
    }

    public static String marshal(EncryptedValueDTO encryptedRecord) throws EncryptionException {
        try {
            if (encryptedRecord == null) {
                throw new EncryptionException("Cannot marshal a null object");
            }
            return objectMapper.writeValueAsString(encryptedRecord);
        } catch (JsonProcessingException | RuntimeException e) {
            throw new EncryptionException("Error marshalling object", e);
        }
    }

    public static EncryptedValueDTO unmarshal(String json) throws EncryptionException {
        try {
            if (json == null) {
                return null;
            }
            return objectMapper.readValue(json, EncryptedValueDTO.class);
        } catch (IOException | RuntimeException e) {
            throw new EncryptionException("Error unmarshalling JSON: " + json, e);  //won't be a security problem because the JSON is always encrypted
        }
    }

    /**
     * Marshal the object to JSON and then unmarshal it again as the requested class
     * <p>
     * The idea being that you pass in an entity with PII and convert it to a non-PII entity
     *
     * @param objToClone
     * @param unmarshalAs
     * @param <T>
     * @return
     * @throws EncryptionException
     */
    public static <T> T downgrade(Object objToClone, Class<T> unmarshalAs) throws EncryptionException {
        try {
            String json = objectMapper.writeValueAsString(objToClone);
            return objectMapper.readValue(json, unmarshalAs);
        } catch (IOException | RuntimeException e) {
            throw new EncryptionException("Error cloning object to class: " + unmarshalAs, e);
        }
    }
}
