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

import java.util.UUID;

/**
 * Implementation of KeyService for testing. NOT FOR PRODUCTION USE!
 *
 * @deprecated - Marking this as deprecated to flag this is not production use.
 *
 * Created by jt, Spring Framework Guru.
 */
@Deprecated(since = "0.1.0", forRemoval = false)
public class StaticTestKeyService implements KeyService {

    public final AesKeyDTO defaultKey = new AesKeyDTO("test-client", "19aea7c1-e621-43f6-8bcc-e2851f78a871",
            "6dzTInCNtUWROj5+f3oIoUTwGyvJonJx6WF2Dmghjvs=",
            "MfbthCp4gUygOJRT/stXGCFQzsn7iSHQpPOZRZ8UVBQ=");

    @Override
    public AesKeyDTO addKey(String clientId, AesKeyDTO key) {
        //effectively a no-op
        return defaultKey;
    }

    @Override
    public void setDefaultKey(String clientId, AesKeyDTO key) {
        // do nothing
    }

    @Override
    public AesKeyDTO getDefaultKey(String clientId) {
        return defaultKey;
    }

    @Override
    public AesKeyDTO getKey(String clientId, String keyId) {
        return defaultKey;
    }

    @Override
    public AesKeyDTO getKey(String clientId, UUID keyId) {
        return defaultKey;
    }
}
