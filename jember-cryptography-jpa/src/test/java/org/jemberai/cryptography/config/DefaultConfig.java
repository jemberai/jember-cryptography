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

package org.jemberai.cryptography.config;

import org.jemberai.cryptography.keymanagement.JpaKeyService;
import org.jemberai.cryptography.keymanagement.KeyService;
import org.jemberai.cryptography.keymanagement.StaticTestKeyService;
import org.jemberai.cryptography.provider.EncryptionProvider;
import org.jemberai.cryptography.provider.EncryptionProviderImpl;
import org.jemberai.cryptography.repositories.AesKeyRepository;
import org.jemberai.cryptography.repositories.DefaultKeyRepository;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Created by jt, Spring Framework Guru.
 */
@Configuration
public class DefaultConfig {

    @Bean
    public EncryptionProvider encryptionProvider() {
        return new EncryptionProviderImpl(new StaticTestKeyService());
    }

    @Bean
    public KeyService keyService(AesKeyRepository aesKeyRepository, DefaultKeyRepository defaultKeyRepository) {
        return new JpaKeyService(aesKeyRepository, defaultKeyRepository);
    }
}
