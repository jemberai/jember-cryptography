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

import jakarta.persistence.*;
import jakarta.validation.constraints.NotNull;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.annotations.UpdateTimestamp;
import org.hibernate.annotations.UuidGenerator;
import org.hibernate.proxy.HibernateProxy;
import org.hibernate.type.SqlTypes;

import java.time.LocalDateTime;
import java.util.Objects;
import java.util.UUID;

@Getter
@Setter
@ToString
@Entity
@Table(name = "aes_key")
@Builder
@NoArgsConstructor
@AllArgsConstructor
@EntityListeners(AesKeyListener.class)
public class AesKey {
    @Id
    @GeneratedValue
    @UuidGenerator(style = UuidGenerator.Style.TIME)
    @JdbcTypeCode(SqlTypes.CHAR)
    @Column(length = 36, columnDefinition = "char(36)", updatable = false, nullable = false)
    private UUID id;

    @Version
    private Integer version;

    @NotNull
    private String clientId;

    @NotNull
    private UUID keyId;

    @Transient
    private byte[] aesKey;

    @Transient
    private byte[] hmacKey;

    @Embedded
    @AttributeOverrides({
            @AttributeOverride(name = "keyId", column = @Column(name = "aes_key_id")),
            @AttributeOverride(name = "provider", column = @Column(name = "aes_provider")),
            @AttributeOverride(name = "hmac", column = @Column(name = "aes_hmac")),
            @AttributeOverride(name = "initializationVector", column = @Column(name = "aes_intitialization_vector")),
            @AttributeOverride(name = "encryptedValue", column = @Column(name = "aes_encrypted_value"))
    })
    private EncryptedValue encryptedAesKeyValue;

    @Embedded
    @AttributeOverrides({
            @AttributeOverride(name = "keyId", column = @Column(name = "hmac_key_id")),
            @AttributeOverride(name = "provider", column = @Column(name = "hmac_provider")),
            @AttributeOverride(name = "hmac", column = @Column(name = "hmac_hmac")),
            @AttributeOverride(name = "initializationVector", column = @Column(name = "hmac_intitialization_vector")),
            @AttributeOverride(name = "encryptedValue", column = @Column(name = "hmac_encrypted_value"))
    })
    private EncryptedValue encryptedHmacKeyValue;

    @CreationTimestamp
    private LocalDateTime createdDate;

    @UpdateTimestamp
    private LocalDateTime updateDate;

    @Override
    public final boolean equals(Object o) {
        if (this == o) return true;
        if (o == null) return false;
        Class<?> oEffectiveClass = o instanceof HibernateProxy ? ((HibernateProxy) o).getHibernateLazyInitializer().getPersistentClass() : o.getClass();
        Class<?> thisEffectiveClass = this instanceof HibernateProxy ? ((HibernateProxy) this).getHibernateLazyInitializer().getPersistentClass() : this.getClass();
        if (thisEffectiveClass != oEffectiveClass) return false;
        AesKey aesKey = (AesKey) o;
        return getId() != null && Objects.equals(getId(), aesKey.getId());
    }

    @Override
    public final int hashCode() {
        return this instanceof HibernateProxy ? ((HibernateProxy) this).getHibernateLazyInitializer().getPersistentClass().hashCode() : getClass().hashCode();
    }
}