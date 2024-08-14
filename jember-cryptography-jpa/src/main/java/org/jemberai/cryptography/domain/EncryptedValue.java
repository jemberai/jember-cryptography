package org.jemberai.cryptography.domain;

import jakarta.persistence.Embeddable;
import lombok.Getter;
import lombok.Setter;

import java.util.UUID;

/**
 * Created by jt, Spring Framework Guru.
 */
@Getter
@Setter
@Embeddable
public class EncryptedValue {
    private String provider;
    private UUID keyId;
    private byte[] hmac;
    private byte[] encryptedValue;
    private byte[] initializationVector;
}
