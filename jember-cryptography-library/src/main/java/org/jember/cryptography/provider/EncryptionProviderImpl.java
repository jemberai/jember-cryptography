package org.jember.cryptography.provider;

import jakarta.annotation.PostConstruct;
import org.springframework.core.env.Environment;

import javax.crypto.spec.SecretKeySpec;

/**
 * Created by jt, Spring Framework Guru.
 */
public class EncryptionProviderImpl implements EncryptionProvider {

    private static final String ID = "DefaultJemberEncryptionProviderV1";

    private final String activeKey;
    private SecretKeySpec aesKey;
    private SecretKeySpec hmacKey;

    public EncryptionProviderImpl(String activeKey) {
        this.activeKey = activeKey;
    }

    @PostConstruct
    public void setUp() throws EncryptionException {
        try {
            if (activeKey.startsWith("${")) {
                throw new EncryptionException("Property encryption.VeloEncryptionProviderV1.key.active has not been set");
            }

            //TODO - in order to support key rotation we would need to look up all the configured keys
            //that's all properties under encryption.VeloEncryptionProviderV1.key
            //Keeping it simple for now though.....

          //  byte[] aesPassPhrase = getProperty(env, String.format("encryption.VeloEncryptionProviderV1.key.%s.aes", activeKey));
         //   byte[] hmacPassPhrase = getProperty(env, String.format("encryption.VeloEncryptionProviderV1.key.%s.hmac", activeKey));
        //    this.aesKey = new SecretKeySpec(aesPassPhrase, "AES");
        //    this.hmacKey = new SecretKeySpec(hmacPassPhrase, "HmacSHA256");
        }
        catch (RuntimeException e) {
            throw new EncryptionException("Problem initialising encryption provider", e);
        }
    }

    @Override
    public String getKeyProviderId() {
        return "";
    }

    @Override
    public String encrypt(String value) throws EncryptionException {
        return "";
    }

    @Override
    public String decrypt(String encryptedValue) throws EncryptionException {
        return "";
    }

    @Override
    public boolean hasChanged(String initialValue, String proposedValue) {
        return false;
    }
}
