package org.jember.cryptography.keymanagement;

import java.util.UUID;

/**
 * Implementation of KeyService for testing. NOT FOR PRODUCTION USE!
 *
 * @deprecated - Marking this as deprecated to flag this is not production use.
 *
 * Created by jt, Spring Framework Guru.
 */
@Deprecated
public class StaticTestKeyService implements KeyService {

    public final AesKeyDTO defaultKey = new AesKeyDTO("19aea7c1-e621-43f6-8bcc-e2851f78a871",
            "6dzTInCNtUWROj5+f3oIoUTwGyvJonJx6WF2Dmghjvs=",
            "MfbthCp4gUygOJRT/stXGCFQzsn7iSHQpPOZRZ8UVBQ=");

    @Override
    public void setDefaultKey(AesKeyDTO key) {
        // do nothing
    }

    @Override
    public AesKeyDTO getDefaultKey() {
        return defaultKey;
    }

    @Override
    public AesKeyDTO getKey(String keyId) {
        return defaultKey;
    }

    @Override
    public AesKeyDTO getKey(UUID keyId) {
        return defaultKey;
    }
}
