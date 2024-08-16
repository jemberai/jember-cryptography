# jember-cryptography

The jember.ai cryptography library provides a simple interface for encrypting and decrypting data using the Java Cryptography Architecture (JCA).  

## Design
The default encryption provider is `AES/GCM/NoPadding` with a randomly generated initialization vector. You can provide 
your own encryption provider by implementing the `EncryptionProvider` interface.

The `AesKeyDTO` class is used to provide encryption key information. The `AesKeyDTO` class contains the following fields:
- `keyId`: A unique identifier for the key
- `aesKey`: The AES key
- `hmacKey`: The HMAC key
- `clientId`: The client ID

The `AesKeyDTO` is provided by a `KeyService` at runtime to the `EncryptionProvider` to encrypt and decrypt data. Several
implementations of the `KeyService` are provided in the `com.jember.cryptography.key` package.
* `StaticKeyService`: Provides a static key for encryption and decryption - to be used for development and testing
* `InMemoryKeyService`: Provides a key stored in memory for encryption and decryption, which can be provisioned at runtime via using environment variables and a Secrets stor of your choice.
* `JpaKeyService`: Provides a key stored in a database for encryption and decryption. The `JpaKeyService` uses the `AesKeyRepository` to store and retrieve keys.

If you require a different key store implementation, you can implement the `KeyService` interface and provide your own implementation.

The encrypted properties are stored in the `EncrptedValueDTO` class. The `EncryptedValueDTO` class contains the following fields:
- `provider`: The encryption provider
- `clientId`: The client ID
- `keyId`: The key ID
- `hmac`: The HMAC
- `encryptedValue`: The encrypted value
- `initializationVector`: The initialization vector

The `jember-cryptography-jpa` module provides a JPA attribute converter to encrypt and decrypt fields in a JPA entity. This 
module provides a JPA key store implementation that uses the `JpaKeyService` to store and retrieve keys. The encryption keys
are encrypted at rest via a JPA Listener. Keys are encrypted using a master key and the listener encrypts the keys before they are persisted to the database.
When the keys are retrieved from the database, the listener decrypts the keys using the master key.

The encrypted properties are stored in the `EncryptedValueWrapper` class. The `EncryptedValueWrapper` class contains the following fields:
- `provider`: The encryption provider
- `clientId`: The client ID
- `keyId`: The key ID
- `hmac`: The HMAC
- `encryptedValue`: The encrypted value
- `initializationVector`: The initialization vector

This supports the use of multiple keys for encryption and decryption. Since the `keyId` is stored with the encrypted value, 
the encryption keys may be rotated when necessary.  If key rotation is not a concern, the `EncryptedValueWrapper` can be 
marshalled to a JSON string and stored in a single column in the database.

This library is designed to be used in conjunction with Spring Data JPA, Spring Framework 6, and Spring Boot 3.