#ifndef CRYPTO_H
#define CRYPTO_H

#include <stddef.h>
#include <stdint.h>

#define CRYPTO_KEY_SIZE 32
#define CRYPTO_NONCE_SIZE 12
#define CRYPTO_TAG_SIZE 16
#define CRYPTO_HASH_SIZE 32

typedef enum {
    CRYPTO_CIPHER_AES_GCM = 0,
    CRYPTO_CIPHER_CHACHA20 = 1
} CryptoCipher;

typedef struct {
    uint8_t public_key[CRYPTO_KEY_SIZE];
    uint8_t secret_key[CRYPTO_KEY_SIZE];
} CryptoKeyPair;

typedef struct {
    uint8_t key[CRYPTO_KEY_SIZE];
    uint8_t nonce_prefix[8];
    uint32_t counter;
    CryptoCipher cipher;
} CryptoSession;

/* Initialization */
int crypto_init(void);

/* Key generation */
int crypto_generate_keypair(CryptoKeyPair *kp);

/* Key exchange (X25519 ECDH) */
int crypto_key_exchange(uint8_t shared_secret[CRYPTO_KEY_SIZE],
                        const uint8_t *our_secret_key,
                        const uint8_t *their_public_key);

/* Session key derivation (HKDF-SHA256) */
int crypto_derive_session_key(CryptoSession *session,
                              const uint8_t *shared_secret,
                              const uint8_t *sender_id,
                              const uint8_t *receiver_id,
                              size_t id_size,
                              CryptoCipher cipher);

/* AEAD encryption */
int crypto_encrypt(CryptoSession *session,
                   uint8_t *ciphertext,
                   size_t *ciphertext_len,
                   const uint8_t *plaintext,
                   size_t plaintext_len,
                   const uint8_t *aad,
                   size_t aad_len,
                   uint8_t nonce_out[CRYPTO_NONCE_SIZE]);

/* AEAD decryption */
int crypto_decrypt(CryptoSession *session,
                   uint8_t *plaintext,
                   size_t *plaintext_len,
                   const uint8_t *ciphertext,
                   size_t ciphertext_len,
                   const uint8_t *aad,
                   size_t aad_len,
                   const uint8_t nonce[CRYPTO_NONCE_SIZE]);

/* SHA-256 hashing */
int crypto_hash(uint8_t hash[CRYPTO_HASH_SIZE],
                const uint8_t *data,
                size_t data_len);

/* Random bytes */
void crypto_random_bytes(uint8_t *buf, size_t len);

/* Secure memory */
void crypto_zero(void *buf, size_t len);

#endif /* CRYPTO_H */
