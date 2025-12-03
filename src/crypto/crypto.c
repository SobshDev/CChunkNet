#include <string.h>
#include <sodium.h>
#include "crypto.h"

int crypto_init(void)
{
    return sodium_init();
}

int crypto_generate_keypair(CryptoKeyPair *kp)
{
    crypto_box_keypair(kp->public_key, kp->secret_key);
    return 0;
}

int crypto_key_exchange(uint8_t shared_secret[CRYPTO_KEY_SIZE],
                        const uint8_t *our_secret_key,
                        const uint8_t *their_public_key)
{
    if (crypto_scalarmult(shared_secret, our_secret_key, their_public_key) != 0)
        return -1;
    return 0;
}

int crypto_derive_session_key(CryptoSession *session,
                              const uint8_t *shared_secret,
                              const uint8_t *sender_id,
                              const uint8_t *receiver_id,
                              size_t id_size,
                              CryptoCipher cipher)
{
    uint8_t salt[64];
    if (id_size > 32)
        id_size = 32;
    memcpy(salt, sender_id, id_size);
    memcpy(salt + id_size, receiver_id, id_size);

    uint8_t prk[CRYPTO_KEY_SIZE];
    crypto_kdf_hkdf_sha256_extract(prk, salt, id_size * 2, shared_secret, CRYPTO_KEY_SIZE);

    const char *info = "chunknet-session-v1";
    crypto_kdf_hkdf_sha256_expand(session->key, CRYPTO_KEY_SIZE, info, strlen(info), prk);

    randombytes_buf(session->nonce_prefix, sizeof(session->nonce_prefix));
    session->counter = 0;
    session->cipher = cipher;

    sodium_memzero(prk, sizeof(prk));
    return 0;
}

static void build_nonce(CryptoSession *session, uint8_t nonce[CRYPTO_NONCE_SIZE])
{
    nonce[0] = (session->counter >> 0) & 0xFF;
    nonce[1] = (session->counter >> 8) & 0xFF;
    nonce[2] = (session->counter >> 16) & 0xFF;
    nonce[3] = (session->counter >> 24) & 0xFF;
    memcpy(nonce + 4, session->nonce_prefix, 8);
    session->counter++;
}

int crypto_encrypt(CryptoSession *session,
                   uint8_t *ciphertext,
                   size_t *ciphertext_len,
                   const uint8_t *plaintext,
                   size_t plaintext_len,
                   const uint8_t *aad,
                   size_t aad_len,
                   uint8_t nonce_out[CRYPTO_NONCE_SIZE])
{
    uint8_t nonce[CRYPTO_NONCE_SIZE];
    build_nonce(session, nonce);
    memcpy(nonce_out, nonce, CRYPTO_NONCE_SIZE);

    unsigned long long clen;
    int ret;

    if (session->cipher == CRYPTO_CIPHER_CHACHA20) {
        ret = crypto_aead_chacha20poly1305_ietf_encrypt(
            ciphertext, &clen,
            plaintext, plaintext_len,
            aad, aad_len,
            NULL, nonce, session->key);
    } else {
        if (crypto_aead_aes256gcm_is_available() == 0)
            return -1;
        ret = crypto_aead_aes256gcm_encrypt(
            ciphertext, &clen,
            plaintext, plaintext_len,
            aad, aad_len,
            NULL, nonce, session->key);
    }

    if (ret != 0)
        return -1;

    *ciphertext_len = (size_t)clen;
    return 0;
}

int crypto_decrypt(CryptoSession *session,
                   uint8_t *plaintext,
                   size_t *plaintext_len,
                   const uint8_t *ciphertext,
                   size_t ciphertext_len,
                   const uint8_t *aad,
                   size_t aad_len,
                   const uint8_t nonce[CRYPTO_NONCE_SIZE])
{
    unsigned long long plen;
    int ret;

    if (session->cipher == CRYPTO_CIPHER_CHACHA20) {
        ret = crypto_aead_chacha20poly1305_ietf_decrypt(
            plaintext, &plen,
            NULL,
            ciphertext, ciphertext_len,
            aad, aad_len,
            nonce, session->key);
    } else {
        if (crypto_aead_aes256gcm_is_available() == 0)
            return -1;
        ret = crypto_aead_aes256gcm_decrypt(
            plaintext, &plen,
            NULL,
            ciphertext, ciphertext_len,
            aad, aad_len,
            nonce, session->key);
    }

    if (ret != 0)
        return -1;

    *plaintext_len = (size_t)plen;
    return 0;
}

int crypto_sha256(uint8_t hash[CRYPTO_HASH_SIZE],
                  const uint8_t *data,
                  size_t data_len)
{
    return crypto_hash_sha256(hash, data, data_len);
}

void crypto_random_bytes(uint8_t *buf, size_t len)
{
    randombytes_buf(buf, len);
}

void crypto_zero(void *buf, size_t len)
{
    sodium_memzero(buf, len);
}
