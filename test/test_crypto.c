#include <stdio.h>
#include <string.h>
#include "../src/crypto/crypto.h"

static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) static void name(void)
#define RUN_TEST(name) do { \
    printf("Running %s... ", #name); \
    fflush(stdout); \
    name(); \
    printf("PASSED\n"); \
    tests_passed++; \
} while(0)

#define ASSERT_EQ(a, b) do { \
    if ((a) != (b)) { \
        printf("FAILED\n  Expected: %d, Got: %d\n", (int)(b), (int)(a)); \
        tests_failed++; \
        return; \
    } \
} while(0)

#define ASSERT_NEQ(a, b) do { \
    if ((a) == (b)) { \
        printf("FAILED\n  Values should not be equal: %d\n", (int)(a)); \
        tests_failed++; \
        return; \
    } \
} while(0)

#define ASSERT_MEM_EQ(a, b, len) do { \
    if (memcmp((a), (b), (len)) != 0) { \
        printf("FAILED\n  Memory mismatch\n"); \
        tests_failed++; \
        return; \
    } \
} while(0)

#define ASSERT_MEM_NEQ(a, b, len) do { \
    if (memcmp((a), (b), (len)) == 0) { \
        printf("FAILED\n  Memory should not match\n"); \
        tests_failed++; \
        return; \
    } \
} while(0)

TEST(test_init)
{
    int ret = crypto_init();
    ASSERT_EQ(ret >= 0, 1);
}

TEST(test_keypair_generation)
{
    CryptoKeyPair kp1, kp2;

    ASSERT_EQ(crypto_generate_keypair(&kp1), 0);
    ASSERT_EQ(crypto_generate_keypair(&kp2), 0);

    ASSERT_MEM_NEQ(kp1.public_key, kp2.public_key, CRYPTO_KEY_SIZE);
    ASSERT_MEM_NEQ(kp1.secret_key, kp2.secret_key, CRYPTO_KEY_SIZE);
}

TEST(test_key_exchange)
{
    CryptoKeyPair alice, bob;
    uint8_t alice_shared[CRYPTO_KEY_SIZE];
    uint8_t bob_shared[CRYPTO_KEY_SIZE];

    crypto_generate_keypair(&alice);
    crypto_generate_keypair(&bob);

    ASSERT_EQ(crypto_key_exchange(alice_shared, alice.secret_key, bob.public_key), 0);
    ASSERT_EQ(crypto_key_exchange(bob_shared, bob.secret_key, alice.public_key), 0);

    ASSERT_MEM_EQ(alice_shared, bob_shared, CRYPTO_KEY_SIZE);
}

TEST(test_session_derivation)
{
    uint8_t shared_secret[CRYPTO_KEY_SIZE];
    crypto_random_bytes(shared_secret, CRYPTO_KEY_SIZE);

    uint8_t sender_id[16], receiver_id[16];
    crypto_random_bytes(sender_id, 16);
    crypto_random_bytes(receiver_id, 16);

    CryptoSession session1, session2;
    ASSERT_EQ(crypto_derive_session_key(&session1, shared_secret, sender_id, receiver_id, 16, CRYPTO_CIPHER_CHACHA20), 0);
    ASSERT_EQ(crypto_derive_session_key(&session2, shared_secret, sender_id, receiver_id, 16, CRYPTO_CIPHER_CHACHA20), 0);

    ASSERT_MEM_EQ(session1.key, session2.key, CRYPTO_KEY_SIZE);
}

TEST(test_encrypt_decrypt_chacha20)
{
    uint8_t shared_secret[CRYPTO_KEY_SIZE];
    uint8_t sender_id[16], receiver_id[16];
    crypto_random_bytes(shared_secret, CRYPTO_KEY_SIZE);
    crypto_random_bytes(sender_id, 16);
    crypto_random_bytes(receiver_id, 16);

    CryptoSession encrypt_session, decrypt_session;
    crypto_derive_session_key(&encrypt_session, shared_secret, sender_id, receiver_id, 16, CRYPTO_CIPHER_CHACHA20);
    crypto_derive_session_key(&decrypt_session, shared_secret, sender_id, receiver_id, 16, CRYPTO_CIPHER_CHACHA20);

    const char *plaintext = "Hello, ChunkNet!";
    size_t plaintext_len = strlen(plaintext);

    uint8_t ciphertext[256];
    size_t ciphertext_len;
    uint8_t nonce[CRYPTO_NONCE_SIZE];
    uint8_t aad[] = {0x01, 0x02, 0x03, 0x04};

    ASSERT_EQ(crypto_encrypt(&encrypt_session, ciphertext, &ciphertext_len,
                             (uint8_t *)plaintext, plaintext_len,
                             aad, sizeof(aad), nonce), 0);

    ASSERT_EQ(ciphertext_len, plaintext_len + CRYPTO_TAG_SIZE);

    uint8_t decrypted[256];
    size_t decrypted_len;
    ASSERT_EQ(crypto_decrypt(&decrypt_session, decrypted, &decrypted_len,
                             ciphertext, ciphertext_len,
                             aad, sizeof(aad), nonce), 0);

    ASSERT_EQ(decrypted_len, plaintext_len);
    ASSERT_MEM_EQ(decrypted, plaintext, plaintext_len);
}

TEST(test_encrypt_decrypt_aes_gcm)
{
    uint8_t shared_secret[CRYPTO_KEY_SIZE];
    uint8_t sender_id[16], receiver_id[16];
    crypto_random_bytes(shared_secret, CRYPTO_KEY_SIZE);
    crypto_random_bytes(sender_id, 16);
    crypto_random_bytes(receiver_id, 16);

    CryptoSession encrypt_session, decrypt_session;
    crypto_derive_session_key(&encrypt_session, shared_secret, sender_id, receiver_id, 16, CRYPTO_CIPHER_AES_GCM);
    crypto_derive_session_key(&decrypt_session, shared_secret, sender_id, receiver_id, 16, CRYPTO_CIPHER_AES_GCM);

    const char *plaintext = "Hello, ChunkNet with AES!";
    size_t plaintext_len = strlen(plaintext);

    uint8_t ciphertext[256];
    size_t ciphertext_len;
    uint8_t nonce[CRYPTO_NONCE_SIZE];
    uint8_t aad[] = {0x01, 0x02, 0x03, 0x04};

    int ret = crypto_encrypt(&encrypt_session, ciphertext, &ciphertext_len,
                             (uint8_t *)plaintext, plaintext_len,
                             aad, sizeof(aad), nonce);

    if (ret == -1) {
        printf("(AES-GCM not available, skipping) ");
        return;
    }

    ASSERT_EQ(ret, 0);

    uint8_t decrypted[256];
    size_t decrypted_len;
    ASSERT_EQ(crypto_decrypt(&decrypt_session, decrypted, &decrypted_len,
                             ciphertext, ciphertext_len,
                             aad, sizeof(aad), nonce), 0);

    ASSERT_EQ(decrypted_len, plaintext_len);
    ASSERT_MEM_EQ(decrypted, plaintext, plaintext_len);
}

TEST(test_decrypt_wrong_key)
{
    uint8_t shared1[CRYPTO_KEY_SIZE], shared2[CRYPTO_KEY_SIZE];
    uint8_t sender_id[16], receiver_id[16];
    crypto_random_bytes(shared1, CRYPTO_KEY_SIZE);
    crypto_random_bytes(shared2, CRYPTO_KEY_SIZE);
    crypto_random_bytes(sender_id, 16);
    crypto_random_bytes(receiver_id, 16);

    CryptoSession encrypt_session, decrypt_session;
    crypto_derive_session_key(&encrypt_session, shared1, sender_id, receiver_id, 16, CRYPTO_CIPHER_CHACHA20);
    crypto_derive_session_key(&decrypt_session, shared2, sender_id, receiver_id, 16, CRYPTO_CIPHER_CHACHA20);

    const char *plaintext = "Secret message";
    uint8_t ciphertext[256];
    size_t ciphertext_len;
    uint8_t nonce[CRYPTO_NONCE_SIZE];

    crypto_encrypt(&encrypt_session, ciphertext, &ciphertext_len,
                   (uint8_t *)plaintext, strlen(plaintext),
                   NULL, 0, nonce);

    uint8_t decrypted[256];
    size_t decrypted_len;
    int ret = crypto_decrypt(&decrypt_session, decrypted, &decrypted_len,
                             ciphertext, ciphertext_len,
                             NULL, 0, nonce);

    ASSERT_EQ(ret, -1);
}

TEST(test_decrypt_tampered_ciphertext)
{
    uint8_t shared[CRYPTO_KEY_SIZE];
    uint8_t sender_id[16], receiver_id[16];
    crypto_random_bytes(shared, CRYPTO_KEY_SIZE);
    crypto_random_bytes(sender_id, 16);
    crypto_random_bytes(receiver_id, 16);

    CryptoSession encrypt_session, decrypt_session;
    crypto_derive_session_key(&encrypt_session, shared, sender_id, receiver_id, 16, CRYPTO_CIPHER_CHACHA20);
    crypto_derive_session_key(&decrypt_session, shared, sender_id, receiver_id, 16, CRYPTO_CIPHER_CHACHA20);

    const char *plaintext = "Secret message";
    uint8_t ciphertext[256];
    size_t ciphertext_len;
    uint8_t nonce[CRYPTO_NONCE_SIZE];

    crypto_encrypt(&encrypt_session, ciphertext, &ciphertext_len,
                   (uint8_t *)plaintext, strlen(plaintext),
                   NULL, 0, nonce);

    ciphertext[5] ^= 0xFF;

    uint8_t decrypted[256];
    size_t decrypted_len;
    int ret = crypto_decrypt(&decrypt_session, decrypted, &decrypted_len,
                             ciphertext, ciphertext_len,
                             NULL, 0, nonce);

    ASSERT_EQ(ret, -1);
}

TEST(test_sha256_hash)
{
    const char *data = "Hello, World!";
    uint8_t hash[CRYPTO_HASH_SIZE];

    ASSERT_EQ(crypto_sha256(hash, (uint8_t *)data, strlen(data)), 0);

    uint8_t expected[CRYPTO_HASH_SIZE] = {
        0xdf, 0xfd, 0x60, 0x21, 0xbb, 0x2b, 0xd5, 0xb0,
        0xaf, 0x67, 0x62, 0x90, 0x80, 0x9e, 0xc3, 0xa5,
        0x31, 0x91, 0xdd, 0x81, 0xc7, 0xf7, 0x0a, 0x4b,
        0x28, 0x68, 0x8a, 0x36, 0x21, 0x82, 0x98, 0x6f
    };
    ASSERT_MEM_EQ(hash, expected, CRYPTO_HASH_SIZE);
}

TEST(test_sha256_hash_empty)
{
    uint8_t hash[CRYPTO_HASH_SIZE];

    ASSERT_EQ(crypto_sha256(hash, NULL, 0), 0);

    uint8_t expected[CRYPTO_HASH_SIZE] = {
        0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
        0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
        0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
        0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55
    };
    ASSERT_MEM_EQ(hash, expected, CRYPTO_HASH_SIZE);
}

TEST(test_random_bytes)
{
    uint8_t buf1[32], buf2[32];

    crypto_random_bytes(buf1, sizeof(buf1));
    crypto_random_bytes(buf2, sizeof(buf2));

    ASSERT_MEM_NEQ(buf1, buf2, 32);
}

TEST(test_nonce_increments)
{
    uint8_t shared[CRYPTO_KEY_SIZE];
    uint8_t sender_id[16], receiver_id[16];
    crypto_random_bytes(shared, CRYPTO_KEY_SIZE);
    crypto_random_bytes(sender_id, 16);
    crypto_random_bytes(receiver_id, 16);

    CryptoSession session;
    crypto_derive_session_key(&session, shared, sender_id, receiver_id, 16, CRYPTO_CIPHER_CHACHA20);

    const char *plaintext = "test";
    uint8_t ciphertext[64];
    size_t ciphertext_len;
    uint8_t nonce1[CRYPTO_NONCE_SIZE], nonce2[CRYPTO_NONCE_SIZE];

    crypto_encrypt(&session, ciphertext, &ciphertext_len,
                   (uint8_t *)plaintext, strlen(plaintext),
                   NULL, 0, nonce1);

    crypto_encrypt(&session, ciphertext, &ciphertext_len,
                   (uint8_t *)plaintext, strlen(plaintext),
                   NULL, 0, nonce2);

    ASSERT_MEM_NEQ(nonce1, nonce2, CRYPTO_NONCE_SIZE);
    ASSERT_EQ(nonce1[0], 0);
    ASSERT_EQ(nonce2[0], 1);
}

TEST(test_full_key_exchange_flow)
{
    CryptoKeyPair alice, bob;
    crypto_generate_keypair(&alice);
    crypto_generate_keypair(&bob);

    uint8_t alice_shared[CRYPTO_KEY_SIZE], bob_shared[CRYPTO_KEY_SIZE];
    crypto_key_exchange(alice_shared, alice.secret_key, bob.public_key);
    crypto_key_exchange(bob_shared, bob.secret_key, alice.public_key);

    uint8_t alice_id[16], bob_id[16];
    crypto_random_bytes(alice_id, 16);
    crypto_random_bytes(bob_id, 16);

    CryptoSession alice_session, bob_session;
    crypto_derive_session_key(&alice_session, alice_shared, alice_id, bob_id, 16, CRYPTO_CIPHER_CHACHA20);
    crypto_derive_session_key(&bob_session, bob_shared, alice_id, bob_id, 16, CRYPTO_CIPHER_CHACHA20);

    ASSERT_MEM_EQ(alice_session.key, bob_session.key, CRYPTO_KEY_SIZE);

    const char *message = "Hello from Alice!";
    uint8_t ciphertext[256];
    size_t ciphertext_len;
    uint8_t nonce[CRYPTO_NONCE_SIZE];
    uint8_t header[12] = {0};

    crypto_encrypt(&alice_session, ciphertext, &ciphertext_len,
                   (uint8_t *)message, strlen(message),
                   header, sizeof(header), nonce);

    uint8_t decrypted[256];
    size_t decrypted_len;
    int ret = crypto_decrypt(&bob_session, decrypted, &decrypted_len,
                             ciphertext, ciphertext_len,
                             header, sizeof(header), nonce);

    ASSERT_EQ(ret, 0);
    ASSERT_EQ(decrypted_len, strlen(message));
    ASSERT_MEM_EQ(decrypted, message, strlen(message));
}

int main(void)
{
    printf("=== Crypto Tests ===\n\n");

    RUN_TEST(test_init);
    RUN_TEST(test_keypair_generation);
    RUN_TEST(test_key_exchange);
    RUN_TEST(test_session_derivation);
    RUN_TEST(test_encrypt_decrypt_chacha20);
    RUN_TEST(test_encrypt_decrypt_aes_gcm);
    RUN_TEST(test_decrypt_wrong_key);
    RUN_TEST(test_decrypt_tampered_ciphertext);
    RUN_TEST(test_sha256_hash);
    RUN_TEST(test_sha256_hash_empty);
    RUN_TEST(test_random_bytes);
    RUN_TEST(test_nonce_increments);
    RUN_TEST(test_full_key_exchange_flow);

    printf("\n=== Results ===\n");
    printf("Passed: %d\n", tests_passed);
    printf("Failed: %d\n", tests_failed);

    return tests_failed > 0 ? 1 : 0;
}
