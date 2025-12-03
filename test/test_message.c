#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "../src/protocol/message.h"
#include "../src/const.h"

static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) static void name(void)
#define RUN_TEST(name) do { \
    printf("Running %s... ", #name); \
    name(); \
    printf("PASSED\n"); \
    tests_passed++; \
} while(0)

#define ASSERT_EQ(a, b) do { \
    if ((a) != (b)) { \
        printf("FAILED\n  Expected: %lld, Got: %lld\n", (long long)(b), (long long)(a)); \
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

TEST(test_header_roundtrip)
{
    MessageHeader orig = {
        .magic = MAGIC_NUMBER,
        .version = 1,
        .type = MSG_HELLO,
        .flags = 0x0003,
        .payload_len = 20
    };
    uint8_t buffer[HEADER_SIZE];
    MessageHeader result;

    size_t written = serialize_header(&orig, buffer, sizeof(buffer));
    ASSERT_EQ(written, HEADER_SIZE);

    int ret = deserialize_header(buffer, sizeof(buffer), &result);
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(result.magic, orig.magic);
    ASSERT_EQ(result.version, orig.version);
    ASSERT_EQ(result.type, orig.type);
    ASSERT_EQ(result.flags, orig.flags);
    ASSERT_EQ(result.payload_len, orig.payload_len);
}

TEST(test_header_little_endian)
{
    MessageHeader header = {
        .magic = 0x434E4554,
        .version = 1,
        .type = MSG_HELLO,
        .flags = 0x0102,
        .payload_len = 0x04030201
    };
    uint8_t buffer[HEADER_SIZE];

    serialize_header(&header, buffer, sizeof(buffer));

    ASSERT_EQ(buffer[0], 0x54);
    ASSERT_EQ(buffer[1], 0x45);
    ASSERT_EQ(buffer[2], 0x4E);
    ASSERT_EQ(buffer[3], 0x43);
    ASSERT_EQ(buffer[4], 1);
    ASSERT_EQ(buffer[5], MSG_HELLO);
    ASSERT_EQ(buffer[6], 0x02);
    ASSERT_EQ(buffer[7], 0x01);
    ASSERT_EQ(buffer[8], 0x01);
    ASSERT_EQ(buffer[9], 0x02);
    ASSERT_EQ(buffer[10], 0x03);
    ASSERT_EQ(buffer[11], 0x04);
}

TEST(test_header_buffer_too_small)
{
    MessageHeader header = { .magic = MAGIC_NUMBER };
    uint8_t buffer[HEADER_SIZE - 1];

    size_t written = serialize_header(&header, buffer, sizeof(buffer));
    ASSERT_EQ(written, 0);

    MessageHeader result;
    int ret = deserialize_header(buffer, sizeof(buffer), &result);
    ASSERT_EQ(ret, -1);
}

TEST(test_hello_roundtrip)
{
    HelloPayload orig = {
        .min_version = 1,
        .max_version = 1,
        .capabilities = CAP_AES_GCM | CAP_CHACHA20,
        .client_id = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                      0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10}
    };
    uint8_t buffer[HELLO_PAYLOAD_SIZE];
    HelloPayload result;

    size_t written = serialize_hello(&orig, buffer, sizeof(buffer));
    ASSERT_EQ(written, HELLO_PAYLOAD_SIZE);

    int ret = deserialize_hello(buffer, sizeof(buffer), &result);
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(result.min_version, orig.min_version);
    ASSERT_EQ(result.max_version, orig.max_version);
    ASSERT_EQ(result.capabilities, orig.capabilities);
    ASSERT_MEM_EQ(result.client_id, orig.client_id, CLIENT_ID_SIZE);
}

TEST(test_key_exchange_roundtrip)
{
    KeyExchangePayload orig = {
        .cipher = CIPHER_AES_GCM,
        .reserved = 0,
        .key_length = PUBLIC_KEY_SIZE,
        .public_key = {0}
    };
    for (int i = 0; i < PUBLIC_KEY_SIZE; i++)
        orig.public_key[i] = (uint8_t)i;

    uint8_t buffer[KEY_EXCHANGE_PAYLOAD_SIZE];
    KeyExchangePayload result;

    size_t written = serialize_key_exchange(&orig, buffer, sizeof(buffer));
    ASSERT_EQ(written, KEY_EXCHANGE_PAYLOAD_SIZE);

    int ret = deserialize_key_exchange(buffer, sizeof(buffer), &result);
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(result.cipher, orig.cipher);
    ASSERT_EQ(result.key_length, orig.key_length);
    ASSERT_MEM_EQ(result.public_key, orig.public_key, PUBLIC_KEY_SIZE);
}

TEST(test_file_info_roundtrip)
{
    uint8_t buffer[256];
    char filename[] = "test_file.txt";
    uint8_t file_hash[HASH_SIZE];
    for (int i = 0; i < HASH_SIZE; i++)
        file_hash[i] = (uint8_t)(i * 2);

    uint8_t temp[256];
    memset(temp, 0, sizeof(temp));
    FileInfoPayload *orig = (FileInfoPayload *)temp;
    orig->file_size = 1024 * 1024;
    orig->chunk_size = CHUNK_SIZE;
    orig->total_chunks = 4;
    orig->filename_length = strlen(filename);
    orig->reserved = 0;
    memcpy(orig->file_hash, file_hash, HASH_SIZE);
    memcpy(orig->filename, filename, strlen(filename));

    size_t written = serialize_file_info(orig, buffer, sizeof(buffer));
    ASSERT_EQ(written, FILE_INFO_FIXED_SIZE + strlen(filename));

    FileInfoPayload result;
    char filename_out[256];
    int ret = deserialize_file_info(buffer, written, &result, filename_out, sizeof(filename_out));
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(result.file_size, orig->file_size);
    ASSERT_EQ(result.chunk_size, orig->chunk_size);
    ASSERT_EQ(result.total_chunks, orig->total_chunks);
    ASSERT_EQ(result.filename_length, orig->filename_length);
    ASSERT_MEM_EQ(result.file_hash, orig->file_hash, HASH_SIZE);
    ASSERT_MEM_EQ(filename_out, filename, strlen(filename));
}

TEST(test_file_info_ack_roundtrip)
{
    FileInfoAckPayload orig = {
        .status = FILE_STATUS_RESUME,
        .reserved = {0, 0, 0},
        .resume_from = 42
    };
    uint8_t buffer[FILE_INFO_ACK_PAYLOAD_SIZE];
    FileInfoAckPayload result;

    size_t written = serialize_file_info_ack(&orig, buffer, sizeof(buffer));
    ASSERT_EQ(written, FILE_INFO_ACK_PAYLOAD_SIZE);

    int ret = deserialize_file_info_ack(buffer, sizeof(buffer), &result);
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(result.status, orig.status);
    ASSERT_EQ(result.resume_from, orig.resume_from);
}

TEST(test_chunk_roundtrip)
{
    uint8_t data[] = {0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE};
    uint8_t chunk_hash[HASH_SIZE];
    for (int i = 0; i < HASH_SIZE; i++)
        chunk_hash[i] = (uint8_t)i;

    ChunkPayload orig;
    orig.chunk_index = 5;
    orig.chunk_size = sizeof(data);
    memcpy(orig.chunk_hash, chunk_hash, HASH_SIZE);

    uint8_t buffer[256];
    size_t written = serialize_chunk(&orig, data, sizeof(data), buffer, sizeof(buffer));
    ASSERT_EQ(written, CHUNK_FIXED_SIZE + sizeof(data));

    ChunkPayload result;
    uint8_t data_out[256];
    int ret = deserialize_chunk(buffer, written, &result, data_out, sizeof(data_out));
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(result.chunk_index, orig.chunk_index);
    ASSERT_EQ(result.chunk_size, orig.chunk_size);
    ASSERT_MEM_EQ(result.chunk_hash, orig.chunk_hash, HASH_SIZE);
    ASSERT_MEM_EQ(data_out, data, sizeof(data));
}

TEST(test_chunk_ack_roundtrip)
{
    ChunkAckPayload orig = {
        .chunk_index = 123,
        .status = CHUNK_STATUS_OK,
        .reserved = {0, 0, 0}
    };
    uint8_t buffer[CHUNK_ACK_PAYLOAD_SIZE];
    ChunkAckPayload result;

    size_t written = serialize_chunk_ack(&orig, buffer, sizeof(buffer));
    ASSERT_EQ(written, CHUNK_ACK_PAYLOAD_SIZE);

    int ret = deserialize_chunk_ack(buffer, sizeof(buffer), &result);
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(result.chunk_index, orig.chunk_index);
    ASSERT_EQ(result.status, orig.status);
}

TEST(test_transfer_complete_roundtrip)
{
    TransferCompletePayload orig = {
        .total_chunks_sent = 100,
        .total_bytes_sent = 26214400
    };
    uint8_t buffer[TRANSFER_COMPLETE_PAYLOAD_SIZE];
    TransferCompletePayload result;

    size_t written = serialize_transfer_complete(&orig, buffer, sizeof(buffer));
    ASSERT_EQ(written, TRANSFER_COMPLETE_PAYLOAD_SIZE);

    int ret = deserialize_transfer_complete(buffer, sizeof(buffer), &result);
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(result.total_chunks_sent, orig.total_chunks_sent);
    ASSERT_EQ(result.total_bytes_sent, orig.total_bytes_sent);
}

TEST(test_transfer_verified_roundtrip)
{
    TransferVerifiedPayload orig = {
        .status = 0,
        .reserved = {0, 0, 0}
    };
    uint8_t buffer[TRANSFER_VERIFIED_PAYLOAD_SIZE];
    TransferVerifiedPayload result;

    size_t written = serialize_transfer_verified(&orig, buffer, sizeof(buffer));
    ASSERT_EQ(written, TRANSFER_VERIFIED_PAYLOAD_SIZE);

    int ret = deserialize_transfer_verified(buffer, sizeof(buffer), &result);
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(result.status, orig.status);
}

TEST(test_error_roundtrip)
{
    char msg[] = "File not found";
    uint8_t buffer[256];

    uint8_t temp[256];
    ErrorPayload *orig = (ErrorPayload *)temp;
    orig->error_code = ERR_FILE_NOT_FOUND;
    orig->error_level = LEVEL_ERROR;
    orig->message_length = strlen(msg);
    memcpy(orig->message, msg, strlen(msg));

    size_t written = serialize_error(orig, buffer, sizeof(buffer));
    ASSERT_EQ(written, ERROR_FIXED_SIZE + strlen(msg));

    ErrorPayload result;
    char message_out[256];
    int ret = deserialize_error(buffer, written, &result, message_out, sizeof(message_out));
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(result.error_code, orig->error_code);
    ASSERT_EQ(result.error_level, orig->error_level);
    ASSERT_EQ(result.message_length, orig->message_length);
}

TEST(test_large_values)
{
    TransferCompletePayload orig = {
        .total_chunks_sent = 0xFFFFFFFF,
        .total_bytes_sent = 0xFFFFFFFFFFFFFFFF
    };
    uint8_t buffer[TRANSFER_COMPLETE_PAYLOAD_SIZE];
    TransferCompletePayload result;

    serialize_transfer_complete(&orig, buffer, sizeof(buffer));
    deserialize_transfer_complete(buffer, sizeof(buffer), &result);

    ASSERT_EQ(result.total_chunks_sent, orig.total_chunks_sent);
    ASSERT_EQ(result.total_bytes_sent, orig.total_bytes_sent);
}

int main(void)
{
    printf("=== Message Serialization Tests ===\n\n");

    RUN_TEST(test_header_roundtrip);
    RUN_TEST(test_header_little_endian);
    RUN_TEST(test_header_buffer_too_small);
    RUN_TEST(test_hello_roundtrip);
    RUN_TEST(test_key_exchange_roundtrip);
    RUN_TEST(test_file_info_roundtrip);
    RUN_TEST(test_file_info_ack_roundtrip);
    RUN_TEST(test_chunk_roundtrip);
    RUN_TEST(test_chunk_ack_roundtrip);
    RUN_TEST(test_transfer_complete_roundtrip);
    RUN_TEST(test_transfer_verified_roundtrip);
    RUN_TEST(test_error_roundtrip);
    RUN_TEST(test_large_values);

    printf("\n=== Results ===\n");
    printf("Passed: %d\n", tests_passed);
    printf("Failed: %d\n", tests_failed);

    return tests_failed > 0 ? 1 : 0;
}
