#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include "../src/file/file.h"
#include "../src/crypto/crypto.h"
#include "../src/const.h"

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
        printf("FAILED\n  Expected: %lld, Got: %lld\n", (long long)(b), (long long)(a)); \
        tests_failed++; \
        return; \
    } \
} while(0)

#define ASSERT_STR_EQ(a, b) do { \
    if (strcmp((a), (b)) != 0) { \
        printf("FAILED\n  Expected: %s, Got: %s\n", (b), (a)); \
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

static char temp_dir[] = "/tmp/chunknet_test_XXXXXX";
static int temp_dir_created = 0;

static void setup(void)
{
    if (!temp_dir_created) {
        if (mkdtemp(temp_dir) == NULL) {
            fprintf(stderr, "Failed to create temp dir\n");
            exit(1);
        }
        temp_dir_created = 1;
    }
}

static void create_test_file(const char *name, size_t size, uint8_t pattern)
{
    char path[512];
    snprintf(path, sizeof(path), "%s/%s", temp_dir, name);

    FILE *f = fopen(path, "wb");
    if (!f) return;

    for (size_t i = 0; i < size; i++) {
        uint8_t byte = (pattern == 0) ? (uint8_t)(i & 0xFF) : pattern;
        fwrite(&byte, 1, 1, f);
    }
    fclose(f);
}

static void cleanup_test_file(const char *name)
{
    char path[512];
    snprintf(path, sizeof(path), "%s/%s", temp_dir, name);
    unlink(path);
}

TEST(test_file_exists)
{
    setup();
    create_test_file("exists_test.bin", 100, 0xAB);

    char path[512];
    snprintf(path, sizeof(path), "%s/exists_test.bin", temp_dir);

    ASSERT_EQ(file_exists(path), 1);
    ASSERT_EQ(file_exists("/nonexistent/path/file.bin"), 0);

    cleanup_test_file("exists_test.bin");
}

TEST(test_file_get_size)
{
    setup();
    create_test_file("size_test.bin", 12345, 0xCD);

    char path[512];
    snprintf(path, sizeof(path), "%s/size_test.bin", temp_dir);

    ASSERT_EQ(file_get_size(path), 12345);

    cleanup_test_file("size_test.bin");
}

TEST(test_file_basename)
{
    ASSERT_STR_EQ(file_basename("/path/to/file.txt"), "file.txt");
    ASSERT_STR_EQ(file_basename("file.txt"), "file.txt");
    ASSERT_STR_EQ(file_basename("/file.txt"), "file.txt");
    ASSERT_STR_EQ(file_basename("./file.txt"), "file.txt");
}

TEST(test_file_compute_hash)
{
    setup();
    create_test_file("hash_test.bin", 0, 0);

    char path[512];
    snprintf(path, sizeof(path), "%s/hash_test.bin", temp_dir);

    FILE *f = fopen(path, "wb");
    fprintf(f, "Hello, World!");
    fclose(f);

    uint8_t hash[CRYPTO_HASH_SIZE];
    ASSERT_EQ(file_compute_hash(path, hash), 0);

    uint8_t expected[CRYPTO_HASH_SIZE] = {
        0xdf, 0xfd, 0x60, 0x21, 0xbb, 0x2b, 0xd5, 0xb0,
        0xaf, 0x67, 0x62, 0x90, 0x80, 0x9e, 0xc3, 0xa5,
        0x31, 0x91, 0xdd, 0x81, 0xc7, 0xf7, 0x0a, 0x4b,
        0x28, 0x68, 0x8a, 0x36, 0x21, 0x82, 0x98, 0x6f
    };
    ASSERT_MEM_EQ(hash, expected, CRYPTO_HASH_SIZE);

    cleanup_test_file("hash_test.bin");
}

TEST(test_reader_open_close)
{
    setup();
    create_test_file("reader_test.bin", 1024, 0);

    char path[512];
    snprintf(path, sizeof(path), "%s/reader_test.bin", temp_dir);

    FileReader reader;
    ASSERT_EQ(file_reader_open(&reader, path, 256), 0);

    ASSERT_EQ(reader.file_size, 1024);
    ASSERT_EQ(reader.chunk_size, 256);
    ASSERT_EQ(reader.total_chunks, 4);
    ASSERT_STR_EQ(reader.filename, "reader_test.bin");

    file_reader_close(&reader);
    cleanup_test_file("reader_test.bin");
}

TEST(test_reader_read_chunks)
{
    setup();
    create_test_file("chunks_test.bin", 1000, 0);

    char path[512];
    snprintf(path, sizeof(path), "%s/chunks_test.bin", temp_dir);

    FileReader reader;
    ASSERT_EQ(file_reader_open(&reader, path, 256), 0);
    ASSERT_EQ(reader.total_chunks, 4);

    uint8_t buffer[256];
    uint32_t chunk_len;
    uint8_t hash[CRYPTO_HASH_SIZE];

    ASSERT_EQ(file_reader_read_chunk(&reader, 0, buffer, &chunk_len, hash), 0);
    ASSERT_EQ(chunk_len, 256);
    ASSERT_EQ(buffer[0], 0);
    ASSERT_EQ(buffer[255], 255);

    ASSERT_EQ(file_reader_read_chunk(&reader, 1, buffer, &chunk_len, hash), 0);
    ASSERT_EQ(chunk_len, 256);

    ASSERT_EQ(file_reader_read_chunk(&reader, 3, buffer, &chunk_len, hash), 0);
    ASSERT_EQ(chunk_len, 232);

    ASSERT_EQ(file_reader_read_chunk(&reader, 4, buffer, &chunk_len, hash), -1);

    file_reader_close(&reader);
    cleanup_test_file("chunks_test.bin");
}

TEST(test_reader_chunk_hash)
{
    setup();
    create_test_file("hash_chunk_test.bin", 100, 0xAA);

    char path[512];
    snprintf(path, sizeof(path), "%s/hash_chunk_test.bin", temp_dir);

    FileReader reader;
    file_reader_open(&reader, path, 256);

    uint8_t buffer[256];
    uint32_t chunk_len;
    uint8_t hash[CRYPTO_HASH_SIZE];

    file_reader_read_chunk(&reader, 0, buffer, &chunk_len, hash);

    uint8_t expected_hash[CRYPTO_HASH_SIZE];
    crypto_sha256(expected_hash, buffer, chunk_len);
    ASSERT_MEM_EQ(hash, expected_hash, CRYPTO_HASH_SIZE);

    file_reader_close(&reader);
    cleanup_test_file("hash_chunk_test.bin");
}

TEST(test_writer_create_close)
{
    setup();

    uint8_t hash[CRYPTO_HASH_SIZE] = {0};
    FileWriter writer;

    ASSERT_EQ(file_writer_create(&writer, temp_dir, "writer_test.bin", 1024, 256, hash), 0);
    ASSERT_EQ(writer.file_size, 1024);
    ASSERT_EQ(writer.chunk_size, 256);
    ASSERT_EQ(writer.total_chunks, 4);
    ASSERT_EQ(writer.chunks_written, 0);

    file_writer_close(&writer);

    char path[512];
    snprintf(path, sizeof(path), "%s/writer_test.bin", temp_dir);
    ASSERT_EQ(file_exists(path), 1);
    ASSERT_EQ(file_get_size(path), 1024);

    cleanup_test_file("writer_test.bin");
}

TEST(test_writer_write_chunks)
{
    setup();

    uint8_t data[256];
    for (int i = 0; i < 256; i++)
        data[i] = (uint8_t)i;

    uint8_t chunk_hash[CRYPTO_HASH_SIZE];
    crypto_sha256(chunk_hash, data, 256);

    uint8_t file_hash[CRYPTO_HASH_SIZE] = {0};
    FileWriter writer;
    file_writer_create(&writer, temp_dir, "write_chunks_test.bin", 256, 256, file_hash);

    ASSERT_EQ(file_writer_write_chunk(&writer, 0, data, 256, chunk_hash), 0);
    ASSERT_EQ(writer.chunks_written, 1);

    file_writer_close(&writer);

    char path[512];
    snprintf(path, sizeof(path), "%s/write_chunks_test.bin", temp_dir);

    uint8_t read_data[256];
    FILE *f = fopen(path, "rb");
    fread(read_data, 1, 256, f);
    fclose(f);

    ASSERT_MEM_EQ(read_data, data, 256);

    cleanup_test_file("write_chunks_test.bin");
}

TEST(test_writer_bad_chunk_hash)
{
    setup();

    uint8_t data[100];
    memset(data, 0xAB, 100);

    uint8_t wrong_hash[CRYPTO_HASH_SIZE] = {0};
    uint8_t file_hash[CRYPTO_HASH_SIZE] = {0};

    FileWriter writer;
    file_writer_create(&writer, temp_dir, "bad_hash_test.bin", 100, 256, file_hash);

    int ret = file_writer_write_chunk(&writer, 0, data, 100, wrong_hash);
    ASSERT_EQ(ret, -2);

    file_writer_close(&writer);
    cleanup_test_file("bad_hash_test.bin");
}

TEST(test_full_transfer_simulation)
{
    setup();
    create_test_file("transfer_src.bin", 700, 0);

    char src_path[512], dst_path[512];
    snprintf(src_path, sizeof(src_path), "%s/transfer_src.bin", temp_dir);

    FileReader reader;
    ASSERT_EQ(file_reader_open(&reader, src_path, 256), 0);

    FileWriter writer;
    ASSERT_EQ(file_writer_create(&writer, temp_dir, "transfer_dst.bin",
                                  reader.file_size, reader.chunk_size,
                                  reader.file_hash), 0);

    uint8_t buffer[256];
    uint32_t chunk_len;
    uint8_t chunk_hash[CRYPTO_HASH_SIZE];

    for (uint32_t i = 0; i < reader.total_chunks; i++) {
        ASSERT_EQ(file_reader_read_chunk(&reader, i, buffer, &chunk_len, chunk_hash), 0);
        ASSERT_EQ(file_writer_write_chunk(&writer, i, buffer, chunk_len, chunk_hash), 0);
    }

    ASSERT_EQ(file_writer_verify(&writer), 0);

    file_reader_close(&reader);
    file_writer_close(&writer);

    snprintf(dst_path, sizeof(dst_path), "%s/transfer_dst.bin", temp_dir);

    uint8_t src_hash[CRYPTO_HASH_SIZE], dst_hash[CRYPTO_HASH_SIZE];
    file_compute_hash(src_path, src_hash);
    file_compute_hash(dst_path, dst_hash);
    ASSERT_MEM_EQ(src_hash, dst_hash, CRYPTO_HASH_SIZE);

    cleanup_test_file("transfer_src.bin");
    cleanup_test_file("transfer_dst.bin");
}

TEST(test_empty_file)
{
    setup();
    create_test_file("empty.bin", 0, 0);

    char path[512];
    snprintf(path, sizeof(path), "%s/empty.bin", temp_dir);

    FileReader reader;
    ASSERT_EQ(file_reader_open(&reader, path, 256), 0);
    ASSERT_EQ(reader.file_size, 0);
    ASSERT_EQ(reader.total_chunks, 0);

    file_reader_close(&reader);
    cleanup_test_file("empty.bin");
}

TEST(test_large_file_chunks)
{
    setup();
    size_t size = 1024 * 1024;
    create_test_file("large.bin", size, 0);

    char path[512];
    snprintf(path, sizeof(path), "%s/large.bin", temp_dir);

    FileReader reader;
    ASSERT_EQ(file_reader_open(&reader, path, CHUNK_SIZE), 0);
    ASSERT_EQ(reader.file_size, size);
    ASSERT_EQ(reader.total_chunks, 4);

    uint8_t *buffer = malloc(CHUNK_SIZE);
    uint32_t chunk_len;
    uint8_t hash[CRYPTO_HASH_SIZE];

    for (uint32_t i = 0; i < reader.total_chunks; i++) {
        ASSERT_EQ(file_reader_read_chunk(&reader, i, buffer, &chunk_len, hash), 0);
        ASSERT_EQ(chunk_len, CHUNK_SIZE);
    }

    free(buffer);
    file_reader_close(&reader);
    cleanup_test_file("large.bin");
}

TEST(test_writer_verify_failure)
{
    setup();

    uint8_t wrong_file_hash[CRYPTO_HASH_SIZE];
    memset(wrong_file_hash, 0xFF, CRYPTO_HASH_SIZE);

    uint8_t data[100];
    memset(data, 0xAB, 100);

    uint8_t chunk_hash[CRYPTO_HASH_SIZE];
    crypto_sha256(chunk_hash, data, 100);

    FileWriter writer;
    file_writer_create(&writer, temp_dir, "verify_fail.bin", 100, 256, wrong_file_hash);
    file_writer_write_chunk(&writer, 0, data, 100, chunk_hash);

    ASSERT_EQ(file_writer_verify(&writer), -2);

    file_writer_close(&writer);
    cleanup_test_file("verify_fail.bin");
}

int main(void)
{
    crypto_init();

    printf("=== File Operations Tests ===\n\n");

    RUN_TEST(test_file_exists);
    RUN_TEST(test_file_get_size);
    RUN_TEST(test_file_basename);
    RUN_TEST(test_file_compute_hash);
    RUN_TEST(test_reader_open_close);
    RUN_TEST(test_reader_read_chunks);
    RUN_TEST(test_reader_chunk_hash);
    RUN_TEST(test_writer_create_close);
    RUN_TEST(test_writer_write_chunks);
    RUN_TEST(test_writer_bad_chunk_hash);
    RUN_TEST(test_full_transfer_simulation);
    RUN_TEST(test_empty_file);
    RUN_TEST(test_large_file_chunks);
    RUN_TEST(test_writer_verify_failure);

    if (temp_dir_created) {
        rmdir(temp_dir);
    }

    printf("\n=== Results ===\n");
    printf("Passed: %d\n", tests_passed);
    printf("Failed: %d\n", tests_failed);

    return tests_failed > 0 ? 1 : 0;
}
