#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <signal.h>
#include "../src/protocol/sender.h"
#include "../src/protocol/receiver.h"
#include "../src/file/file.h"
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

#define ASSERT_MEM_EQ(a, b, len) do { \
    if (memcmp((a), (b), (len)) != 0) { \
        printf("FAILED\n  Memory mismatch\n"); \
        tests_failed++; \
        return; \
    } \
} while(0)

static char temp_dir[] = "/tmp/chunknet_transfer_XXXXXX";
static int temp_dir_created = 0;

#define TEST_PORT 14300

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

static void create_test_file(const char *name, size_t size)
{
    char path[512];
    snprintf(path, sizeof(path), "%s/%s", temp_dir, name);

    FILE *f = fopen(path, "wb");
    if (!f) return;

    for (size_t i = 0; i < size; i++) {
        uint8_t byte = (uint8_t)(i & 0xFF);
        fwrite(&byte, 1, 1, f);
    }
    fclose(f);
}

static void cleanup_file(const char *name)
{
    char path[512];
    snprintf(path, sizeof(path), "%s/%s", temp_dir, name);
    unlink(path);
}

TEST(test_small_file_transfer)
{
    setup();
    create_test_file("small.bin", 1000);

    char src_path[512], dst_dir[512];
    snprintf(src_path, sizeof(src_path), "%s/small.bin", temp_dir);
    snprintf(dst_dir, sizeof(dst_dir), "%s/recv", temp_dir);
    mkdir(dst_dir, 0755);

    pid_t pid = fork();
    if (pid == 0) {
        Receiver receiver;
        receiver_init(&receiver, dst_dir);
        receiver_listen(&receiver, TEST_PORT);
        receiver_accept(&receiver);
        int ret = receiver_receive_file(&receiver);
        receiver_cleanup(&receiver);
        exit(ret == 0 ? 0 : 1);
    }

    usleep(100000);

    Sender sender;
    sender_init(&sender);
    uint8_t addr[4] = {127, 0, 0, 1};
    ASSERT_EQ(sender_connect(&sender, addr, TEST_PORT), 0);
    ASSERT_EQ(sender_send_file(&sender, src_path), 0);
    sender_cleanup(&sender);

    int status;
    waitpid(pid, &status, 0);
    ASSERT_EQ(WEXITSTATUS(status), 0);

    char dst_path[512];
    snprintf(dst_path, sizeof(dst_path), "%s/recv/small.bin", temp_dir);
    ASSERT_EQ(file_exists(dst_path), 1);
    ASSERT_EQ(file_get_size(dst_path), 1000);

    uint8_t src_hash[CRYPTO_HASH_SIZE], dst_hash[CRYPTO_HASH_SIZE];
    file_compute_hash(src_path, src_hash);
    file_compute_hash(dst_path, dst_hash);
    ASSERT_MEM_EQ(src_hash, dst_hash, CRYPTO_HASH_SIZE);

    cleanup_file("small.bin");
    cleanup_file("recv/small.bin");
    rmdir(dst_dir);
}

TEST(test_multi_chunk_transfer)
{
    setup();
    create_test_file("multi.bin", 700000);

    char src_path[512], dst_dir[512];
    snprintf(src_path, sizeof(src_path), "%s/multi.bin", temp_dir);
    snprintf(dst_dir, sizeof(dst_dir), "%s/recv2", temp_dir);
    mkdir(dst_dir, 0755);

    pid_t pid = fork();
    if (pid == 0) {
        Receiver receiver;
        receiver_init(&receiver, dst_dir);
        receiver_listen(&receiver, TEST_PORT + 1);
        receiver_accept(&receiver);
        int ret = receiver_receive_file(&receiver);
        receiver_cleanup(&receiver);
        exit(ret == 0 ? 0 : 1);
    }

    usleep(100000);

    Sender sender;
    sender_init(&sender);
    uint8_t addr[4] = {127, 0, 0, 1};
    ASSERT_EQ(sender_connect(&sender, addr, TEST_PORT + 1), 0);
    ASSERT_EQ(sender_send_file(&sender, src_path), 0);
    sender_cleanup(&sender);

    int status;
    waitpid(pid, &status, 0);
    ASSERT_EQ(WEXITSTATUS(status), 0);

    char dst_path[512];
    snprintf(dst_path, sizeof(dst_path), "%s/recv2/multi.bin", temp_dir);

    uint8_t src_hash[CRYPTO_HASH_SIZE], dst_hash[CRYPTO_HASH_SIZE];
    file_compute_hash(src_path, src_hash);
    file_compute_hash(dst_path, dst_hash);
    ASSERT_MEM_EQ(src_hash, dst_hash, CRYPTO_HASH_SIZE);

    cleanup_file("multi.bin");
    cleanup_file("recv2/multi.bin");
    rmdir(dst_dir);
}

TEST(test_exact_chunk_boundary)
{
    setup();
    create_test_file("exact.bin", 262144);

    char src_path[512], dst_dir[512];
    snprintf(src_path, sizeof(src_path), "%s/exact.bin", temp_dir);
    snprintf(dst_dir, sizeof(dst_dir), "%s/recv3", temp_dir);
    mkdir(dst_dir, 0755);

    pid_t pid = fork();
    if (pid == 0) {
        Receiver receiver;
        receiver_init(&receiver, dst_dir);
        receiver_listen(&receiver, TEST_PORT + 2);
        receiver_accept(&receiver);
        int ret = receiver_receive_file(&receiver);
        receiver_cleanup(&receiver);
        exit(ret == 0 ? 0 : 1);
    }

    usleep(100000);

    Sender sender;
    sender_init(&sender);
    uint8_t addr[4] = {127, 0, 0, 1};
    ASSERT_EQ(sender_connect(&sender, addr, TEST_PORT + 2), 0);
    ASSERT_EQ(sender_send_file(&sender, src_path), 0);
    sender_cleanup(&sender);

    int status;
    waitpid(pid, &status, 0);
    ASSERT_EQ(WEXITSTATUS(status), 0);

    char dst_path[512];
    snprintf(dst_path, sizeof(dst_path), "%s/recv3/exact.bin", temp_dir);

    uint8_t src_hash[CRYPTO_HASH_SIZE], dst_hash[CRYPTO_HASH_SIZE];
    file_compute_hash(src_path, src_hash);
    file_compute_hash(dst_path, dst_hash);
    ASSERT_MEM_EQ(src_hash, dst_hash, CRYPTO_HASH_SIZE);

    cleanup_file("exact.bin");
    cleanup_file("recv3/exact.bin");
    rmdir(dst_dir);
}

int main(void)
{
    signal(SIGPIPE, SIG_IGN);
    crypto_init();

    printf("=== File Transfer Integration Tests ===\n\n");

    RUN_TEST(test_small_file_transfer);
    RUN_TEST(test_multi_chunk_transfer);
    RUN_TEST(test_exact_chunk_boundary);

    if (temp_dir_created) {
        rmdir(temp_dir);
    }

    printf("\n=== Results ===\n");
    printf("Passed: %d\n", tests_passed);
    printf("Failed: %d\n", tests_failed);

    return tests_failed > 0 ? 1 : 0;
}
