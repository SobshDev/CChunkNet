#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <signal.h>
#include "../src/network/socket.h"
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
        printf("FAILED\n  Expected: %d, Got: %d\n", (int)(b), (int)(a)); \
        tests_failed++; \
        return; \
    } \
} while(0)

#define ASSERT_GE(a, b) do { \
    if ((a) < (b)) { \
        printf("FAILED\n  Expected >= %d, Got: %d\n", (int)(b), (int)(a)); \
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

#define TEST_PORT 14200

TEST(test_listen_and_close)
{
    int server_fd = socket_listen(TEST_PORT);
    ASSERT_GE(server_fd, 0);
    socket_close_fd(server_fd);
}

TEST(test_listen_reuse_port)
{
    int server_fd1 = socket_listen(TEST_PORT + 1);
    ASSERT_GE(server_fd1, 0);
    socket_close_fd(server_fd1);

    int server_fd2 = socket_listen(TEST_PORT + 1);
    ASSERT_GE(server_fd2, 0);
    socket_close_fd(server_fd2);
}

TEST(test_connect_accept)
{
    int server_fd = socket_listen(TEST_PORT + 2);
    ASSERT_GE(server_fd, 0);

    pid_t pid = fork();
    if (pid == 0) {
        Socket client;
        uint8_t addr[4] = {127, 0, 0, 1};
        usleep(50000);
        int ret = socket_connect(addr, TEST_PORT + 2, &client);
        socket_close(&client);
        exit(ret == 0 ? 0 : 1);
    }

    Socket accepted;
    int ret = socket_accept(server_fd, &accepted);
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(accepted.remote_addr[0], 127);
    ASSERT_EQ(accepted.remote_addr[1], 0);
    ASSERT_EQ(accepted.remote_addr[2], 0);
    ASSERT_EQ(accepted.remote_addr[3], 1);

    socket_close(&accepted);
    socket_close_fd(server_fd);

    int status;
    waitpid(pid, &status, 0);
    ASSERT_EQ(WEXITSTATUS(status), 0);
}

TEST(test_send_recv)
{
    int server_fd = socket_listen(TEST_PORT + 3);
    ASSERT_GE(server_fd, 0);

    pid_t pid = fork();
    if (pid == 0) {
        Socket client;
        uint8_t addr[4] = {127, 0, 0, 1};
        usleep(50000);
        if (socket_connect(addr, TEST_PORT + 3, &client) != 0)
            exit(1);

        char msg[] = "Hello, server!";
        ssize_t sent = socket_send_all(&client, msg, strlen(msg));
        socket_close(&client);
        exit(sent == (ssize_t)strlen(msg) ? 0 : 1);
    }

    Socket accepted;
    ASSERT_EQ(socket_accept(server_fd, &accepted), 0);

    char buf[64];
    ssize_t received = socket_recv(&accepted, buf, sizeof(buf));
    ASSERT_EQ(received, 14);
    ASSERT_MEM_EQ(buf, "Hello, server!", 14);

    socket_close(&accepted);
    socket_close_fd(server_fd);

    int status;
    waitpid(pid, &status, 0);
    ASSERT_EQ(WEXITSTATUS(status), 0);
}

TEST(test_send_recv_large)
{
    int server_fd = socket_listen(TEST_PORT + 4);
    ASSERT_GE(server_fd, 0);

    size_t data_size = 65536;
    uint8_t *send_buf = malloc(data_size);
    uint8_t *recv_buf = malloc(data_size);
    for (size_t i = 0; i < data_size; i++)
        send_buf[i] = (uint8_t)(i & 0xFF);

    pid_t pid = fork();
    if (pid == 0) {
        Socket client;
        uint8_t addr[4] = {127, 0, 0, 1};
        usleep(50000);
        if (socket_connect(addr, TEST_PORT + 4, &client) != 0)
            exit(1);

        ssize_t sent = socket_send_all(&client, send_buf, data_size);
        socket_close(&client);
        free(send_buf);
        free(recv_buf);
        exit(sent == (ssize_t)data_size ? 0 : 1);
    }

    Socket accepted;
    ASSERT_EQ(socket_accept(server_fd, &accepted), 0);

    ssize_t received = socket_recv_all(&accepted, recv_buf, data_size);
    ASSERT_EQ(received, (ssize_t)data_size);
    ASSERT_MEM_EQ(recv_buf, send_buf, data_size);

    socket_close(&accepted);
    socket_close_fd(server_fd);
    free(send_buf);
    free(recv_buf);

    int status;
    waitpid(pid, &status, 0);
    ASSERT_EQ(WEXITSTATUS(status), 0);
}

TEST(test_bidirectional)
{
    int server_fd = socket_listen(TEST_PORT + 5);
    ASSERT_GE(server_fd, 0);

    pid_t pid = fork();
    if (pid == 0) {
        Socket client;
        uint8_t addr[4] = {127, 0, 0, 1};
        usleep(50000);
        if (socket_connect(addr, TEST_PORT + 5, &client) != 0)
            exit(1);

        char msg[] = "ping";
        socket_send_all(&client, msg, 4);

        char buf[64];
        ssize_t received = socket_recv(&client, buf, sizeof(buf));
        socket_close(&client);
        exit(received == 4 && memcmp(buf, "pong", 4) == 0 ? 0 : 1);
    }

    Socket accepted;
    ASSERT_EQ(socket_accept(server_fd, &accepted), 0);

    char buf[64];
    ssize_t received = socket_recv(&accepted, buf, sizeof(buf));
    ASSERT_EQ(received, 4);
    ASSERT_MEM_EQ(buf, "ping", 4);

    char reply[] = "pong";
    ssize_t sent = socket_send_all(&accepted, reply, 4);
    ASSERT_EQ(sent, 4);

    socket_close(&accepted);
    socket_close_fd(server_fd);

    int status;
    waitpid(pid, &status, 0);
    ASSERT_EQ(WEXITSTATUS(status), 0);
}

TEST(test_connection_closed)
{
    int server_fd = socket_listen(TEST_PORT + 6);
    ASSERT_GE(server_fd, 0);

    pid_t pid = fork();
    if (pid == 0) {
        Socket client;
        uint8_t addr[4] = {127, 0, 0, 1};
        usleep(50000);
        socket_connect(addr, TEST_PORT + 6, &client);
        socket_close(&client);
        exit(0);
    }

    Socket accepted;
    ASSERT_EQ(socket_accept(server_fd, &accepted), 0);

    usleep(100000);

    char buf[64];
    ssize_t received = socket_recv(&accepted, buf, sizeof(buf));
    ASSERT_EQ(received, SOCKET_CLOSED);

    socket_close(&accepted);
    socket_close_fd(server_fd);

    int status;
    waitpid(pid, &status, 0);
}

int main(void)
{
    signal(SIGPIPE, SIG_IGN);

    printf("=== Socket Tests ===\n\n");

    RUN_TEST(test_listen_and_close);
    RUN_TEST(test_listen_reuse_port);
    RUN_TEST(test_connect_accept);
    RUN_TEST(test_send_recv);
    RUN_TEST(test_send_recv_large);
    RUN_TEST(test_bidirectional);
    RUN_TEST(test_connection_closed);

    printf("\n=== Results ===\n");
    printf("Passed: %d\n", tests_passed);
    printf("Failed: %d\n", tests_failed);

    return tests_failed > 0 ? 1 : 0;
}
