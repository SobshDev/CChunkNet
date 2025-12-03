#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "../src/cli/cli.h"
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
        printf("FAILED\n  Expected: %d, Got: %d\n", (int)(b), (int)(a)); \
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

// Test: "chunknet send 192.168.1.1 /path/to/file" with default port
TEST(test_send_basic)
{
    char *av[] = {"chunknet", "send", "192.168.1.1", "/path/to/file", NULL};
    int ac = 4;

    CLI_T cli = parse(ac, av);

    ASSERT_EQ(cli.operation_type, 1);
    ASSERT_EQ(cli.address[0], 192);
    ASSERT_EQ(cli.address[1], 168);
    ASSERT_EQ(cli.address[2], 1);
    ASSERT_EQ(cli.address[3], 1);
    ASSERT_EQ(cli.port, DEFAULT_PORT);
    ASSERT_STR_EQ(cli.path, "/path/to/file");
}

// Test: "chunknet s 10.0.0.1 /file" shorthand
TEST(test_send_shorthand)
{
    char *av[] = {"chunknet", "s", "10.0.0.1", "/file", NULL};
    int ac = 4;

    CLI_T cli = parse(ac, av);

    ASSERT_EQ(cli.operation_type, 1);
    ASSERT_EQ(cli.address[0], 10);
    ASSERT_EQ(cli.address[1], 0);
    ASSERT_EQ(cli.address[2], 0);
    ASSERT_EQ(cli.address[3], 1);
    ASSERT_EQ(cli.port, DEFAULT_PORT);
}

// Test: "chunknet send 127.0.0.1 /file --port 8080" custom port
TEST(test_send_custom_port)
{
    char *av[] = {"chunknet", "send", "127.0.0.1", "/file", "--port", "8080", NULL};
    int ac = 6;

    CLI_T cli = parse(ac, av);

    ASSERT_EQ(cli.operation_type, 1);
    ASSERT_EQ(cli.address[0], 127);
    ASSERT_EQ(cli.address[1], 0);
    ASSERT_EQ(cli.address[2], 0);
    ASSERT_EQ(cli.address[3], 1);
    ASSERT_EQ(cli.port, 8080);
}

// Test: case insensitive "SEND"
TEST(test_send_case_insensitive)
{
    char *av[] = {"chunknet", "SEND", "192.168.1.1", "/file", NULL};
    int ac = 4;

    CLI_T cli = parse(ac, av);

    ASSERT_EQ(cli.operation_type, 1);
}

// Test: case insensitive "S"
TEST(test_send_shorthand_case_insensitive)
{
    char *av[] = {"chunknet", "S", "192.168.1.1", "/file", NULL};
    int ac = 4;

    CLI_T cli = parse(ac, av);

    ASSERT_EQ(cli.operation_type, 1);
}

// Test: missing file path
TEST(test_send_missing_file)
{
    char *av[] = {"chunknet", "send", "192.168.1.1", NULL};
    int ac = 3;

    CLI_T cli = parse(ac, av);

    ASSERT_EQ(cli.operation_type, 0);
}

// Test: missing IP address
TEST(test_send_missing_ip)
{
    char *av[] = {"chunknet", "send", NULL};
    int ac = 2;

    CLI_T cli = parse(ac, av);

    ASSERT_EQ(cli.operation_type, 0);
}

// Test: invalid IP address (wrong format)
TEST(test_send_invalid_ip_format)
{
    char *av[] = {"chunknet", "send", "192.168.1", "/file", NULL};
    int ac = 4;

    CLI_T cli = parse(ac, av);

    ASSERT_EQ(cli.operation_type, 0);
}

// Test: invalid IP address (out of range)
TEST(test_send_invalid_ip_range)
{
    char *av[] = {"chunknet", "send", "256.168.1.1", "/file", NULL};
    int ac = 4;

    CLI_T cli = parse(ac, av);

    ASSERT_EQ(cli.operation_type, 0);
}

// Test: invalid IP address (negative)
TEST(test_send_invalid_ip_negative)
{
    char *av[] = {"chunknet", "send", "-1.168.1.1", "/file", NULL};
    int ac = 4;

    CLI_T cli = parse(ac, av);

    ASSERT_EQ(cli.operation_type, 0);
}

// Test: invalid IP address (text)
TEST(test_send_invalid_ip_text)
{
    char *av[] = {"chunknet", "send", "localhost", "/file", NULL};
    int ac = 4;

    CLI_T cli = parse(ac, av);

    ASSERT_EQ(cli.operation_type, 0);
}

// Test: too many arguments
TEST(test_send_too_many_args)
{
    char *av[] = {"chunknet", "send", "192.168.1.1", "/file", "--port", "8080", "extra", NULL};
    int ac = 7;

    CLI_T cli = parse(ac, av);

    ASSERT_EQ(cli.operation_type, 0);
}

// Test: invalid port parameter
TEST(test_send_invalid_param)
{
    char *av[] = {"chunknet", "send", "192.168.1.1", "/file", "--invalid", "8080", NULL};
    int ac = 6;

    CLI_T cli = parse(ac, av);

    ASSERT_EQ(cli.operation_type, 0);
}

// Test: incomplete --port argument
TEST(test_send_incomplete_port)
{
    char *av[] = {"chunknet", "send", "192.168.1.1", "/file", "--port", NULL};
    int ac = 5;

    CLI_T cli = parse(ac, av);

    ASSERT_EQ(cli.operation_type, 0);
}

// Test: port = 0 (invalid)
TEST(test_send_port_zero)
{
    char *av[] = {"chunknet", "send", "192.168.1.1", "/file", "--port", "0", NULL};
    int ac = 6;

    CLI_T cli = parse(ac, av);

    ASSERT_EQ(cli.operation_type, 0);
}

// Test: port negative (invalid)
TEST(test_send_port_negative)
{
    char *av[] = {"chunknet", "send", "192.168.1.1", "/file", "--port", "-1", NULL};
    int ac = 6;

    CLI_T cli = parse(ac, av);

    ASSERT_EQ(cli.operation_type, 0);
}

// Test: port > 65535 (invalid)
TEST(test_send_port_too_high)
{
    char *av[] = {"chunknet", "send", "192.168.1.1", "/file", "--port", "65536", NULL};
    int ac = 6;

    CLI_T cli = parse(ac, av);

    ASSERT_EQ(cli.operation_type, 0);
}

// Test: port = 65535 (valid max)
TEST(test_send_port_max_valid)
{
    char *av[] = {"chunknet", "send", "192.168.1.1", "/file", "--port", "65535", NULL};
    int ac = 6;

    CLI_T cli = parse(ac, av);

    ASSERT_EQ(cli.operation_type, 1);
    ASSERT_EQ(cli.port, 65535);
}

// Test: port = 1 (valid min)
TEST(test_send_port_min_valid)
{
    char *av[] = {"chunknet", "send", "192.168.1.1", "/file", "--port", "1", NULL};
    int ac = 6;

    CLI_T cli = parse(ac, av);

    ASSERT_EQ(cli.operation_type, 1);
    ASSERT_EQ(cli.port, 1);
}

// Test: non-numeric port
TEST(test_send_port_non_numeric)
{
    char *av[] = {"chunknet", "send", "192.168.1.1", "/file", "--port", "abc", NULL};
    int ac = 6;

    CLI_T cli = parse(ac, av);

    ASSERT_EQ(cli.operation_type, 0);
}

// Test: IP 0.0.0.0 (valid)
TEST(test_send_ip_zeros)
{
    char *av[] = {"chunknet", "send", "0.0.0.0", "/file", NULL};
    int ac = 4;

    CLI_T cli = parse(ac, av);

    ASSERT_EQ(cli.operation_type, 1);
    ASSERT_EQ(cli.address[0], 0);
    ASSERT_EQ(cli.address[1], 0);
    ASSERT_EQ(cli.address[2], 0);
    ASSERT_EQ(cli.address[3], 0);
}

// Test: IP 255.255.255.255 (valid)
TEST(test_send_ip_max)
{
    char *av[] = {"chunknet", "send", "255.255.255.255", "/file", NULL};
    int ac = 4;

    CLI_T cli = parse(ac, av);

    ASSERT_EQ(cli.operation_type, 1);
    ASSERT_EQ(cli.address[0], 255);
    ASSERT_EQ(cli.address[1], 255);
    ASSERT_EQ(cli.address[2], 255);
    ASSERT_EQ(cli.address[3], 255);
}

int main(void)
{
    printf("=== CLI Parse Send Tests ===\n\n");

    // Basic send tests
    RUN_TEST(test_send_basic);
    RUN_TEST(test_send_shorthand);
    RUN_TEST(test_send_custom_port);

    // Case insensitivity tests
    RUN_TEST(test_send_case_insensitive);
    RUN_TEST(test_send_shorthand_case_insensitive);

    // Missing arguments tests
    RUN_TEST(test_send_missing_file);
    RUN_TEST(test_send_missing_ip);

    // IP validation tests
    RUN_TEST(test_send_invalid_ip_format);
    RUN_TEST(test_send_invalid_ip_range);
    RUN_TEST(test_send_invalid_ip_negative);
    RUN_TEST(test_send_invalid_ip_text);
    RUN_TEST(test_send_ip_zeros);
    RUN_TEST(test_send_ip_max);

    // Error handling tests
    RUN_TEST(test_send_too_many_args);
    RUN_TEST(test_send_invalid_param);
    RUN_TEST(test_send_incomplete_port);

    // Port validation tests
    RUN_TEST(test_send_port_zero);
    RUN_TEST(test_send_port_negative);
    RUN_TEST(test_send_port_too_high);
    RUN_TEST(test_send_port_max_valid);
    RUN_TEST(test_send_port_min_valid);
    RUN_TEST(test_send_port_non_numeric);

    printf("\n=== Results ===\n");
    printf("Passed: %d\n", tests_passed);
    printf("Failed: %d\n", tests_failed);

    return tests_failed > 0 ? 1 : 0;
}