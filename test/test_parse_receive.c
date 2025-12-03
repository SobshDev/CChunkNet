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

// Test: "chunknet receive" with default port
TEST(test_receive_default_port)
{
    char *av[] = {"chunknet", "receive", NULL};
    int ac = 2;

    CLI_T cli = parse(ac, av);

    ASSERT_EQ(cli.operation_type, 2);
    ASSERT_EQ(cli.port, DEFAULT_PORT);
}

// Test: "chunknet r" shorthand with default port
TEST(test_receive_shorthand_default_port)
{
    char *av[] = {"chunknet", "r", NULL};
    int ac = 2;

    CLI_T cli = parse(ac, av);

    ASSERT_EQ(cli.operation_type, 2);
    ASSERT_EQ(cli.port, DEFAULT_PORT);
}

// Test: "chunknet receive --port 8080" custom port
TEST(test_receive_custom_port)
{
    char *av[] = {"chunknet", "receive", "--port", "8080", NULL};
    int ac = 4;

    CLI_T cli = parse(ac, av);

    ASSERT_EQ(cli.operation_type, 2);
    ASSERT_EQ(cli.port, 8080);
}

// Test: "chunknet r --port 1234" shorthand with custom port
TEST(test_receive_shorthand_custom_port)
{
    char *av[] = {"chunknet", "r", "--port", "1234", NULL};
    int ac = 4;

    CLI_T cli = parse(ac, av);

    ASSERT_EQ(cli.operation_type, 2);
    ASSERT_EQ(cli.port, 1234);
}

// Test: case insensitive "RECEIVE"
TEST(test_receive_case_insensitive)
{
    char *av[] = {"chunknet", "RECEIVE", NULL};
    int ac = 2;

    CLI_T cli = parse(ac, av);

    ASSERT_EQ(cli.operation_type, 2);
    ASSERT_EQ(cli.port, DEFAULT_PORT);
}

// Test: case insensitive "R"
TEST(test_receive_shorthand_case_insensitive)
{
    char *av[] = {"chunknet", "R", NULL};
    int ac = 2;

    CLI_T cli = parse(ac, av);

    ASSERT_EQ(cli.operation_type, 2);
    ASSERT_EQ(cli.port, DEFAULT_PORT);
}

// Test: invalid port parameter name
TEST(test_receive_invalid_param)
{
    char *av[] = {"chunknet", "receive", "--invalid", "8080", NULL};
    int ac = 4;

    CLI_T cli = parse(ac, av);

    ASSERT_EQ(cli.operation_type, 0);
}

// Test: too many arguments
TEST(test_receive_too_many_args)
{
    char *av[] = {"chunknet", "receive", "--port", "8080", "extra", NULL};
    int ac = 5;

    CLI_T cli = parse(ac, av);

    ASSERT_EQ(cli.operation_type, 0);
}

// Test: port = 0 (invalid)
TEST(test_receive_port_zero)
{
    char *av[] = {"chunknet", "receive", "--port", "0", NULL};
    int ac = 4;

    CLI_T cli = parse(ac, av);

    ASSERT_EQ(cli.operation_type, 0);
}

// Test: port negative (invalid)
TEST(test_receive_port_negative)
{
    char *av[] = {"chunknet", "receive", "--port", "-1", NULL};
    int ac = 4;

    CLI_T cli = parse(ac, av);

    ASSERT_EQ(cli.operation_type, 0);
}

// Test: port > 65535 (invalid)
TEST(test_receive_port_too_high)
{
    char *av[] = {"chunknet", "receive", "--port", "65536", NULL};
    int ac = 4;

    CLI_T cli = parse(ac, av);

    ASSERT_EQ(cli.operation_type, 0);
}

// Test: port = 65535 (valid max)
TEST(test_receive_port_max_valid)
{
    char *av[] = {"chunknet", "receive", "--port", "65535", NULL};
    int ac = 4;

    CLI_T cli = parse(ac, av);

    ASSERT_EQ(cli.operation_type, 2);
    ASSERT_EQ(cli.port, 65535);
}

// Test: port = 1 (valid min)
TEST(test_receive_port_min_valid)
{
    char *av[] = {"chunknet", "receive", "--port", "1", NULL};
    int ac = 4;

    CLI_T cli = parse(ac, av);

    ASSERT_EQ(cli.operation_type, 2);
    ASSERT_EQ(cli.port, 1);
}

// Test: non-numeric port
TEST(test_receive_port_non_numeric)
{
    char *av[] = {"chunknet", "receive", "--port", "abc", NULL};
    int ac = 4;

    CLI_T cli = parse(ac, av);

    ASSERT_EQ(cli.operation_type, 0);
}

// Test: no arguments at all
TEST(test_no_arguments)
{
    char *av[] = {"chunknet", NULL};
    int ac = 1;

    CLI_T cli = parse(ac, av);

    ASSERT_EQ(cli.operation_type, 0);
}

// Test: unknown command
TEST(test_unknown_command)
{
    char *av[] = {"chunknet", "unknown", NULL};
    int ac = 2;

    CLI_T cli = parse(ac, av);

    ASSERT_EQ(cli.operation_type, 0);
}

int main(void)
{
    printf("=== CLI Parse Receive Tests ===\n\n");

    // Basic receive tests
    RUN_TEST(test_receive_default_port);
    RUN_TEST(test_receive_shorthand_default_port);
    RUN_TEST(test_receive_custom_port);
    RUN_TEST(test_receive_shorthand_custom_port);

    // Case insensitivity tests
    RUN_TEST(test_receive_case_insensitive);
    RUN_TEST(test_receive_shorthand_case_insensitive);

    // Error handling tests
    RUN_TEST(test_receive_invalid_param);
    RUN_TEST(test_receive_too_many_args);

    // Port validation tests
    RUN_TEST(test_receive_port_zero);
    RUN_TEST(test_receive_port_negative);
    RUN_TEST(test_receive_port_too_high);
    RUN_TEST(test_receive_port_max_valid);
    RUN_TEST(test_receive_port_min_valid);
    RUN_TEST(test_receive_port_non_numeric);

    // Edge cases
    RUN_TEST(test_no_arguments);
    RUN_TEST(test_unknown_command);

    printf("\n=== Results ===\n");
    printf("Passed: %d\n", tests_passed);
    printf("Failed: %d\n", tests_failed);

    return tests_failed > 0 ? 1 : 0;
}