#include <string.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include "cli.h"
#include "../const.h"
#include "../common/dbgprintf.h"


static int parse_ipv4(const char *ip_str, unsigned char address[4])
{
    int parts[4];
    int count = sscanf(ip_str, "%d.%d.%d.%d", &parts[0], &parts[1], &parts[2], &parts[3]);

    if (count != 4)
        return 0;
    for (int i = 0; i < 4; i++) {
        if (parts[i] < 0 || parts[i] > 255)
            return 0;
        address[i] = (unsigned char)parts[i];
    }
    return 1;
}

static CLI_T parse_send(int ac, char *av[])
{
    CLI_T cli = {};

    // Minimum: chunknet send <ip> <file>
    if (ac < 4) {
        dbgprintf("Missing arguments: chunknet send <ip> <file> [--port <port>]");
        return cli;
    }
    // Maximum: chunknet send <ip> <file> --port <port>
    if (ac > 6) {
        dbgprintf("Too many arguments: %d", ac);
        return cli;
    }
    // Parse IP address
    if (!parse_ipv4(av[2], cli.address)) {
        dbgprintf("Invalid IP address: %s", av[2]);
        return cli;
    }
    // Parse file path
    cli.path = av[3];
    if (cli.path == NULL || strlen(cli.path) == 0) {
        dbgprintf("Invalid file path");
        return cli;
    }
    if (strlen(cli.path) > MAX_FILENAME_LEN) {
        dbgprintf("File path too long (max %d characters)", MAX_FILENAME_LEN);
        return cli;
    }
    // Default port
    cli.port = DEFAULT_PORT;

    // Parse optional --port argument
    if (ac == 6) {
        if (strcmp(av[4], "--port") != 0) {
            dbgprintf("Invalid parameter, use chunknet -h to get help");
            return cli;
        }
        int port = atoi(av[5]);
        if (port <= 0 || port > 65535) {
            dbgprintf("Invalid port, must be between 1 and 65535");
            return cli;
        }
        cli.port = port;
    }
    // Handle case where ac == 5 (incomplete --port argument)
    if (ac == 5) {
        dbgprintf("Incomplete --port argument");
        return cli;
    }
    cli.operation_type = 1;
    return cli;
}

static CLI_T parse_receive(int ac, char *av[])
{
    CLI_T cli = {};

    if (ac == 2) {
        cli.port = DEFAULT_PORT;
        dbgprintf("Port not found, using default port");
    }
    if (ac > 4) {
        dbgprintf("Too many arguments : %d", ac);
        return cli;
    }
    if (ac == 4) {
        if (strcmp(av[2], "--port") != 0) {
            dbgprintf("Invalid parametter, use chunknet -h to get help");
            return cli;
        }
        int port = atoi(av[3]);
        if (port <= 0 || port > 65535) {
            dbgprintf("Invalid port, must be between 0 and 65535");
            return cli;
        } else {
            cli.port = port;
        }
    }
    cli.operation_type = 2;
    return cli;
}

CLI_T parse(int ac, char *av[])
{
    CLI_T cli = {};

    if (ac <= 1) // No arguments
        return cli;
    if (strcasecmp(av[1], "receive") == 0 || strcasecmp(av[1], "r") == 0) {
        cli = parse_receive(ac, av);
        return cli;
    }
    if (strcasecmp(av[1], "send") == 0 || strcasecmp(av[1], "s") == 0) {
        cli = parse_send(ac, av);
        return cli;
    }
    return cli;
}