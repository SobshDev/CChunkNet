#include <string.h>
#include <stddef.h>
#include <stdlib.h>
#include "cli.h"
#include "../const.h"
#include "../common/dbgprintf.h"


static CLI_T parse_send(int ac, char *av[])
{
    CLI_T cli = {};

    (void)ac;(void)av;
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
        dbgprintf("Too many arguments");
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