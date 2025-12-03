#include <string.h>
#include <stddef.h>
#include "cli.h"
#include "../const.h"


static CLI_T parse_send(int ac, char *av[])
{
    CLI_T cli = {};

    cli.operation_type = 1;

    return cli;
}

static CLI_T parse_receive(int ac, char *av[])
{
    CLI_T cli = {};

    cli.operation_type = 2;

    if (ac == 2)
        cli.port = DEFAULT_PORT;
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