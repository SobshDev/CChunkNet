#include "cli/cli.h"

int main(int ac, char *av[])
{
    CLI_T cli = parse(ac, av);

    if (cli.operation_type == 0) {
        return 1;
    }
    return 0;
}