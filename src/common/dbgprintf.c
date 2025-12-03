#include <stdio.h>
#include <stdbool.h>
#include <string.h>

bool is_debug(char **env)
{
    for (unsigned int i = 0; env[i]; i++) {
        if (strcmp(env[i], "DEBUG=1") == 0)
            return true;
    }
    return false;
}

int dbgprintf(char *message)
{
    extern char **environ;

    if (is_debug(environ) == true) {
        return printf("DEBUG: %s\n", message);
    }
    return 0;
}