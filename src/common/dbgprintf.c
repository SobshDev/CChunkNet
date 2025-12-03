#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <stdarg.h>

bool is_debug(char **env)
{
    for (unsigned int i = 0; env[i]; i++) {
        if (strcmp(env[i], "DEBUG=1") == 0)
            return true;
    }
    return false;
}

int dbgprintf(const char *format, ...)
{
    extern char **environ;

    if (is_debug(environ) == true) {
        va_list args;
        int ret;

        printf("DEBUG: ");
        va_start(args, format);
        ret = vprintf(format, args);
        va_end(args);
        return ret + 7;
    }
    return 0;
}