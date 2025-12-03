#ifndef DBGPRINTF_H
#define DBGPRINTF_H

#include <stdbool.h>

int dbgprintf(const char *format, ...);
bool is_debug(char **env);

#endif // DBGPRINTF_H