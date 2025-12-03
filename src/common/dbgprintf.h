#ifndef DBGPRINTF_H
#define DBGPRINTF_H

#include <stdbool.h>

int dbgprintf(char *message);
bool is_debug(char **env);

#endif // DBGPRINTF_H