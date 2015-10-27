#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include "common/utils.h"

static int argc_count(const char *str);

char **argv_split(const char *str, int *argcp)
{
    char *argv_str;
    int was_space, argc;
    char **argv, **argv_ret;

    argv_str = strdup(str);
    if (!argv_str) {
        return NULL;
    }

    argc = argc_count(argv_str);
    argv = malloc((argc + 2) * sizeof(*argv));
    if (!argv) {
        free(argv_str);
        return NULL;
    }

    *argv = argv_str;
    argv_ret = ++argv;
    for (was_space = 1; *argv_str; argv_str++) {
        if (isspace(*argv_str)) {
            was_space = 1;
            *argv_str = 0;
        } else if (was_space) {
            was_space = 0;
            *argv++ = argv_str;
        }
    }
    *argv = NULL;

    if (argcp) {
        *argcp = argc;
    }

    return argv_ret;
}

void argv_free(char **argv)
{
    argv--;
    free(argv[0]);
    free(argv);
    return;
}

static int argc_count(const char *str)
{
    int was_space, count = 0;

    for (was_space = 1; *str; str++) {
        if (isspace(*str)) {
            was_space = 1;
        } else if (was_space) {
            was_space = 0;
            count++;
        }
    }

    return count;
}

