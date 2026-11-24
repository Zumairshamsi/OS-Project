#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "tracer.h"

bool filter_allows(const syscall_filter_t *f, long nr)
{
    if (!f->active)
        return true;
    if (nr < 0 || nr >= FILTER_MAX_NR)
        return false;
    return (f->bits[nr / 64] >> (nr % 64)) & 1u;
}

static void filter_set(syscall_filter_t *f, long nr)
{
    f->bits[nr / 64] |= (uint64_t)1 << (nr % 64);
}

int filter_parse(const char *list, syscall_filter_t *f)
{
    char *copy = strdup(list);
    char *p    = copy;
    int   rc   = 0;

    if (!copy) {
        perror("strdup");
        return -1;
    }

    memset(f, 0, sizeof *f);
    f->active = true;

    while (p) {
        char *comma = strchr(p, ',');

        if (comma)
            *comma = '\0';

        if (*p == '\0') {                       /* "a,,b" or trailing comma */
            fprintf(stderr, "mini_strace: empty name in trace list '%s'\n",
                    list);
            rc = -1;
            break;
        }

        if (strcmp(p, "all") == 0) {
            memset(f->bits, 0xff, sizeof f->bits);
        } else {
            long nr = syscall_number(p);

            if (nr < 0 || nr >= FILTER_MAX_NR) {
                fprintf(stderr, "mini_strace: unknown system call '%s'\n", p);
                rc = -1;
                break;
            }
            filter_set(f, nr);
        }
        p = comma ? comma + 1 : NULL;
    }

    free(copy);
    return rc;
}