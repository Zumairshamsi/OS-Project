#define _GNU_SOURCE
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/syscall.h>

#include "tracer.h"

/* Generated at build time: syscall_list[] and errno_list[]. */
#include "tables.inc"

#define HASH_BITS   10
#define HASH_SIZE   (1u << HASH_BITS)          /* 1024 slots, power of two */
#define HASH_MASK   (HASH_SIZE - 1u)
#define SYSCALL_COUNT (sizeof(syscall_list) / sizeof(syscall_list[0]))
#define ERRNO_COUNT   (sizeof(errno_list)   / sizeof(errno_list[0]))

/* Keep the load factor <= 50% so probing always finds an empty slot. */
_Static_assert(SYSCALL_COUNT * 2 <= HASH_SIZE,
               "syscall table too large for hash size: raise HASH_BITS");

typedef struct {
    long        nr;
    const char *name;           /* NULL = empty slot */
} slot_t;

static slot_t g_table[HASH_SIZE];
static bool   g_ready = false;

/* Knuth multiplicative hash, keeping the top HASH_BITS bits. */
static size_t hash_nr(long nr)
{
    return (size_t)(((uint32_t)nr * 2654435761u) >> (32 - HASH_BITS));
}

void syscalls_init(void)
{
    if (g_ready)
        return;

    for (size_t i = 0; i < SYSCALL_COUNT; i++) {
        size_t h = hash_nr(syscall_list[i].nr);

        while (g_table[h].name)                 /* linear probing */
            h = (h + 1) & HASH_MASK;

        g_table[h].nr   = syscall_list[i].nr;
        g_table[h].name = syscall_list[i].name;
    }
    g_ready = true;
}

const char *syscall_name(long nr)
{
    if (!g_ready)
        syscalls_init();
    if (nr < 0)
        return NULL;

    size_t h = hash_nr(nr);

    while (g_table[h].name) {
        if (g_table[h].nr == nr)
            return g_table[h].name;
        h = (h + 1) & HASH_MASK;
    }
    return NULL;                                /* unknown syscall */
}

long syscall_number(const char *name)
{
    /* Called a handful of times while parsing -e, so a scan is fine. */
    for (size_t i = 0; i < SYSCALL_COUNT; i++)
        if (strcmp(syscall_list[i].name, name) == 0)
            return syscall_list[i].nr;
    return -1;
}

const char *errno_name(int err)
{
    if (err > 0 && (size_t)err < ERRNO_COUNT)
        return errno_list[err];                 /* may be NULL for gaps */
    return NULL;
}