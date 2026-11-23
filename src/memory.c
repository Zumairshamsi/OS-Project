#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/uio.h>

#include "tracer.h"

#define CHUNK_ALIGN 4096UL      /* never let one read cross a 4 KB boundary */

/* Set once process_vm_readv proves unusable (ENOSYS / EPERM under seccomp). */
static bool g_use_peek = false;

static ssize_t read_vm(pid_t pid, unsigned long addr, void *buf, size_t len)
{
    struct iovec local  = { .iov_base = buf,          .iov_len = len };
    struct iovec remote = { .iov_base = (void *)addr, .iov_len = len };

    return process_vm_readv(pid, &local, 1, &remote, 1, 0);
}

/* Fallback: one machine word per ptrace call. Words are read from aligned
 * addresses, so a single word can never straddle a page. */
static ssize_t read_peek(pid_t pid, unsigned long addr, void *buf, size_t len)
{
    unsigned char *out = buf;
    size_t done = 0;

    while (done < len) {
        unsigned long a    = addr + done;
        unsigned long base = a & ~(unsigned long)(sizeof(long) - 1);
        size_t        off  = (size_t)(a - base);
        size_t        take = sizeof(long) - off;
        long          word;

        if (take > len - done)
            take = len - done;

        errno = 0;
        word = ptrace(PTRACE_PEEKDATA, pid, (void *)base, 0);
        if (word == -1 && errno != 0)
            break;                      /* unmapped, or tracee gone */

        memcpy(out + done, (unsigned char *)&word + off, take);
        done += take;
    }
    return done ? (ssize_t)done : -1;
}

ssize_t tracee_read(pid_t pid, unsigned long addr, void *buf, size_t len)
{
    if (len == 0)
        return 0;

    if (!g_use_peek) {
        ssize_t n = read_vm(pid, addr, buf, len);

        if (n > 0)
            return n;
        if (n == 0 || errno == EFAULT || errno == ESRCH)
            return -1;                  /* genuinely unreadable */
        g_use_peek = true;              /* ENOSYS, EPERM, ...: stop trying */
    }
    return read_peek(pid, addr, buf, len);
}

ssize_t tracee_read_string(pid_t pid, unsigned long addr, char *buf,
                           size_t max, bool *truncated)
{
    size_t total = 0;

    *truncated = false;

    while (total < max) {
        unsigned long a    = addr + total;
        size_t        room = CHUNK_ALIGN - (size_t)(a & (CHUNK_ALIGN - 1));
        size_t        want = max - total;
        ssize_t       n;
        char         *nul;

        if (want > room)
            want = room;

        n = tracee_read(pid, a, buf + total, want);
        if (n <= 0) {
            if (total == 0)
                return -1;
            *truncated = true;          /* hit unreadable memory mid-string */
            break;
        }

        nul = memchr(buf + total, '\0', (size_t)n);
        if (nul) {
            total = (size_t)(nul - buf);
            buf[total] = '\0';
            return (ssize_t)total;
        }

        total += (size_t)n;
        if ((size_t)n < want) {         /* short read: next page is bad */
            *truncated = true;
            break;
        }
    }

    if (total >= max)
        *truncated = true;
    buf[total] = '\0';
    return (ssize_t)total;
}