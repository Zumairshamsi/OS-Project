#include <fcntl.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "tracer.h"

#define PATH_SHOW     256   /* chars of a pathname shown                 */
#define BUF_SHOW       32   /* bytes of a data buffer shown              */
#define ARG_SHOW       32   /* chars of each execve argument shown       */
#define ARGV_SHOW       8   /* execve argv entries shown                 */
#define ENV_COUNT_MAX 4096

/* ------------------------------------------------------------------ */
/* Bounded string builder: never overflows, always NUL-terminated.     */
/* ------------------------------------------------------------------ */

typedef struct {
    char  *buf;
    size_t cap;
    size_t len;
    int    argn;                /* arguments emitted so far */
} sb_t;

static void sb_init(sb_t *sb, char *buf, size_t cap)
{
    sb->buf  = buf;
    sb->cap  = cap;
    sb->len  = 0;
    sb->argn = 0;
    buf[0]   = '\0';
}

static void sb_printf(sb_t *sb, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));

static void sb_printf(sb_t *sb, const char *fmt, ...)
{
    va_list ap;
    int     n;
    size_t  room;

    if (sb->len + 1 >= sb->cap)
        return;                                 /* full: drop the rest */

    room = sb->cap - sb->len;
    va_start(ap, fmt);
    n = vsnprintf(sb->buf + sb->len, room, fmt, ap);
    va_end(ap);

    if (n < 0)
        return;
    sb->len += ((size_t)n >= room) ? room - 1 : (size_t)n;
}

static void sb_puts(sb_t *sb, const char *s)
{
    sb_printf(sb, "%s", s);
}

static void next_arg(sb_t *sb)
{
    if (sb->argn++)
        sb_puts(sb, ", ");
}

/* ------------------------------------------------------------------ */
/* Leaf renderers                                                      */
/* ------------------------------------------------------------------ */

/* "text" with C escapes, strace style. Bytes come from another process,
 * so they are always printed through %c / %o, never as a format string. */
static void put_escaped(sb_t *sb, const unsigned char *s, size_t n,
                        bool truncated)
{
    sb_puts(sb, "\"");
    for (size_t i = 0; i < n; i++) {
        unsigned char c = s[i];

        switch (c) {
        case '"':  sb_puts(sb, "\\\""); break;
        case '\\': sb_puts(sb, "\\\\"); break;
        case '\n': sb_puts(sb, "\\n");  break;
        case '\t': sb_puts(sb, "\\t");  break;
        case '\r': sb_puts(sb, "\\r");  break;
        case '\f': sb_puts(sb, "\\f");  break;
        case '\v': sb_puts(sb, "\\v");  break;
        default:
            if (c >= 0x20 && c < 0x7f)
                sb_printf(sb, "%c", c);
            else if (i + 1 < n && s[i + 1] >= '0' && s[i + 1] <= '7')
                sb_printf(sb, "\\%03o", c);     /* next is a digit: 3 digits */
            else
                sb_printf(sb, "\\%o", c);
            break;
        }
    }
    sb_puts(sb, truncated ? "\"..." : "\"");
}

static void put_ptr(sb_t *sb, unsigned long v)
{
    if (v == 0)
        sb_puts(sb, "NULL");
    else
        sb_printf(sb, "0x%lx", v);
}

/* char * argument: NULL, an unreadable address (hex), or a quoted string. */
static void put_cstr(sb_t *sb, pid_t pid, unsigned long addr, size_t max)
{
    char    tmp[PATH_SHOW + 1];
    bool    trunc;
    ssize_t n;

    if (addr == 0) {
        sb_puts(sb, "NULL");
        return;
    }
    if (max > PATH_SHOW)
        max = PATH_SHOW;

    n = tracee_read_string(pid, addr, tmp, max, &trunc);
    if (n < 0) {
        sb_printf(sb, "0x%lx", addr);
        return;
    }
    put_escaped(sb, (const unsigned char *)tmp, (size_t)n, trunc);
}

/* Data buffer of `len` bytes: show the first BUF_SHOW. */
static void put_buf(sb_t *sb, pid_t pid, unsigned long addr, unsigned long len)
{
    unsigned char tmp[BUF_SHOW];
    size_t        want = len < BUF_SHOW ? (size_t)len : BUF_SHOW;
    ssize_t       n;

    if (addr == 0) {
        sb_puts(sb, "NULL");
        return;
    }
    if (want == 0) {
        sb_puts(sb, "\"\"");
        return;
    }
    n = tracee_read(pid, addr, tmp, want);
    if (n <= 0) {
        sb_printf(sb, "0x%lx", addr);
        return;
    }
    put_escaped(sb, tmp, (size_t)n, len > (unsigned long)n);
}

/* NULL-terminated array of char * (execve argv): ["ls", "-l", ...] */
static void put_argv(sb_t *sb, pid_t pid, unsigned long addr)
{
    unsigned long p;

    if (addr == 0) {
        sb_puts(sb, "NULL");
        return;
    }
    if (tracee_read(pid, addr, &p, sizeof p) != (ssize_t)sizeof p) {
        sb_printf(sb, "0x%lx", addr);
        return;
    }

    sb_puts(sb, "[");
    for (int i = 0; ; i++) {
        if (i && tracee_read(pid, addr + (unsigned long)i * sizeof p,
                             &p, sizeof p) != (ssize_t)sizeof p)
            break;
        if (p == 0)
            break;
        if (i == ARGV_SHOW) {
            sb_puts(sb, ", ...");
            break;
        }
        if (i)
            sb_puts(sb, ", ");
        put_cstr(sb, pid, p, ARG_SHOW);
    }
    sb_puts(sb, "]");
}

/* envp: just the address and a count, like strace: 0x7ffd... /* 52 vars */
static void put_envp(sb_t *sb, pid_t pid, unsigned long addr)
{
    unsigned long chunk[32];
    int           count = 0;
    bool          done  = false;

    if (addr == 0) {
        sb_puts(sb, "NULL");
        return;
    }

    while (!done && count < ENV_COUNT_MAX) {
        ssize_t n = tracee_read(pid, addr + (unsigned long)count * sizeof(long),
                                chunk, sizeof chunk);
        size_t  got;

        if (n < (ssize_t)sizeof(long))
            break;                              /* unreadable */
        got = (size_t)n / sizeof(long);
        for (size_t k = 0; k < got; k++) {
            if (chunk[k] == 0) {
                done = true;
                break;
            }
            count++;
        }
    }

    if (done)
        sb_printf(sb, "0x%lx /* %d vars */", addr, count);
    else
        sb_printf(sb, "0x%lx", addr);
}

/* ------------------------------------------------------------------ */
/* Flag tables                                                         */
/* ------------------------------------------------------------------ */

typedef struct { unsigned long val; const char *name; } flag_t;

#define FLAG(x)    { (unsigned long)(x), #x }
#define NFLAGS(t)  (sizeof(t) / sizeof((t)[0]))

/* Order matters for multi-bit flags: O_TMPFILE contains O_DIRECTORY and
 * O_SYNC contains O_DSYNC, so the wider one is tested first. Zero-valued
 * flags (O_RDONLY, O_LARGEFILE on x86_64) must NOT be in these tables. */
static const flag_t open_tbl[] = {
    FLAG(O_CREAT), FLAG(O_EXCL), FLAG(O_NOCTTY), FLAG(O_TRUNC),
    FLAG(O_APPEND), FLAG(O_NONBLOCK), FLAG(O_ASYNC), FLAG(O_DIRECT),
    FLAG(O_TMPFILE), FLAG(O_DIRECTORY), FLAG(O_NOFOLLOW), FLAG(O_NOATIME),
    FLAG(O_CLOEXEC), FLAG(O_PATH), FLAG(O_SYNC), FLAG(O_DSYNC),
};

static const flag_t prot_tbl[] = {
    FLAG(PROT_READ), FLAG(PROT_WRITE), FLAG(PROT_EXEC),
};

static const flag_t map_tbl[] = {
    FLAG(MAP_FIXED), FLAG(MAP_ANONYMOUS), FLAG(MAP_GROWSDOWN),
    FLAG(MAP_DENYWRITE), FLAG(MAP_EXECUTABLE), FLAG(MAP_LOCKED),
    FLAG(MAP_NORESERVE), FLAG(MAP_POPULATE), FLAG(MAP_NONBLOCK),
    FLAG(MAP_STACK), FLAG(MAP_HUGETLB),
#ifdef MAP_FIXED_NOREPLACE
    FLAG(MAP_FIXED_NOREPLACE),
#endif
};

static const flag_t access_tbl[] = {
    FLAG(R_OK), FLAG(W_OK), FLAG(X_OK),
};

static const flag_t at_tbl[] = {
    FLAG(AT_SYMLINK_NOFOLLOW), FLAG(AT_REMOVEDIR), FLAG(AT_SYMLINK_FOLLOW),
    FLAG(AT_NO_AUTOMOUNT), FLAG(AT_EMPTY_PATH),
};

/* A|B|0xLEFTOVER. `zero` is printed when no bit is set. */
static void fmt_flags(sb_t *sb, unsigned long v, const flag_t *tbl, size_t n,
                      const char *zero)
{
    bool first = true;

    if (v == 0) {
        sb_puts(sb, zero);
        return;
    }
    for (size_t i = 0; i < n; i++) {
        if ((v & tbl[i].val) == tbl[i].val) {
            if (!first)
                sb_puts(sb, "|");
            sb_puts(sb, tbl[i].name);
            first = false;
            v &= ~tbl[i].val;           /* consume, so O_SYNC hides O_DSYNC */
        }
    }
    if (v) {
        if (!first)
            sb_puts(sb, "|");
        sb_printf(sb, "0x%lx", v);
    }
}

static void put_open_flags(sb_t *sb, unsigned int fl)
{
    unsigned int rest;

    switch (fl & O_ACCMODE) {
    case O_RDONLY: sb_puts(sb, "O_RDONLY"); break;
    case O_WRONLY: sb_puts(sb, "O_WRONLY"); break;
    case O_RDWR:   sb_puts(sb, "O_RDWR");   break;
    default:       sb_printf(sb, "0x%x", fl & O_ACCMODE); break;
    }
    rest = fl & ~(unsigned int)O_ACCMODE;
    if (rest) {
        sb_puts(sb, "|");
        fmt_flags(sb, rest, open_tbl, NFLAGS(open_tbl), "0");
    }
}

/* open()/openat() only read their mode argument when creating a file. */
static bool open_has_mode(unsigned long flags)
{
    unsigned int f = (unsigned int)flags;

    return (f & O_CREAT) || (f & O_TMPFILE) == O_TMPFILE;
}

static void put_map_flags(sb_t *sb, unsigned int fl)
{
    unsigned int rest = fl & ~0x0fu;

    switch (fl & 0x0f) {                        /* MAP_TYPE field */
    case 1:  sb_puts(sb, "MAP_SHARED");          break;
    case 2:  sb_puts(sb, "MAP_PRIVATE");         break;
    case 3:  sb_puts(sb, "MAP_SHARED_VALIDATE"); break;
    default: sb_printf(sb, "0x%x", fl & 0x0f);   break;
    }
    if (rest) {
        sb_puts(sb, "|");
        fmt_flags(sb, rest, map_tbl, NFLAGS(map_tbl), "0");
    }
}

static void put_dirfd(sb_t *sb, unsigned long v)
{
    int fd = (int)v;

    if (fd == AT_FDCWD)
        sb_puts(sb, "AT_FDCWD");
    else
        sb_printf(sb, "%d", fd);
}

static void put_whence(sb_t *sb, int w)
{
    switch (w) {
    case SEEK_SET:  sb_puts(sb, "SEEK_SET");  break;
    case SEEK_CUR:  sb_puts(sb, "SEEK_CUR");  break;
    case SEEK_END:  sb_puts(sb, "SEEK_END");  break;
    case SEEK_DATA: sb_puts(sb, "SEEK_DATA"); break;
    case SEEK_HOLE: sb_puts(sb, "SEEK_HOLE"); break;
    default:        sb_printf(sb, "%d", w);   break;
    }
}

/* ------------------------------------------------------------------ */
/* Per-syscall argument descriptions                                   */
/* ------------------------------------------------------------------ */

typedef enum {
    T_NONE = 0,                 /* end of the argument list */
    T_INT, T_UINT, T_LONG, T_ULONG, T_HEX, T_PTR,
    T_FD, T_DIRFD, T_PATH,
    T_BUF_IN,                   /* data going in; length = next argument    */
    T_BUF_OUT,                  /* data coming out; shown at exit, length
                                   = min(return value, next argument)       */
    T_OPEN_FLAGS, T_OPEN_MODE,  /* mode only shown when flags create a file */
    T_MODE, T_PROT, T_MAP_FLAGS, T_ACCESS, T_WHENCE, T_AT_FLAGS,
    T_ARGV, T_ENVP
} argtype_t;

typedef struct {
    long      nr;
    argtype_t a[6];             /* unused slots stay T_NONE */
} sc_desc_t;

static const sc_desc_t sc_table[] = {
    /* ---- file I/O ---- */
    { SYS_read,        { T_FD, T_BUF_OUT, T_ULONG } },
    { SYS_write,       { T_FD, T_BUF_IN,  T_ULONG } },
    { SYS_pread64,     { T_FD, T_BUF_OUT, T_ULONG, T_LONG } },
    { SYS_pwrite64,    { T_FD, T_BUF_IN,  T_ULONG, T_LONG } },
    { SYS_open,        { T_PATH, T_OPEN_FLAGS, T_OPEN_MODE } },
    { SYS_openat,      { T_DIRFD, T_PATH, T_OPEN_FLAGS, T_OPEN_MODE } },
    { SYS_creat,       { T_PATH, T_MODE } },
    { SYS_close,       { T_FD } },
    { SYS_lseek,       { T_FD, T_LONG, T_WHENCE } },
    { SYS_dup,         { T_FD } },
    { SYS_dup2,        { T_FD, T_FD } },
    { SYS_dup3,        { T_FD, T_FD, T_HEX } },
    { SYS_pipe,        { T_PTR } },
    { SYS_pipe2,       { T_PTR, T_HEX } },
    { SYS_ioctl,       { T_FD, T_HEX, T_HEX } },
    { SYS_fcntl,       { T_FD, T_INT, T_HEX } },
    { SYS_getdents64,  { T_FD, T_PTR, T_ULONG } },

    /* ---- files and directories ---- */
    { SYS_stat,        { T_PATH, T_PTR } },
    { SYS_lstat,       { T_PATH, T_PTR } },
    { SYS_fstat,       { T_FD, T_PTR } },
    { SYS_newfstatat,  { T_DIRFD, T_PATH, T_PTR, T_AT_FLAGS } },
    { SYS_access,      { T_PATH, T_ACCESS } },
    { SYS_faccessat,   { T_DIRFD, T_PATH, T_ACCESS } },
    { SYS_readlink,    { T_PATH, T_BUF_OUT, T_ULONG } },
    { SYS_readlinkat,  { T_DIRFD, T_PATH, T_BUF_OUT, T_ULONG } },
    { SYS_getcwd,      { T_PTR, T_ULONG } },
    { SYS_chdir,       { T_PATH } },
    { SYS_chmod,       { T_PATH, T_MODE } },
    { SYS_mkdir,       { T_PATH, T_MODE } },
    { SYS_mkdirat,     { T_DIRFD, T_PATH, T_MODE } },
    { SYS_rmdir,       { T_PATH } },
    { SYS_unlink,      { T_PATH } },
    { SYS_unlinkat,    { T_DIRFD, T_PATH, T_AT_FLAGS } },
    { SYS_rename,      { T_PATH, T_PATH } },

    /* ---- memory ---- */
    { SYS_mmap,        { T_PTR, T_ULONG, T_PROT, T_MAP_FLAGS, T_FD, T_HEX } },
    { SYS_mprotect,    { T_PTR, T_ULONG, T_PROT } },
    { SYS_munmap,      { T_PTR, T_ULONG } },
    { SYS_brk,         { T_PTR } },

    /* ---- processes ---- */
    { SYS_execve,      { T_PATH, T_ARGV, T_ENVP } },
    { SYS_exit,        { T_INT } },
    { SYS_exit_group,  { T_INT } },
    { SYS_wait4,       { T_INT, T_PTR, T_HEX, T_PTR } },
    { SYS_kill,        { T_INT, T_INT } },
    { SYS_getpid,      { T_NONE } },
    { SYS_getppid,     { T_NONE } },
    { SYS_gettid,      { T_NONE } },
    { SYS_getuid,      { T_NONE } },
    { SYS_geteuid,     { T_NONE } },
    { SYS_getgid,      { T_NONE } },
    { SYS_getegid,     { T_NONE } },
    { SYS_arch_prctl,  { T_HEX, T_HEX } },
    { SYS_set_tid_address, { T_PTR } },
    { SYS_set_robust_list, { T_PTR, T_ULONG } },
    { SYS_prlimit64,   { T_INT, T_INT, T_PTR, T_PTR } },

    /* ---- signals ---- */
    { SYS_rt_sigaction,   { T_INT, T_PTR, T_PTR, T_ULONG } },
    { SYS_rt_sigprocmask, { T_INT, T_PTR, T_PTR, T_ULONG } },

    /* ---- newer syscalls: only if the host headers know them ---- */
#ifdef SYS_faccessat2
    { SYS_faccessat2,  { T_DIRFD, T_PATH, T_ACCESS, T_AT_FLAGS } },
#endif
#ifdef SYS_statx
    { SYS_statx,       { T_DIRFD, T_PATH, T_AT_FLAGS, T_HEX, T_PTR } },
#endif
#ifdef SYS_getrandom
    { SYS_getrandom,   { T_PTR, T_ULONG, T_HEX } },
#endif
#ifdef SYS_rseq
    { SYS_rseq,        { T_PTR, T_UINT, T_INT, T_HEX } },
#endif
};

static const sc_desc_t *find_desc(long nr)
{
    for (size_t i = 0; i < NFLAGS(sc_table); i++)
        if (sc_table[i].nr == nr)
            return &sc_table[i];
    return NULL;
}

bool decode_has_output_buf(long nr)
{
    const sc_desc_t *d = find_desc(nr);

    if (!d)
        return false;
    for (int i = 0; i < 6; i++)
        if (d->a[i] == T_BUF_OUT)
            return true;
    return false;
}

bool decode_ret_is_pointer(long nr)
{
    return nr == SYS_mmap || nr == SYS_brk || nr == SYS_mremap;
}

/* ------------------------------------------------------------------ */
/* The decoder                                                         */
/* ------------------------------------------------------------------ */

void decode_args(pid_t pid, syscall_rec_t *r, bool at_exit)
{
    sb_t             sb;
    const sc_desc_t *d = find_desc(r->nr);

    sb_init(&sb, r->argstr, sizeof r->argstr);

    if (!d) {                                   /* unknown: raw hex */
        for (int i = 0; i < 6; i++) {
            next_arg(&sb);
            sb_printf(&sb, "0x%lx", r->args[i]);
        }
        return;
    }

    for (int i = 0; i < 6 && d->a[i] != T_NONE; i++) {
        unsigned long v = r->args[i];

        if (d->a[i] == T_OPEN_MODE && !open_has_mode(r->args[i - 1]))
            continue;                           /* mode ignored: omit it */

        next_arg(&sb);

        switch (d->a[i]) {
        case T_INT:    sb_printf(&sb, "%d",  (int)v);          break;
        case T_UINT:   sb_printf(&sb, "%u",  (unsigned int)v); break;
        case T_LONG:   sb_printf(&sb, "%ld", (long)v);         break;
        case T_ULONG:  sb_printf(&sb, "%lu", v);               break;
        case T_HEX:    sb_printf(&sb, "0x%lx", v);             break;
        case T_PTR:    put_ptr(&sb, v);                        break;
        case T_FD:     sb_printf(&sb, "%d", (int)v);           break;
        case T_DIRFD:  put_dirfd(&sb, v);                      break;
        case T_PATH:   put_cstr(&sb, pid, v, PATH_SHOW);       break;

        case T_BUF_IN:
            put_buf(&sb, pid, v, r->args[i + 1]);
            break;

        case T_BUF_OUT:
            if (at_exit && !r->failed && r->ret >= 0) {
                unsigned long cap = r->args[i + 1];
                unsigned long ret = (unsigned long)r->ret;

                put_buf(&sb, pid, v, ret < cap ? ret : cap);
            } else {
                put_ptr(&sb, v);                /* entry: not filled yet */
            }
            break;

        case T_OPEN_FLAGS: put_open_flags(&sb, (unsigned int)v);        break;
        case T_OPEN_MODE:
        case T_MODE:       sb_printf(&sb, "%#o", (unsigned int)v);      break;
        case T_PROT:
            fmt_flags(&sb, (unsigned int)v, prot_tbl, NFLAGS(prot_tbl),
                      "PROT_NONE");
            break;
        case T_MAP_FLAGS:  put_map_flags(&sb, (unsigned int)v);         break;
        case T_ACCESS:
            fmt_flags(&sb, (unsigned int)v, access_tbl, NFLAGS(access_tbl),
                      "F_OK");
            break;
        case T_WHENCE:     put_whence(&sb, (int)v);                     break;
        case T_AT_FLAGS:
            fmt_flags(&sb, (unsigned int)v, at_tbl, NFLAGS(at_tbl), "0");
            break;
        case T_ARGV:       put_argv(&sb, pid, v);                       break;
        case T_ENVP:       put_envp(&sb, pid, v);                       break;
        case T_NONE:       break;
        }
    }
}