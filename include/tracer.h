#ifndef TRACER_H
#define TRACER_H

#include <stdbool.h>
#include <sys/types.h>
#include <stdint.h>
#include <stdio.h>

/* Which syscalls to show: a bitmask indexed by syscall number. */
#define FILTER_MAX_NR 1024

typedef struct {
    bool     active;                          /* false: trace everything  */
    uint64_t bits[FILTER_MAX_NR / 64];
} syscall_filter_t;


typedef struct {
    pid_t       attach_pid;   /* -p PID; 0 means spawn mode            */
    char      **cmd_argv;     /* command + args; NULL means attach mode */
    bool        summary;      /* -c : print statistics table at exit    */
    const char *out_path;     /* -o FILE; NULL means stderr             */
    const char *filter_str;   /* -e trace=...  (text after "trace=")    */
    syscall_filter_t filter;  /* parsed from filter_str by filter_parse()  */
    FILE            *out;     /* trace destination (stderr unless -o)      */
} tracer_config_t;

#define ARGSTR_MAX 2048

/* One decoded system call: filled at entry (nr, args, argstr), completed at
 * exit (ret, failed, err). */
typedef struct {
    long          nr;          /* syscall number (orig_rax)              */
    unsigned long args[6];     /* rdi, rsi, rdx, r10, r8, r9             */
    long          ret;         /* rax at exit                            */
    bool          failed;      /* ret in [-4095, -1]                     */
    int           err;         /* errno value when failed, else 0        */
    int64_t       start_ns;    /* CLOCK_MONOTONIC when the call began    */
    int64_t       dur_ns;      /* time inside the kernel; -1 = unknown   */
    char          argstr[ARGSTR_MAX];  /* rendered arguments, no parens  */
} syscall_rec_t;


/* ---- Process control layer (src/control.c) ---- */
int tracer_set_options(pid_t pid, bool exit_kill);
pid_t tracer_spawn(char *const argv[]);

int tracer_attach(pid_t pid);
int tracer_detach(pid_t pid);

/* ---- Interception layer (src/trace.c) ---- */

/* Main interception loop. Runs until the tracee exits, is killed, or
 * (attach mode) the user presses Ctrl+C.
 * Returns the exit code the tracer should use. */
int tracer_run(pid_t pid, bool attached, const tracer_config_t *cfg);

/* ---- Name resolution (src/syscalls.c) ---- */

/* Build the syscall hash map. Idempotent; lookups call it lazily too. */
void        syscalls_init(void);

/* x86_64 syscall number -> name, or NULL if unknown. */
const char *syscall_name(long nr);

/* Name -> syscall number, or -1 if unknown. (Used by -e in Step 10.) */
long        syscall_number(const char *name);

/* errno value -> "ENOENT" etc., or NULL if unknown. */
const char *errno_name(int err);


/* ---- Tracee memory access (src/memory.c) ---- */

/* Read up to len bytes at addr in the tracee. Returns the number of bytes
 * actually read (may be partial), or -1 if nothing could be read. */
ssize_t tracee_read(pid_t pid, unsigned long addr, void *buf, size_t len);

/* Read a NUL-terminated string of at most max chars into buf (capacity must
 * be max+1). Always NUL-terminates. Returns its length, or -1 if the first
 * byte was unreadable. *truncated is set if the string was cut short. */
ssize_t tracee_read_string(pid_t pid, unsigned long addr, char *buf,
                           size_t max, bool *truncated);

/* ---- Argument decoder (src/decode.c) ---- */

/* Render r->args into r->argstr. Call at entry with at_exit=false; for
 * syscalls where decode_has_output_buf() is true, call again at exit with
 * at_exit=true (r->ret must be filled in first). */
void decode_args(pid_t pid, syscall_rec_t *r, bool at_exit);

/* True if the syscall has an output buffer that is only valid at exit. */
bool decode_has_output_buf(long nr);

/* True if the return value is an address (mmap, brk, mremap): print as hex. */
bool decode_ret_is_pointer(long nr);

/* ---- Syscall filter (src/filter.c) ---- */

/* Parse "read,write,openat" (or "all") into f. Prints an error and returns
 * -1 on an unknown name or an empty entry. */
int  filter_parse(const char *list, syscall_filter_t *f);

/* True if syscall nr should be shown. Always true for an inactive filter. */
bool filter_allows(const syscall_filter_t *f, long nr);

/* ---- Statistics (src/stats.c) ---- */

typedef struct {
    unsigned long calls;
    unsigned long errors;
    int64_t       total_ns;
} stat_entry_t;

typedef struct {
    stat_entry_t e[FILTER_MAX_NR];      /* indexed by syscall number */
} stats_t;

stats_t *stats_create(void);
void     stats_destroy(stats_t *st);
void     stats_record(stats_t *st, const syscall_rec_t *r);
void     stats_print(FILE *out, const stats_t *st);

#endif /* TRACER_H */
