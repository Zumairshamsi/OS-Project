#ifndef TRACER_H
#define TRACER_H

#include <stdbool.h>
#include <sys/types.h>


typedef struct {
    pid_t       attach_pid;   /* -p PID; 0 means spawn mode            */
    char      **cmd_argv;     /* command + args; NULL means attach mode */
    bool        summary;      /* -c : print statistics table at exit    */
    const char *out_path;     /* -o FILE; NULL means stderr             */
    const char *filter_str;   /* -e trace=...  (text after "trace=")    */
} tracer_config_t;

/* One decoded system call: filled at entry (nr, args), completed at exit
 * (ret, failed, err). Reused by the name table, decoder and statistics. */
typedef struct {
    long          nr;          /* syscall number (orig_rax)              */
    unsigned long args[6];     /* rdi, rsi, rdx, r10, r8, r9             */
    long          ret;         /* rax at exit                            */
    bool          failed;      /* ret in [-4095, -1]                     */
    int           err;         /* errno value when failed, else 0        */
} syscall_rec_t;

/* ---- Process control layer (src/control.c) ---- */
int tracer_set_options(pid_t pid, bool exit_kill);
pid_t tracer_spawn(char *const argv[]);

int tracer_attach(pid_t pid);
int tracer_detach(pid_t pid);

/* ---- Interception layer (src/trace.c) ---- */

/* Install SIGINT/SIGTERM handlers (no SA_RESTART) used to detach cleanly.
 * Call BEFORE tracer_attach() in attach mode. */
void tracer_install_stop_handlers(void);

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

#endif /* TRACER_H */