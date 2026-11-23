#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>

#include "tracer.h"

#ifndef __x86_64__
#error "This tracer decodes x86_64 registers only (see proposal scope)."
#endif

#define SYSCALL_STOP (SIGTRAP | 0x80)   /* what PTRACE_O_TRACESYSGOOD reports */
#define MAX_ERRNO    4095               /* kernel: IS_ERR_VALUE range         */

/* Per-tracee state. One tracee for now; Step 8 extends this to children. */
typedef struct {
    pid_t         pid;
    bool          in_syscall;   /* false: next syscall stop should be ENTRY
                                   true : next syscall stop should be EXIT  */
    bool          have_entry;   /* cur holds a valid entry record           */
    syscall_rec_t cur;          /* syscall currently in progress            */
    unsigned long entries;
    unsigned long exits;
    unsigned long resyncs;      /* toggle corrections via the -ENOSYS check */
} tracee_t;

/* ---------- Ctrl+C handling (attach mode) ---------- */

static volatile sig_atomic_t g_stop = 0;

static void on_stop_signal(int sig)
{
    (void)sig;
    g_stop = 1;
}

void tracer_install_stop_handlers(void)
{
    struct sigaction sa;

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_stop_signal;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;            /* no SA_RESTART: waitpid must return EINTR */

    sigaction(SIGINT,  &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
}

/* ---------- register access ---------- */

static int get_regs(pid_t pid, struct user_regs_struct *regs)
{
    if (ptrace(PTRACE_GETREGS, pid, 0, regs) == -1) {
        if (errno != ESRCH)         /* ESRCH = tracee is dying: not an error */
            perror("ptrace(PTRACE_GETREGS)");
        return -1;
    }
    return 0;
}

static void fill_entry(syscall_rec_t *r, const struct user_regs_struct *regs)
{
    memset(r, 0, sizeof(*r));
    r->nr      = (long)regs->orig_rax;
    r->args[0] = regs->rdi;
    r->args[1] = regs->rsi;
    r->args[2] = regs->rdx;
    r->args[3] = regs->r10;
    r->args[4] = regs->r8;
    r->args[5] = regs->r9;
}

static void fill_exit(syscall_rec_t *r, const struct user_regs_struct *regs)
{
    r->ret = (long)regs->rax;
    if (r->ret >= -MAX_ERRNO && r->ret <= -1) {
        r->failed = true;
        r->err    = (int)-r->ret;
    } else {
        r->failed = false;
        r->err    = 0;
    }
}

/* Non-returning syscalls never get an exit stop. */
static bool never_returns(long nr)
{
    return nr == SYS_exit_group || nr == SYS_exit;
}

/* ---------- output (raw numbers for now; names in Step 6) ---------- */

static void print_syscall(const syscall_rec_t *r, bool have_args, bool returned)
{
    const char *name = syscall_name(r->nr);

    if (name)
        fputs(name, stderr);
    else
        fprintf(stderr, "syscall_%ld", r->nr);

    fputc('(', stderr);
    fputs(have_args ? r->argstr : "?", stderr);
    fputc(')', stderr);

    if (!returned) {
        fputs(" = ?\n", stderr);
    } else if (r->failed) {
        const char *en = errno_name(r->err);
        if (en)
            fprintf(stderr, " = -1 %s (%s)\n", en, strerror(r->err));
        else
            fprintf(stderr, " = -1 errno %d (%s)\n", r->err, strerror(r->err));
    } else if (decode_ret_is_pointer(r->nr)) {
        fprintf(stderr, " = 0x%lx\n", (unsigned long)r->ret);
    } else {
        fprintf(stderr, " = %ld\n", r->ret);
    }
}

/* ---------- one syscall stop ---------- */

static void handle_syscall_stop(tracee_t *t)
{
    struct user_regs_struct regs;

    if (get_regs(t->pid, &regs) == -1) {
        t->in_syscall = !t->in_syscall;     /* keep the toggle moving */
        return;
    }

    /* Resync: a genuine ENTRY always has rax == -ENOSYS. If we expected an
     * entry but rax says otherwise, this is really an EXIT stop. */
    if (!t->in_syscall && (long)regs.rax != -ENOSYS) {
        t->in_syscall = true;
        t->resyncs++;
    }

    if (!t->in_syscall) {
        /* ---- ENTRY ---- */
        fill_entry(&t->cur, &regs);
        decode_args(t->pid, &t->cur, false);    /* paths, input buffers */
        t->have_entry = true;
        t->in_syscall = true;
        t->entries++;

        if (never_returns(t->cur.nr))
            print_syscall(&t->cur, true, false);
    } else {
        /* ---- EXIT ---- */
        syscall_rec_t *r = &t->cur;

        if (!t->have_entry) {
            /* Attached mid-syscall: we never saw the arguments. */
            memset(r, 0, sizeof(*r));
            r->nr = (long)regs.orig_rax;
        }
        fill_exit(r, &regs);

        /* Output buffers (read, readlink...) are only valid now. */
        if (t->have_entry && decode_has_output_buf(r->nr))
            decode_args(t->pid, r, true);

        print_syscall(r, t->have_entry, true);

        t->have_entry = false;
        t->in_syscall = false;
        t->exits++;
    }
}

/* ---------- main loop ---------- */

static void print_totals(const tracee_t *t)
{
    fprintf(stderr, "(entries=%lu exits=%lu resyncs=%lu)\n",
            t->entries, t->exits, t->resyncs);
}

int tracer_run(pid_t pid, bool attached, const tracer_config_t *cfg)
{
    tracee_t t = { .pid = pid };
    int  status;
    int  sig = 0;               /* signal to deliver on the next resume */
    bool resume = true;

    (void)cfg;                  /* used from Step 7 onwards */
    syscalls_init();

    for (;;) {
        if (resume &&
            ptrace(PTRACE_SYSCALL, t.pid, 0, (void *)(intptr_t)sig) == -1) {
            if (errno == ESRCH) {
                resume = false;     /* tracee vanished: collect its status */
            } else {
                perror("ptrace(PTRACE_SYSCALL)");
                return EXIT_FAILURE;
            }
        }
        resume = true;
        sig = 0;

        if (waitpid(t.pid, &status, __WALL) == -1) {
            if (errno == EINTR) {
                if (attached && g_stop) {
                    if (tracer_detach(t.pid) == 0)
                        fprintf(stderr, "+++ detached from pid %d +++\n",
                                t.pid);
                    return EXIT_SUCCESS;
                }
                resume = false;     /* tracee still running: wait again */
                continue;
            }
            perror("waitpid");
            return EXIT_FAILURE;
        }

        if (WIFEXITED(status)) {
            fprintf(stderr, "+++ exited with %d +++\n", WEXITSTATUS(status));
            print_totals(&t);
            return WEXITSTATUS(status);
        }
        if (WIFSIGNALED(status)) {
            fprintf(stderr, "+++ killed by signal %d +++\n", WTERMSIG(status));
            print_totals(&t);
            return 128 + WTERMSIG(status);
        }
        if (!WIFSTOPPED(status))
            continue;

        int stopsig = WSTOPSIG(status);

        if (stopsig == SYSCALL_STOP) {
            handle_syscall_stop(&t);
        } else if (stopsig == SIGTRAP) {
            /* Post-execve trap: ours, do not deliver. (Step 8 replaces
             * this with PTRACE_O_TRACEEXEC.) */
            sig = 0;
        } else {
            /* A real signal destined for the tracee: pass it through. */
            sig = stopsig;
        }
    }
}