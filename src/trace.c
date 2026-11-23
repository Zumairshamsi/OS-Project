#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "tracer.h"

#define SYSCALL_STOP (SIGTRAP | 0x80)   /* what PTRACE_O_TRACESYSGOOD reports */

/* Per-tracee state. One tracee for now; Step 8 extends this to children. */
typedef struct {
    pid_t         pid;
    bool          in_syscall;   /* false: next syscall stop is an ENTRY
                                   true : next syscall stop is an EXIT  */
    unsigned long entries;
    unsigned long exits;
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

/* ---------- syscall stop handlers ---------- */

static void on_syscall_entry(tracee_t *t)
{
    t->entries++;
    fprintf(stderr, "[pid %d] syscall entry #%lu\n", t->pid, t->entries);
}

static void on_syscall_exit(tracee_t *t)
{
    t->exits++;
    fprintf(stderr, "[pid %d] syscall exit  #%lu\n", t->pid, t->exits);
}

/* ---------- main loop ---------- */

int tracer_run(pid_t pid, bool attached, const tracer_config_t *cfg)
{
    tracee_t t = { .pid = pid };
    int  status;
    int  sig = 0;               /* signal to deliver on the next resume */
    bool resume = true;

    (void)cfg;                  /* used from Step 7 onwards */

    for (;;) {
        if (resume &&
            ptrace(PTRACE_SYSCALL, t.pid, 0, (void *)(intptr_t)sig) == -1) {
            perror("ptrace(PTRACE_SYSCALL)");
            return EXIT_FAILURE;
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
            fprintf(stderr, "(entries=%lu exits=%lu)\n", t.entries, t.exits);
            return WEXITSTATUS(status);
        }
        if (WIFSIGNALED(status)) {
            fprintf(stderr, "+++ killed by signal %d +++\n", WTERMSIG(status));
            fprintf(stderr, "(entries=%lu exits=%lu)\n", t.entries, t.exits);
            return 128 + WTERMSIG(status);
        }
        if (!WIFSTOPPED(status))
            continue;

        int stopsig = WSTOPSIG(status);

        if (stopsig == SYSCALL_STOP) {
            /* Entry/exit toggle: kernel stops us once before and once
             * after every syscall, always alternating. */
            if (!t.in_syscall) {
                on_syscall_entry(&t);
                t.in_syscall = true;
            } else {
                on_syscall_exit(&t);
                t.in_syscall = false;
            }
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