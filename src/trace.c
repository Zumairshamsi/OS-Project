#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/signalfd.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>
#include <time.h>

#include "tracer.h"

#ifndef __x86_64__
#error "This tracer decodes x86_64 registers only (see proposal scope)."
#endif

#define SYSCALL_STOP (SIGTRAP | 0x80)   /* what PTRACE_O_TRACESYSGOOD reports */
#define MAX_ERRNO    4095               /* kernel: IS_ERR_VALUE range         */

/* ------------------------------------------------------------------ */
/* Data structures                                                     */
/* ------------------------------------------------------------------ */

/* One traced process or thread. Heap-allocated so pointers stay valid
 * while new tracees are added during event handling. */
typedef struct tracee {
    struct tracee *next;
    pid_t          pid;                 /* really a TID                      */
    bool           in_syscall;          /* next syscall stop is an EXIT      */
    bool           have_entry;          /* cur holds a valid entry record    */
    bool           cur_traced;          /* cur passed the -e filter          */
    bool           awaiting_init_stop;  /* auto-attached child: its first
                                           SIGSTOP has not been seen yet     */
    syscall_rec_t  cur;
    unsigned long  entries;
    unsigned long  exits;
    unsigned long  resyncs;
} tracee_t;

typedef struct {
    tracee_t     *head;
    int           nlive;                /* tracees currently in the list     */
    int           ever;                 /* tracees ever created              */
    pid_t         root;                 /* spawned child / attached PID      */
    int           root_code;            /* exit code to return               */
    int           sfd;                  /* signalfd                          */
    const syscall_filter_t *filter;     /* from the command line             */
    FILE         *out;                  /* trace destination                 */
    bool          quiet;                /* -c: no per-event lines            */
    stats_t      *stats;                /* NULL unless -c                    */
    int64_t       t0_ns;                /* CLOCK_MONOTONIC at tracer start   */
    int           interrupt_sig;        /* SIGINT/SIGTERM seen, else 0       */
    unsigned long entries, exits, resyncs;   /* totals of finished tracees   */
} session_t;

static tracee_t *find_tracee(const session_t *s, pid_t pid)
{
    for (tracee_t *t = s->head; t; t = t->next)
        if (t->pid == pid)
            return t;
    return NULL;
}

static tracee_t *add_tracee(session_t *s, pid_t pid, bool awaiting)
{
    tracee_t *t = calloc(1, sizeof *t);

    if (!t) {
        perror("calloc");
        exit(EXIT_FAILURE);             /* EXITKILL/kernel clean up for us */
    }
    t->pid = pid;
    t->awaiting_init_stop = awaiting;
    t->next = s->head;
    s->head = t;
    s->nlive++;
    s->ever++;
    return t;
}

static void remove_tracee(session_t *s, tracee_t *t)
{
    for (tracee_t **pp = &s->head; *pp; pp = &(*pp)->next) {
        if (*pp == t) {
            *pp = t->next;
            break;
        }
    }
    s->entries += t->entries;
    s->exits   += t->exits;
    s->resyncs += t->resyncs;
    s->nlive--;
    free(t);
}

/* ------------------------------------------------------------------ */
/* Clock and line prefixes                                             */
/* ------------------------------------------------------------------ */

static int64_t now_ns(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000000000LL + ts.tv_nsec;
}

/* "[  1.234567] " : seconds.microseconds since the tracer started. */
static void put_stamp(const session_t *s, int64_t ns)
{
    int64_t rel = ns - s->t0_ns;

    if (rel < 0)
        rel = 0;
    fprintf(s->out, "[%3lld.%06lld] ",
            (long long)(rel / 1000000000LL),
            (long long)((rel % 1000000000LL) / 1000));
}

/* Timestamp, then "[pid N] " once more than one process/thread existed. */
static void prefix_at(const session_t *s, const tracee_t *t, int64_t ns)
{
    put_stamp(s, ns);
    if (s->ever > 1)
        fprintf(s->out, "[pid %d] ", t->pid);
}

static void prefix(const session_t *s, const tracee_t *t)
{
    prefix_at(s, t, now_ns());
}

/* ------------------------------------------------------------------ */
/* Signal names and reporting                                          */
/* ------------------------------------------------------------------ */

static const char *signame(int sig, char *buf, size_t n)
{
#define SN(x) [x] = #x
    static const char *const names[32] = {
        SN(SIGHUP), SN(SIGINT), SN(SIGQUIT), SN(SIGILL), SN(SIGTRAP),
        SN(SIGABRT), SN(SIGBUS), SN(SIGFPE), SN(SIGKILL), SN(SIGUSR1),
        SN(SIGSEGV), SN(SIGUSR2), SN(SIGPIPE), SN(SIGALRM), SN(SIGTERM),
        SN(SIGSTKFLT), SN(SIGCHLD), SN(SIGCONT), SN(SIGSTOP), SN(SIGTSTP),
        SN(SIGTTIN), SN(SIGTTOU), SN(SIGURG), SN(SIGXCPU), SN(SIGXFSZ),
        SN(SIGVTALRM), SN(SIGPROF), SN(SIGWINCH), SN(SIGIO), SN(SIGPWR),
        SN(SIGSYS),
    };
#undef SN
    if (sig > 0 && sig < 32 && names[sig])
        return names[sig];
    snprintf(buf, n, "SIG%d", sig);
    return buf;
}

static bool is_stop_signal(int sig)
{
    return sig == SIGSTOP || sig == SIGTSTP || sig == SIGTTIN ||
           sig == SIGTTOU;
}

/* Print a signal-delivery-stop in strace style. */
static void report_signal(const session_t *s, const tracee_t *t, int sig)
{
    if (s->quiet)
        return;
    siginfo_t si;
    char nb[24];
    const char *nm = signame(sig, nb, sizeof nb);

    prefix(s, t);

    if (ptrace(PTRACE_GETSIGINFO, t->pid, 0, &si) == -1) {
        fprintf(s->out, "--- %s ---\n", nm);
        return;
    }

    switch (sig) {
    case SIGSEGV:
    case SIGBUS:
    case SIGILL:
    case SIGFPE:
        if (sig == SIGSEGV && si.si_code == SEGV_MAPERR)
            fprintf(s->out, "--- %s {si_code=SEGV_MAPERR, si_addr=%p} ---\n",
                    nm, si.si_addr);
        else if (sig == SIGSEGV && si.si_code == SEGV_ACCERR)
            fprintf(s->out, "--- %s {si_code=SEGV_ACCERR, si_addr=%p} ---\n",
                    nm, si.si_addr);
        else
            fprintf(s->out, "--- %s {si_code=%d, si_addr=%p} ---\n",
                    nm, si.si_code, si.si_addr);
        break;
    case SIGCHLD:
        fprintf(s->out, "--- %s {si_pid=%d, si_status=%d} ---\n",
                nm, (int)si.si_pid, si.si_status);
        break;
    default:
        if (si.si_code <= 0)            /* kill(), sigqueue(), tkill()... */
            fprintf(s->out, "--- %s {si_pid=%d, si_uid=%u} ---\n",
                    nm, (int)si.si_pid, (unsigned)si.si_uid);
        else
            fprintf(s->out, "--- %s ---\n", nm);
        break;
    }
}

static void report_exit(const session_t *s, const tracee_t *t, int status)
{
    if (s->quiet)
        return;
    prefix(s, t);
    if (WIFEXITED(status)) {
        fprintf(s->out, "+++ exited with %d +++\n", WEXITSTATUS(status));
    } else {
        char nb[24];

        fprintf(s->out, "+++ killed by %s%s +++\n",
                signame(WTERMSIG(status), nb, sizeof nb),
                WCOREDUMP(status) ? " (core dumped)" : "");
    }
}

/* ------------------------------------------------------------------ */
/* Race-free Ctrl+C: block the signals and read them from a signalfd   */
/* ------------------------------------------------------------------ */

static int setup_signals(session_t *s)
{
    struct sigaction sa;
    sigset_t mask;

    /* An inherited SIG_IGN for SIGCHLD would stop the kernel from
     * generating it, and we rely on it to wake up. */
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = SIG_DFL;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGCHLD, &sa, NULL);

    sigemptyset(&mask);
    sigaddset(&mask, SIGCHLD);
    sigaddset(&mask, SIGINT);
    sigaddset(&mask, SIGTERM);

    if (sigprocmask(SIG_BLOCK, &mask, NULL) == -1) {
        perror("sigprocmask");
        return -1;
    }
    s->sfd = signalfd(-1, &mask, SFD_NONBLOCK | SFD_CLOEXEC);
    if (s->sfd == -1) {
        perror("signalfd");
        return -1;
    }
    return 0;
}

/* Consume everything queued on the signalfd; remember SIGINT/SIGTERM. */
static void drain_signals(session_t *s)
{
    struct signalfd_siginfo si;

    while (read(s->sfd, &si, sizeof si) == (ssize_t)sizeof si)
        if ((si.ssi_signo == SIGINT || si.ssi_signo == SIGTERM) &&
            !s->interrupt_sig)
            s->interrupt_sig = (int)si.ssi_signo;
}

/* Wait for any tracee to change state.
 * Returns 1 with pid and status filled, 0 if the user interrupted us,
 * -1 on error (errno set; ECHILD means no tracees are left). */
static int wait_any(session_t *s, int *status, pid_t *pid)
{
    for (;;) {
        pid_t r;

        drain_signals(s);               /* checked on EVERY iteration */
        if (s->interrupt_sig)
            return 0;

        r = waitpid(-1, status, __WALL | WNOHANG);
        if (r > 0) {
            *pid = r;
            return 1;
        }
        if (r < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }

        /* Nothing ready. Any new state change queues SIGCHLD on the
         * signalfd, so this wakes up immediately; the timeout is only a
         * defensive upper bound. */
        struct pollfd p = { .fd = s->sfd, .events = POLLIN };
        (void)poll(&p, 1, 250);
    }
}

/* ------------------------------------------------------------------ */
/* Registers                                                           */
/* ------------------------------------------------------------------ */

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

/* ------------------------------------------------------------------ */
/* Syscall output                                                      */
/* ------------------------------------------------------------------ */
static void print_syscall(const session_t *s, const tracee_t *t,
                          const syscall_rec_t *r, bool have_args,
                          bool returned)
{
    if (s->quiet)
        return;
    const char *name = syscall_name(r->nr);

    /* Stamp = when the call began (unknown if we attached mid-call). */
    prefix_at(s, t, have_args ? r->start_ns : now_ns());

    if (name)
        fputs(name, s->out);
    else
        fprintf(s->out, "syscall_%ld", r->nr);

    fputc('(', s->out);
    fputs(have_args ? r->argstr : "?", s->out);
    fputc(')', s->out);

    if (!returned) {
        fputs(" = ?", s->out);
    } else if (r->failed) {
        const char *en = errno_name(r->err);
        if (en)
            fprintf(s->out, " = -1 %s (%s)", en, strerror(r->err));
        else
            fprintf(s->out, " = -1 errno %d (%s)", r->err, strerror(r->err));
    } else if (decode_ret_is_pointer(r->nr)) {
        fprintf(s->out, " = 0x%lx", (unsigned long)r->ret);
    } else {
        fprintf(s->out, " = %ld", r->ret);
    }

    if (returned && r->dur_ns >= 0)
        fprintf(s->out, " <%lld.%06lld>",
                (long long)(r->dur_ns / 1000000000LL),
                (long long)((r->dur_ns % 1000000000LL) / 1000));

    fputc('\n', s->out);
}

static void handle_syscall_stop(session_t *s, tracee_t *t, int64_t stop_ns)
{
    struct user_regs_struct regs;

    if (get_regs(t->pid, &regs) == -1) {
        t->in_syscall = !t->in_syscall;     /* keep the toggle moving */
        return;
    }

    /* Resync: a genuine ENTRY always has rax == -ENOSYS. */
    if (!t->in_syscall && (long)regs.rax != -ENOSYS) {
        t->in_syscall = true;
        t->resyncs++;
    }

    if (!t->in_syscall) {
        /* ---- ENTRY ---- */
        fill_entry(&t->cur, &regs);
        t->cur_traced = filter_allows(s->filter, t->cur.nr);
        if (t->cur_traced && !s->quiet)         /* skip the memory reads  */
            decode_args(t->pid, &t->cur, false);/* for filtered-out calls */
        t->cur.start_ns = now_ns();             /* after our decoding cost */
        t->cur.dur_ns   = -1;
        t->have_entry = true;
        t->in_syscall = true;
        t->entries++;

        if (t->cur_traced && never_returns(t->cur.nr))
            print_syscall(s, t, &t->cur, true, false);
    } else {
        /* ---- EXIT ---- */
        syscall_rec_t *r = &t->cur;

        if (!t->have_entry) {
            /* Attached mid-syscall: we never saw the arguments. */
            memset(r, 0, sizeof(*r));
            r->nr = (long)regs.orig_rax;
            t->cur_traced = filter_allows(s->filter, r->nr);
        }
        fill_exit(r, &regs);
        r->dur_ns = t->have_entry ? stop_ns - r->start_ns : -1;

        if (t->cur_traced) {
            if (!s->quiet) {
                /* Output buffers (read, readlink...) are only valid now. */
                if (t->have_entry && decode_has_output_buf(r->nr))
                    decode_args(t->pid, r, true);
                print_syscall(s, t, r, t->have_entry, true);
            }
            if (s->stats)
                stats_record(s->stats, r);
        }

        t->have_entry = false;
        t->in_syscall = false;
        t->exits++;
    }
}

/* ------------------------------------------------------------------ */
/* Event stops and signal stops                                        */
/* ------------------------------------------------------------------ */

static void handle_event(session_t *s, tracee_t *t, int event)
{
    unsigned long msg;

    switch (event) {
    case PTRACE_EVENT_FORK:
    case PTRACE_EVENT_VFORK:
    case PTRACE_EVENT_CLONE:
        /* The new child is already traced by the kernel. Register it unless
         * its initial SIGSTOP was reported (and the child created) first. */
        if (ptrace(PTRACE_GETEVENTMSG, t->pid, 0, &msg) == -1) {
            if (errno != ESRCH)
                perror("ptrace(PTRACE_GETEVENTMSG)");
            return;
        }
        if (!find_tracee(s, (pid_t)msg))
            add_tracee(s, (pid_t)msg, true);
        break;

    case PTRACE_EVENT_EXEC:
        /* Nothing to do: the execve entry was already decoded, and its exit
         * stop follows. The old address space is gone, which is why paths
         * are read at entry. */
        break;

    default:
        break;
    }
}

/* A non-syscall, non-event stop. Returns the signal to deliver on resume. */
static int handle_signal_stop(session_t *s, tracee_t *t, int sig)
{
    siginfo_t si;

    /* Signal-delivery-stop has siginfo; a group-stop does not (EINVAL).
     * Without PTRACE_SEIZE we cannot keep a group-stopped tracee stopped
     * (no PTRACE_LISTEN), so we report it and let it run. */
    if (is_stop_signal(sig) &&
        ptrace(PTRACE_GETSIGINFO, t->pid, 0, &si) == -1 && errno == EINVAL) {
        char nb[24];

        prefix(s, t);
        if (!s->quiet)
            fprintf(s->out, "--- stopped by %s ---\n", signame(sig, nb, sizeof nb));
        return 0;
    }

    report_signal(s, t, sig);
    return sig;                         /* deliver it to the program */
}

static void resume(const tracee_t *t, int sig)
{
    if (ptrace(PTRACE_SYSCALL, t->pid, 0, (void *)(intptr_t)sig) == -1 &&
        errno != ESRCH)                 /* ESRCH: killed; waitpid reports it */
        perror("ptrace(PTRACE_SYSCALL)");
}

/* ------------------------------------------------------------------ */
/* Main loop                                                           */
/* ------------------------------------------------------------------ */

static void detach_all(session_t *s)
{
    for (tracee_t *t = s->head; t; t = t->next)
        if (tracer_detach(t->pid) == 0)
            fprintf(stderr, "+++ detached from pid %d +++\n", t->pid);
}

int tracer_run(pid_t pid, bool attached, const tracer_config_t *cfg)
{
    session_t s = { .root = pid, .root_code = EXIT_FAILURE, .sfd = -1 };
    int ret;


    syscalls_init();
    if (setup_signals(&s) == -1)
        return EXIT_FAILURE;
    s.t0_ns = now_ns();
    s.filter = &cfg->filter;
    s.out = cfg->out ? cfg->out : stderr;
    s.quiet = cfg->summary;
    if (cfg->summary) {
        s.stats = stats_create();
        if (!s.stats) {
            close(s.sfd);
            return EXIT_FAILURE;
        }
    }

    /* The root tracee is already stopped and has had its options set. */
    add_tracee(&s, pid, false);
    resume(s.head, 0);

    while (s.nlive > 0) {
        int     status;
        pid_t   wpid;
        tracee_t *t;
        int     w = wait_any(&s, &status, &wpid);

        if (w == 0) {                               /* Ctrl+C / SIGTERM */
            detach_all(&s);
            s.root_code = attached ? EXIT_SUCCESS : 128 + s.interrupt_sig;
            break;
        }
        if (w < 0) {
            if (errno != ECHILD)
                perror("waitpid");
            break;
        }

        /* A child can be reported before its parent's clone event. */
        t = find_tracee(&s, wpid);
        if (!t)
            t = add_tracee(&s, wpid, true);

        if (WIFEXITED(status) || WIFSIGNALED(status)) {
            report_exit(&s, t, status);
            if (t->pid == s.root)
                s.root_code = WIFEXITED(status) ? WEXITSTATUS(status)
                                                : 128 + WTERMSIG(status);
            remove_tracee(&s, t);
            continue;
        }
        if (!WIFSTOPPED(status))
            continue;

        int64_t stop_ns = now_ns();     /* right after waitpid returned */
        int stopsig = WSTOPSIG(status);
        int event   = status >> 16;     /* PTRACE_EVENT_* or 0 */
        int deliver = 0;

        if (stopsig == SYSCALL_STOP) {
            handle_syscall_stop(&s, t, stop_ns);
        } else if (stopsig == SIGTRAP && event) {
            handle_event(&s, t, event);
        } else if (t->awaiting_init_stop && stopsig == SIGSTOP) {
            t->awaiting_init_stop = false;  /* auto-attach start: swallow */
        } else {
            deliver = handle_signal_stop(&s, t, stopsig);
        }
        resume(t, deliver);
    }

    ret = s.root_code;

    while (s.head)
        remove_tracee(&s, s.head);          /* also folds counters into s */

    if (s.stats) {
        stats_print(s.out, s.stats);
        stats_destroy(s.stats);
    } else {
        fprintf(s.out, "(entries=%lu exits=%lu resyncs=%lu tracees=%d)\n",
                s.entries, s.exits, s.resyncs, s.ever);
    }

    close(s.sfd);
    return ret;
}