#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "tracer.h"

int tracer_set_options(pid_t pid, bool exit_kill)
{
    long opts = PTRACE_O_TRACESYSGOOD;      /* syscall stops = SIGTRAP|0x80 */

    if (exit_kill)
        opts |= PTRACE_O_EXITKILL;          /* tracee dies if we die        */

    if (ptrace(PTRACE_SETOPTIONS, pid, 0, opts) == -1) {
        perror("ptrace(PTRACE_SETOPTIONS)");
        return -1;
    }
    return 0;
}

pid_t tracer_spawn(char *const argv[])
{
    pid_t pid = fork();

    if (pid < 0) {
        perror("fork");
        return -1;
    }

    if (pid == 0) {
        /* ---------- child ---------- */
        if (ptrace(PTRACE_TRACEME, 0, 0, 0) == -1) {
            perror("ptrace(PTRACE_TRACEME)");
            _exit(126);
        }

        /* Stop ourselves so the parent can finish setup before exec. */
        raise(SIGSTOP);

        execvp(argv[0], argv);

        /* Only reached if exec failed. */
        fprintf(stderr, "mini_strace: cannot exec '%s': %s\n",
                argv[0], strerror(errno));
        _exit(127);
    }

    /* ---------- parent ---------- */
    int status;

    if (waitpid(pid, &status, 0) == -1) {
        perror("waitpid");
        return -1;
    }

    if (!WIFSTOPPED(status) || WSTOPSIG(status) != SIGSTOP) {
        fprintf(stderr, "mini_strace: child did not stop as expected\n");
        return -1;
    }

    if (tracer_set_options(pid, true) == -1) {
        kill(pid, SIGKILL);
        waitpid(pid, NULL, 0);
        return -1;
    }

    return pid;
}

int tracer_attach(pid_t pid)
{
    int status;

    if (pid == getpid()) {
        fprintf(stderr, "mini_strace: cannot attach to myself\n");
        return -1;
    }

    if (ptrace(PTRACE_ATTACH, pid, 0, 0) == -1) {
        int e = errno;
        fprintf(stderr, "mini_strace: cannot attach to pid %d: %s\n",
                pid, strerror(e));
        if (e == EPERM)
            fprintf(stderr,
                "  hint: run as root (sudo), or check "
                "/proc/sys/kernel/yama/ptrace_scope\n");
        return -1;
    }

    if (waitpid(pid, &status, __WALL) == -1) {
        perror("waitpid");
        return -1;
    }

    if (!WIFSTOPPED(status)) {
        fprintf(stderr, "mini_strace: pid %d exited during attach\n", pid);
        return -1;
    }

    if (tracer_set_options(pid, false) == -1) {
        ptrace(PTRACE_DETACH, pid, 0, 0);
        return -1;
    }

    return 0;
}

int tracer_detach(pid_t pid)
{
    int status;

    if (kill(pid, SIGSTOP) == -1)
        return (errno == ESRCH) ? 0 : -1;

    for (;;) {
        if (waitpid(pid, &status, __WALL) == -1)
            return (errno == ECHILD) ? 0 : -1;

        if (!WIFSTOPPED(status))
            return 0;

        int sig = WSTOPSIG(status);
        if (sig == SIGSTOP)
            break;

        if (sig == SIGTRAP || sig == (SIGTRAP | 0x80))
            sig = 0;
        ptrace(PTRACE_CONT, pid, 0, (void *)(intptr_t)sig);
    }

    if (ptrace(PTRACE_DETACH, pid, 0, 0) == -1) {
        perror("ptrace(PTRACE_DETACH)");
        return -1;
    }
    return 0;
}