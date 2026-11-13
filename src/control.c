#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <string.h>
#include "tracer.h"

int tracer_set_options(pid_t pid)
{
    long opts = PTRACE_O_TRACESYSGOOD   /* syscall stops = SIGTRAP|0x80 */
              | PTRACE_O_EXITKILL;      /* tracee dies if we die        */

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

        
        raise(SIGSTOP);
        execvp(argv[0], argv);

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
        /* Child died before reaching SIGSTOP (e.g. TRACEME failed). */
        fprintf(stderr, "mini_strace: child did not stop as expected\n");
        return -1;
    }

    if (tracer_set_options(pid) == -1) {
        kill(pid, SIGKILL);
        waitpid(pid, NULL, 0);
        return -1;
    }

    return pid;
}