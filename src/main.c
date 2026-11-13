#include <errno.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <stdint.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <stdbool.h>
#include "tracer.h"

static void usage(const char *prog)
{
    fprintf(stderr,
        "Usage:\n"
        "  %s [-c] [-o file] [-e trace=sc1,sc2,...] -p PID\n"
        "  %s [-c] [-o file] [-e trace=sc1,sc2,...] command [args...]\n"
        "\n"
        "Options:\n"
        "  -p PID           attach to a running process\n"
        "  -e trace=LIST    only trace the listed system calls\n"
        "  -c               print a per-syscall statistics summary at exit\n"
        "  -o FILE          write trace output to FILE instead of stderr\n"
        "  -h               show this help\n",
        prog, prog);
}

static int parse_args(int argc, char **argv, tracer_config_t *cfg)
{
    int opt;

    memset(cfg, 0, sizeof(*cfg));

    while ((opt = getopt(argc, argv, "+p:o:e:ch")) != -1) {
        switch (opt) {
        case 'p': {
            char *end;
            errno = 0;
            long v = strtol(optarg, &end, 10);
            if (errno || *end != '\0' || v <= 0) {
                fprintf(stderr, "%s: invalid PID '%s'\n", argv[0], optarg);
                return -1;
            }
            cfg->attach_pid = (pid_t)v;
            break;
        }
        case 'o':
            cfg->out_path = optarg;
            break;
        case 'e':
            if (strncmp(optarg, "trace=", 6) != 0 || optarg[6] == '\0') {
                fprintf(stderr, "%s: expected -e trace=name1,name2,...\n",
                        argv[0]);
                return -1;
            }
            cfg->filter_str = optarg + 6;
            break;
        case 'c':
            cfg->summary = true;
            break;
        case 'h':
        default:
            return -1;
        }
    }

    if (optind < argc)
        cfg->cmd_argv = &argv[optind];

    /* Exactly one mode: attach (-p) XOR spawn (command). */
    if (cfg->attach_pid && cfg->cmd_argv) {
        fprintf(stderr, "%s: use either -p PID or a command, not both\n",
                argv[0]);
        return -1;
    }
    if (!cfg->attach_pid && !cfg->cmd_argv) {
        fprintf(stderr, "%s: must specify -p PID or a command\n", argv[0]);
        return -1;
    }
    return 0;
}


/* Set by the signal handler in attach mode so we can detach cleanly. */
static volatile sig_atomic_t g_stop = 0;

static void on_stop_signal(int sig)
{
    (void)sig;
    g_stop = 1;
}

static void install_stop_handlers(void)
{
    struct sigaction sa;

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_stop_signal;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;            /* no SA_RESTART: waitpid must return EINTR */

    sigaction(SIGINT,  &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
}


static int run_until_exit(pid_t pid, bool attached)
{
    int status;
    int sig = 0;
    bool resume = true;

    for (;;) {
        if (resume && ptrace(PTRACE_CONT, pid, 0, (void *)(intptr_t)sig) == -1) {
            perror("ptrace(PTRACE_CONT)");
            return EXIT_FAILURE;
        }
        resume = true;
        sig = 0;

        if (waitpid(pid, &status, __WALL) == -1) {
            if (errno == EINTR) {
                if (attached && g_stop) {
                    if (tracer_detach(pid) == 0)
                        fprintf(stderr, "+++ detached from pid %d +++\n", pid);
                    return EXIT_SUCCESS;
                }
                resume = false;     /* tracee still running: just wait again */
                continue;
            }
            perror("waitpid");
            return EXIT_FAILURE;
        }

        if (WIFEXITED(status)) {
            fprintf(stderr, "+++ exited with %d +++\n", WEXITSTATUS(status));
            return WEXITSTATUS(status);
        }
        if (WIFSIGNALED(status)) {
            fprintf(stderr, "+++ killed by signal %d +++\n", WTERMSIG(status));
            return 128 + WTERMSIG(status);
        }
        if (WIFSTOPPED(status)) {
            sig = WSTOPSIG(status);
            /* SIGTRAP after execve is ours; everything else is forwarded. */
            if (sig == SIGTRAP)
                sig = 0;
        }
    }
}

int main(int argc, char **argv)
{
    tracer_config_t cfg;
    pid_t pid;
    bool attached = false;

    if (parse_args(argc, argv, &cfg) < 0) {
        usage(argv[0]);
        return EXIT_FAILURE;
    }

    if (cfg.attach_pid) {
        pid = cfg.attach_pid;
        install_stop_handlers();
        if (tracer_attach(pid) < 0)
            return EXIT_FAILURE;
        attached = true;
        fprintf(stderr, "+++ attached to pid %d +++\n", pid);
    } else {
        pid = tracer_spawn(cfg.cmd_argv);
        if (pid < 0)
            return EXIT_FAILURE;
    }

    return run_until_exit(pid, attached);
}