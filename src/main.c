#include <errno.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <stdint.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
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


static int run_until_exit(pid_t pid)
{
    int status;
    int sig = 0;

    for (;;) {
        if (ptrace(PTRACE_CONT, pid, 0, (void *)(intptr_t)sig) == -1) {
            perror("ptrace(PTRACE_CONT)");
            return EXIT_FAILURE;
        }
        if (waitpid(pid, &status, 0) == -1) {
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
            if (sig == SIGTRAP)
                sig = 0;
        }
    }
}

int main(int argc, char **argv)
{
    tracer_config_t cfg;

    if (parse_args(argc, argv, &cfg) < 0) {
        usage(argv[0]);
        return EXIT_FAILURE;
    }

    if (cfg.attach_pid) {
        fprintf(stderr, "%s: attach mode not implemented yet (Step 3)\n",
                argv[0]);
        return EXIT_FAILURE;
    }

    pid_t pid = tracer_spawn(cfg.cmd_argv);
    if (pid < 0)
        return EXIT_FAILURE;

    return run_until_exit(pid);
}