#define _GNU_SOURCE
#include <errno.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

int main(int argc, char **argv)
{
    tracer_config_t cfg;

    if (parse_args(argc, argv, &cfg) < 0) {
        usage(argv[0]);
        return EXIT_FAILURE;
    }

    /* Temporary: just shows what we parsed. Replaced in Step 2. */
    printf("mode    : %s\n", cfg.attach_pid ? "attach" : "spawn");
    if (cfg.attach_pid)
        printf("pid     : %d\n", cfg.attach_pid);
    else
        printf("command : %s\n", cfg.cmd_argv[0]);
    printf("filter  : %s\n", cfg.filter_str ? cfg.filter_str : "(none)");
    printf("summary : %s\n", cfg.summary ? "yes" : "no");
    printf("output  : %s\n", cfg.out_path ? cfg.out_path : "stderr");

    return EXIT_SUCCESS;
}