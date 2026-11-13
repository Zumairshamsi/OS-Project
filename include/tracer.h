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

/* ---- Process control layer (src/control.c) ---- */
int tracer_set_options(pid_t pid, bool exit_kill);
pid_t tracer_spawn(char *const argv[]);

int tracer_attach(pid_t pid);
int tracer_detach(pid_t pid);

#endif /* TRACER_H */