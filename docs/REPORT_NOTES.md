# Report notes: Mini strace

## Architecture (three layers from the proposal)
- Process Control & Interception: `control.c` (spawn/attach/detach/options), `trace.c` (waitpid(-1)+signalfd loop, per-tracee entry/exit toggle, fork/clone/exec events, signals)
- Data Extraction & Decoding: `memory.c` (process_vm_readv / PEEKDATA), `syscalls.c` (hash map), `decode.c` (table-driven), `filter.c` (bitmask)
- Output & Analytics: `trace.c` printers (timestamps, durations), `stats.c` (-c), single `FILE *out` for `-o`

## Proposal traceability
| Proposal item | Where |
|---|---|
| Attach by PID | control.c `tracer_attach/detach` |
| Spawn fork/TRACEME/execvp | control.c `tracer_spawn` |
| Entry/exit logging, toggle | trace.c `handle_syscall_stop` |
| Names, return values, errno -4095..-1 | syscalls.c, trace.c `fill_exit` |
| Creation/termination/signals | trace.c `handle_event`, `handle_signal_stop`, `report_exit` |
| Argument decoding | decode.c, memory.c |
| Timestamps (CLOCK_MONOTONIC) | trace.c `now_ns` |
| Filtering | filter.c |
| Statistics | stats.c |
| Output redirection | main.c, `s->out` |
| Validation vs ls/cat/curl/strace, benchmarking | tests/run_tests.sh, tests/bench.sh |

## Design decisions
1. Entry/exit toggle + `rax == -ENOSYS` resync for mid-syscall attach.
2. `PTRACE_O_TRACESYSGOOD` separates syscall stops from real SIGTRAP.
3. `EXITKILL` only in spawn mode.
4. Paths decoded at entry (execve destroys address space); output buffers at exit.
5. Tables generated from host headers (no hand-typed syscall list).
6. `signalfd` for race-free Ctrl+C.
7. One `FILE *out`; log opened with O_CLOEXEC.
8. `-c` counts only traced calls (like strace -c -e).

## Security perspective
Bursts of failing openat/access on distinct paths indicate probing (see `make bench`); the -c table profiles behaviour; ptrace is powerful, hence Yama ptrace_scope and container seccomp limits.

## Limitations / future work
seccomp-bpf pre-filter to reduce stops; struct decoding; socket syscalls; `-e` groups/negation; PTRACE_SEIZE for group-stop.
