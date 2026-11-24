# Mini strace: Linux System Call Tracer

Course: Operating Systems (CS 2006), Fall 2026, FAST University
Authors: Zumair Shamsi (24K-2040), Huzaifa Zafar (24K-2044), Roohan Siddiqui (24K-2018)
Instructor: Sandesh Kumar

A lightweight system call tracer for Linux x86_64 in C11 built on `ptrace(2)`.

## Features
- Spawn a command (`fork`, `PTRACE_TRACEME`, `execvp`) or attach to a PID (`PTRACE_ATTACH`, clean detach on Ctrl+C)
- Syscall entry/exit interception (`PTRACE_SYSCALL`), names, return values, errno names
- Argument decoding (paths, flags, buffers, argv) via `process_vm_readv` with `PTRACE_PEEKDATA` fallback
- Microsecond timestamps and per-call duration (`CLOCK_MONOTONIC`)
- `-e trace=a,b` bitmask filter, `-c` statistics table, `-o FILE` output redirection
- Follows fork/vfork/clone/exec; reports signals and process exit

## Build
    make          # build
    make asan     # AddressSanitizer + UBSan build
    make test     # automated tests (sudo bash tests/run_tests.sh to include attach tests)
    make bench    # overhead benchmark + probing demo
    make samples  # writes docs/samples.txt

## Usage
    mini_strace [-c] [-o file] [-e trace=a,b,c] -p PID
    mini_strace [-c] [-o file] [-e trace=a,b,c] command [args...]

Exit status is the traced program's (128+N if killed by signal N).

Examples:

    ./mini_strace ls /tmp
    ./mini_strace -e trace=openat,read,write cat /etc/hostname
    ./mini_strace -c -o stats.log ls /usr/include
    sudo ./mini_strace -p $(pgrep -n sshd)

## Layout
    include/tracer.h   shared types/interfaces
    src/main.c         CLI, -o handling       src/control.c   spawn/attach/detach
    src/trace.c        interception loop      src/syscalls.c  name hash map
    src/memory.c       tracee memory reads    src/decode.c    argument decoder
    src/filter.c       -e bitmask             src/stats.c     -c table
    tools/gen_tables.sh  generates syscall/errno tables from host headers
    tests/             run_tests.sh, bench.sh, samples.sh
    docs/REPORT_NOTES.md  architecture, traceability, design notes

## Limitations
x86_64 only; ~70 syscalls have decoded arguments (others print hex); struct arguments shown as addresses; durations include ptrace round-trip; no `PTRACE_SEIZE`/`LISTEN` group-stop; attach traces only the given TID (+ later children); `-e` takes names only.

## References
1. M. Kerrisk, *The Linux Programming Interface*, No Starch Press, 2010.
2. ptrace(2), process_vm_readv(2), signalfd(2), Linux man-pages.
