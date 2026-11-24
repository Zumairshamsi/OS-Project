#!/usr/bin/env bash
# Automated tests for mini_strace.  Usage: tests/run_tests.sh   (or: make test)
set -u
cd "$(dirname "$0")/.."
MS=${MS:-./mini_strace}
[ -x "$MS" ] || { echo "mini_strace not built: run 'make' first"; exit 2; }
TMP=$(mktemp -d); BGPID=
trap '[ -n "$BGPID" ] && kill "$BGPID" 2>/dev/null; rm -rf "$TMP"' EXIT
PASS=0; FAIL=0; SKIP=0
ok()      { PASS=$((PASS+1)); printf '  [PASS] %s\n' "$1"; }
bad()     { FAIL=$((FAIL+1)); printf '  [FAIL] %s\n' "$1"; [ -n "${2:-}" ] && printf '         %s\n' "$2"; }
skip()    { SKIP=$((SKIP+1)); printf '  [SKIP] %s\n' "$1"; }
section() { printf '\n== %s ==\n' "$1"; }
check()   { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1" "expected '$2', got '$3'"; fi; }
norm()  { sed -E 's/^\[ *[0-9]+\.[0-9]+\] //; s/^\[pid +[0-9]+\] //; s/^[0-9]+ +//; s/ <[0-9]+\.[0-9]+>$//'; }
names() { norm | grep -oE '^[a-z_0-9]+\(' | tr -d '('; }
# successful execve lines only (execvp also tries failing PATH entries)
okexec() { norm | grep '^execve(' | grep -c ' = 0$'; }

printf 'hello-mini-strace\n' > "$TMP/data.txt"
mkdir "$TMP/dir"; : > "$TMP/dir/a"; : > "$TMP/dir/b"
HAVE_STRACE=0
command -v strace >/dev/null && strace -o /dev/null true 2>/dev/null && HAVE_STRACE=1

section "exit codes are preserved"
"$MS" -o /dev/null true;                  check "true -> 0" 0 $?
"$MS" -o /dev/null sh -c 'exit 3';        check "exit 3 -> 3" 3 $?
"$MS" -o /dev/null /nonexistent_cmd 2>/dev/null; check "missing command -> 127" 127 $?
"$MS" -o /dev/null sh -c 'kill -USR1 $$'; check "killed by SIGUSR1 -> 138" 138 $?
if command -v gcc >/dev/null; then
    printf 'int main(void){*(volatile int*)0=1;return 0;}' > "$TMP/segv.c"
    gcc -o "$TMP/segv" "$TMP/segv.c"
    "$MS" -o "$TMP/segv.log" "$TMP/segv"; check "SIGSEGV -> 139" 139 $?
    grep -q 'SIGSEGV {si_code=SEGV_MAPERR' "$TMP/segv.log" && ok "SIGSEGV reported with si_code" || bad "SIGSEGV line missing"
    "$MS" -e trace=write -o "$TMP/segv2.log" "$TMP/segv"
    grep -q -- '--- SIGSEGV' "$TMP/segv2.log" && ok "signals are not hidden by -e" || bad "signal hidden by filter"
else skip "SIGSEGV tests (no gcc)"; fi

section "command-line errors"
"$MS" >/dev/null 2>&1;                       check "no arguments -> 1" 1 $?
"$MS" -e trace=reed true >/dev/null 2>&1;    check "unknown syscall -> 1" 1 $?
"$MS" -e trace=read,,write true >/dev/null 2>&1; check "empty name -> 1" 1 $?
"$MS" -e read true >/dev/null 2>&1;          check "bad -e format -> 1" 1 $?
"$MS" -p 1 true >/dev/null 2>&1;             check "-p plus command -> 1" 1 $?
out=$("$MS" -o /nonexistent/x/log echo SHOULD-NOT-PRINT 2>/dev/null); rc=$?
check "unwritable -o fails early (rc)" 1 "$rc"
check "unwritable -o: program never ran" "" "$out"

section "the traced program is not disturbed"
check "stdout passes through" hello "$("$MS" -o "$TMP/t.log" echo hello)"
check "stdin passes through" abc "$(echo abc | "$MS" -o "$TMP/t.log" cat)"
check "nothing leaks to stderr with -o" 0 "$("$MS" -o "$TMP/t.log" true 2>&1 | wc -l | tr -d ' ')"

section "trace content"
"$MS" -o "$TMP/cat.log" cat "$TMP/data.txt" >/dev/null
norm < "$TMP/cat.log" > "$TMP/cat.norm"
grep -qF "openat(AT_FDCWD, \"$TMP/data.txt\", O_RDONLY" "$TMP/cat.norm" && ok "openat path and flags decoded" || bad "openat line not decoded"
grep -qF 'read(3, "hello-mini-strace\n"' "$TMP/cat.norm" && ok "read buffer decoded at exit" || bad "read buffer not decoded"
grep -qF 'write(1, "hello-mini-strace\n", 18) = 18' "$TMP/cat.norm" && ok "write buffer, count and return" || bad "write line wrong"
grep -q '^execve("' "$TMP/cat.norm" && ok "execve path decoded" || bad "execve line wrong"
"$MS" -o "$TMP/miss.log" cat "$TMP/missing" >/dev/null 2>&1
grep -q 'ENOENT (No such file or directory)' "$TMP/miss.log" && ok "errno name and message" || bad "ENOENT not shown"
"$MS" -o "$TMP/creat.log" sh -c "echo hi > $TMP/new.txt"
grep -qF 'O_WRONLY|O_CREAT|O_TRUNC, 0666' "$TMP/creat.log" && ok "open flags and mode decoded" || bad "O_CREAT line wrong"
check "every event line has a timestamp" 0 "$(grep -v '^(entries' "$TMP/cat.log" | grep -vcE '^\[ *[0-9]+\.[0-9]{6}\] ')"

section "timestamps and durations"
"$MS" -o "$TMP/ls.log" ls "$TMP/dir" >/dev/null
grep -oE '^\[ *[0-9]+\.[0-9]+\]' "$TMP/ls.log" | tr -d '[] ' | sort -c -n 2>/dev/null && ok "timestamps never go backwards" || bad "timestamps not monotonic"
"$MS" -o "$TMP/sleep.log" sleep 0.3
d=$(grep -E '\] (clock_)?nanosleep\(' "$TMP/sleep.log" | grep -oE '<[0-9]+\.[0-9]+>$' | tr -d '<>' | head -1)
if [ -n "$d" ] && awk -v d="$d" 'BEGIN{exit !(d>=0.29 && d<1.0)}'; then ok "sleep 0.3 measured as <$d>"; else bad "sleep duration wrong" "got '${d:-none}'"; fi

section "-e filtering"
"$MS" -o "$TMP/full.log" cat "$TMP/data.txt" >/dev/null
"$MS" -e trace=openat -o "$TMP/f1.log" cat "$TMP/data.txt" >/dev/null
check "trace=openat: same openat count as full trace" "$(norm < "$TMP/full.log" | grep -c '^openat(')" "$(norm < "$TMP/f1.log" | grep -c '^openat(')"
check "trace=openat: nothing else shown" 0 "$(norm < "$TMP/f1.log" | grep -E '^[a-z_0-9]+\(' | grep -vc '^openat(')"
"$MS" -e trace=read,write -o "$TMP/f2.log" cat "$TMP/data.txt" >/dev/null
check "trace=read,write: only those names" "read write " "$(names < "$TMP/f2.log" | sort -u | tr '\n' ' ')"
"$MS" -e trace=all -o "$TMP/f3.log" true
"$MS" -o "$TMP/f4.log" true
check "trace=all equals no filter (line count)" "$(wc -l < "$TMP/f4.log")" "$(wc -l < "$TMP/f3.log")"

section "-c statistics"
"$MS" -o "$TMP/full.log" ls "$TMP/dir" >/dev/null
"$MS" -c -o "$TMP/st.log" ls "$TMP/dir" >/dev/null
calls_trace=$(norm < "$TMP/full.log" | grep -E '^[a-z_0-9]+\(' | grep -vc ' = ?$')
calls_table=$(awk '$NF=="total"{print $3}' "$TMP/st.log")
check "table total calls == returning calls in full trace" "$calls_trace" "$calls_table"
check "-c hides per-call lines" 0 "$(grep -c '(' "$TMP/st.log")"
"$MS" -o "$TMP/full2.log" cat "$TMP/missing" >/dev/null 2>&1
"$MS" -c -o "$TMP/st2.log" cat "$TMP/missing" >/dev/null 2>&1
check "table total errors == '= -1' lines in full trace" "$(norm < "$TMP/full2.log" | grep -c ' = -1 ')" "$(awk '$NF=="total"{print (NF==5 ? $4 : 0)}' "$TMP/st2.log")"
"$MS" -c -e trace=write -o "$TMP/st3.log" echo hi >/dev/null
check "-c with -e: exactly one row" 1 "$(awk '$1 ~ /^[0-9.]+$/ && $NF!="total"' "$TMP/st3.log" | wc -l | tr -d ' ')"
"$MS" -c -e trace=mount -o "$TMP/st4.log" true
grep -q 'no system calls were traced' "$TMP/st4.log" && ok "-c with nothing traced" || bad "empty-table message missing"

section "-o redirection"
echo OLD > "$TMP/old.log"; "$MS" -o "$TMP/old.log" true
check "existing file is truncated" 0 "$(grep -c OLD "$TMP/old.log")"
out=$("$MS" -o "$TMP/fd.log" sh -c 'ls -l /proc/self/fd')
check "log fd not inherited by the tracee" 0 "$(printf '%s\n' "$out" | grep -c 'fd.log')"
"$MS" -o /dev/full sh -c 'exit 3' 2>"$TMP/err"; rc=$?
check "write error: tracee exit code kept" 3 "$rc"
grep -q 'error writing' "$TMP/err" && ok "write error is reported" || bad "write error not reported"

section "children, exec and signals"
"$MS" -o "$TMP/kids.log" sh -c '/bin/true; /bin/true'
check "successful execve in shell and both children" 3 "$(okexec < "$TMP/kids.log")"
grep -q '\[pid [0-9]*\]' "$TMP/kids.log" && ok "child lines carry [pid N]" || bad "no [pid N] prefix"
grep -q 'SIGCHLD {si_pid=' "$TMP/kids.log" && ok "SIGCHLD reported" || bad "SIGCHLD missing"
"$MS" -o "$TMP/sig.log" sh -c 'kill -USR1 $$'
grep -q -- '--- SIGUSR1 {si_pid=' "$TMP/sig.log" && grep -q 'killed by SIGUSR1' "$TMP/sig.log" && ok "signal and death by signal reported" || bad "signal lines missing"

section "comparison with GNU strace"
compare() {
    local label=$1; shift
    "$MS" -o "$TMP/m.log" "$@" >/dev/null 2>&1; local rm=$?
    strace -f -o "$TMP/s.log" "$@" >/dev/null 2>&1; local rs=$?
    names < "$TMP/m.log" > "$TMP/m.names"; names < "$TMP/s.log" > "$TMP/s.names"
    local tm ts max d pct
    tm=$(wc -l < "$TMP/m.names"); ts=$(wc -l < "$TMP/s.names")
    max=$(( tm > ts ? tm : ts ))
    d=$(diff "$TMP/s.names" "$TMP/m.names" | grep -c '^[<>]')
    pct=$(( max > 0 ? d * 100 / max : 100 ))
    check "$label: same exit code" "$rs" "$rm"
    if [ "$tm" -gt 0 ] && [ "$pct" -le 10 ]; then ok "$label: syscall sequence matches (mini=$tm strace=$ts differing=${pct}%)"
    else bad "$label: sequence differs" "mini=$tm strace=$ts differing=${pct}%"; fi
}
if [ "$HAVE_STRACE" = 1 ]; then
    compare ls ls -l "$TMP/dir"; compare cat cat "$TMP/data.txt"
    if command -v curl >/dev/null; then compare curl curl -s "file://$TMP/data.txt"; else skip "curl comparison (no curl)"; fi
else skip "strace comparison (strace missing or not permitted here)"; fi

section "attach mode"
scope=$(cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null || echo 0)
if [ "$(id -u)" = 0 ] || [ "$scope" = 0 ]; then
    sh -c 'while :; do echo x; sleep 0.2; done' >/dev/null 2>&1 &
    BGPID=$!; sleep 0.3
    timeout -s INT 2 "$MS" -o "$TMP/a.log" -p "$BGPID" >"$TMP/a.out" 2>&1
    grep -q "attached to pid $BGPID" "$TMP/a.out" && ok "attached" || bad "attach failed" "$(head -2 "$TMP/a.out")"
    [ -s "$TMP/a.log" ] && ok "syscalls were traced" || bad "empty trace"
    grep -q "detached from pid $BGPID" "$TMP/a.out" && ok "Ctrl+C detached cleanly" || bad "no detach message"
    kill -0 "$BGPID" 2>/dev/null && ok "target survived the tracer" || bad "target died"
    kill "$BGPID" 2>/dev/null; wait "$BGPID" 2>/dev/null; BGPID=
else skip "attach tests (run with sudo, or set kernel.yama.ptrace_scope=0)"; fi
"$MS" -o /dev/null -p 999999 2>/dev/null; check "attach to nonexistent pid -> 1" 1 $?

printf '\n== summary: %d passed, %d failed, %d skipped ==\n' "$PASS" "$FAIL" "$SKIP"
[ "$FAIL" -eq 0 ]
