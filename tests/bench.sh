#!/usr/bin/env bash
# Overhead comparison and a small probing-detection demo.
# Usage: tests/bench.sh [directory-to-walk]   (default /usr/include)
set -u
cd "$(dirname "$0")/.."
MS=${MS:-./mini_strace}
WORK=${1:-/usr/include}
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
timeit() { local s e; s=$(date +%s.%N); "$@" >/dev/null 2>&1; e=$(date +%s.%N)
           awk -v s="$s" -v e="$e" 'BEGIN{printf "%.3f", e-s}'; }
row() { awk -v n="$1" -v t="$2" -v b="$3" 'BEGIN{printf "%-26s %8.3fs   x%.1f\n", n, t, (b>0 ? t/b : 0)}'; }
echo "== overhead: find $WORK -type f =="
base=$(timeit find "$WORK" -type f)
row "native" "$base" "$base"
row "mini_strace -o" "$(timeit "$MS" -o /dev/null find "$WORK" -type f)" "$base"
row "mini_strace -c" "$(timeit "$MS" -c -o /dev/null find "$WORK" -type f)" "$base"
row "mini_strace -e openat" "$(timeit "$MS" -e trace=openat -o /dev/null find "$WORK" -type f)" "$base"
if command -v strace >/dev/null && strace -o /dev/null true 2>/dev/null; then
    row "strace -f -o" "$(timeit strace -f -o /dev/null find "$WORK" -type f)" "$base"
    row "strace -c -f" "$(timeit strace -c -f -o /dev/null find "$WORK" -type f)" "$base"
fi
echo
echo "== security demo: a script probing for sensitive files =="
"$MS" -c -e trace=openat -o "$TMP/sec.log" sh -c '
  for p in /etc/shadow /root/.ssh/id_rsa /etc/sudoers /proc/1/environ /nonexistent1 /nonexistent2; do cat "$p" 2>/dev/null; done' >/dev/null 2>&1
cat "$TMP/sec.log"
echo; echo "Many failing openat calls on distinct paths = probing/scanning signature. Paths and errors:"
"$MS" -e trace=openat -o "$TMP/sec2.log" sh -c 'cat /etc/shadow /nonexistent1' >/dev/null 2>&1
grep -E 'EACCES|ENOENT' "$TMP/sec2.log" | sed -E 's/^\[ *[0-9.]+\] //' | head -5
