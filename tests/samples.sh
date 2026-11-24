#!/usr/bin/env bash
# Capture real sample output for the report -> docs/samples.txt
set -u
cd "$(dirname "$0")/.."
MS=${MS:-./mini_strace}; OUT=docs/samples.txt; mkdir -p docs
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
printf 'hello-mini-strace\n' > "$TMP/data.txt"
sec() { printf '\n##### %s\n$ %s\n\n' "$1" "$2"; }
{
  echo "mini_strace samples, $(date -u +%FT%TZ), $(uname -srm)"
  sec "1. Basic trace" "mini_strace cat data.txt"; "$MS" cat "$TMP/data.txt" 2>&1 | tail -15
  sec "2. Filter" "mini_strace -e trace=openat,read,write,close cat data.txt"; "$MS" -e trace=openat,read,write,close cat "$TMP/data.txt" 2>&1 | tail -12
  sec "3. ENOENT" "mini_strace -e trace=openat cat /nonexistent"; "$MS" -e trace=openat cat /nonexistent 2>&1 | tail -4
  sec "4. Statistics" "mini_strace -c ls /usr/include"; "$MS" -c ls /usr/include 2>&1 >/dev/null | head -20
  sec "5. Children" "mini_strace -e trace=execve sh -c '/bin/true; /bin/echo hi'"; "$MS" -e trace=execve sh -c '/bin/true; /bin/echo hi' 2>&1 | tail -8
  if command -v gcc >/dev/null; then
    printf 'int main(void){*(volatile int*)0=1;return 0;}' > "$TMP/segv.c"; gcc -o "$TMP/segv" "$TMP/segv.c"
    sec "6. Fatal signal" "mini_strace ./segv"; "$MS" "$TMP/segv" 2>&1 | tail -4
  fi
  sec "7. -o redirection" "mini_strace -o trace.log echo hi; head -3 trace.log"; "$MS" -o "$TMP/t.log" echo hi; head -3 "$TMP/t.log"
} > "$OUT"
echo "wrote $OUT"
