#!/usr/bin/env bash
# Strips the binary, preserving function names in a MiniDebugInfo
# (.gnu_debugdata) section readable by gdb/elfutils/perf.
set -euo pipefail
umask 077
export LC_ALL=C
unset XZ_DEFAULTS XZ_OPT

if [[ "$#" -ne 1 ]]; then
  echo "Usage: $0 ELF" >&2
  exit 2
fi

bin="$1"
if [[ ! -f "$bin" || -L "$bin" || ! -x "$bin" ]]; then
  echo "MiniDebugInfo input must be a plain executable file: $bin" >&2
  exit 1
fi

tmp="$(mktemp -d "${TMPDIR:-/tmp}/tevless-minidebug.XXXXXX")"
trap 'rm -rf -- "$tmp"' EXIT

nm -p -D "$bin" --format=posix --defined-only | awk '{print $1}' > "$tmp/dynsyms"
nm -p    "$bin" --format=posix --defined-only | awk '$2 ~ /[tTwW]/ {print $1}' > "$tmp/funcsyms"
awk 'FILENAME == ARGV[1] { dyn[$0]; next } !($0 in dyn)' "$tmp/dynsyms" "$tmp/funcsyms" > "$tmp/keep"

objcopy --only-keep-debug "$bin" "$tmp/mini"
objcopy -S --remove-section .comment --keep-symbols="$tmp/keep" "$tmp/mini"
xz --threads=1 --check=crc64 -9 "$tmp/mini"

strip -s --remove-section=.comment "$bin"
objcopy --add-section .gnu_debugdata="$tmp/mini.xz" "$bin"
