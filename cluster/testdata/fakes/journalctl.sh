#!/bin/sh
dir=$(dirname "$0")
: > "$dir/args"
for a in "$@"; do printf '%s\n' "$a" >> "$dir/args"; done
limit=
prev=
for a in "$@"; do
  case $prev in -n | --lines) limit=$a ;; esac
  case $a in --lines=*) limit=${a#--lines=} ;; -n[0-9]*) limit=${a#-n} ;; esac
  prev=$a
done
if [ -n "$limit" ]; then exec tail -n "$limit" "$dir/journal.txt"; fi
exec cat "$dir/journal.txt"
