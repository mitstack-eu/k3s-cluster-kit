#!/bin/sh
# Records its arguments and the files --exceptions and --controls-config
# name beside itself, then writes report.json to --output, or prints stderr
# and exits with the status in exit when that file exists.
dir=$(dirname "$0")
: > "$dir/args"
for a in "$@"; do printf '%s\n' "$a" >> "$dir/args"; done
prev=
for a in "$@"; do
  case $prev in
    --exceptions) cp "$a" "$dir/exceptions.seen" ;;
    --controls-config) cp "$a" "$dir/controls-config.seen" ;;
    --output) output=$a ;;
  esac
  prev=$a
done
if [ -e "$dir/exit" ]; then
  cat "$dir/stderr" >&2
  exit "$(cat "$dir/exit")"
fi
cp "$dir/report.json" "$output"
