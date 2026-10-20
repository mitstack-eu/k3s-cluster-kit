#!/bin/sh
# Records its arguments, then runs the command after systemd-run's options in
# the foreground, so a test reads what the detached unit would have written.
dir=$(dirname "$0")
: > "$dir/args"
for a in "$@"; do printf '%s\n' "$a" >> "$dir/args"; done
while [ $# -gt 0 ]; do
  case $1 in
    -p | --property) shift 2 ;;
    -*) shift ;;
    *) break ;;
  esac
done
"$@" > "$dir/unit.log" 2>&1
echo "Running as unit: mitstack-scan.service"
