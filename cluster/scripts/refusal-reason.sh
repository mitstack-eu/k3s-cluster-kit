#!/bin/sh
# Defines refusal_reason, which prints ": <error>" when the refused answer in
# the file $1 is a JSON object with a non-empty string error, and nothing
# otherwise.
# Usage: spliced in at @REFUSAL_REASON@ or sourced, then
# refusal_reason <answer-file>.
# It exists so a platform refusal reaches the journal as one printable line.
refusal_reason() {
  python3 - "$1" <<'PY' 2> /dev/null || :
import json
import sys

try:
    with open(sys.argv[1], "rb") as f:
        error = json.loads(f.read()).get("error")
except (OSError, ValueError, AttributeError):
    sys.exit(0)
if isinstance(error, str):
    error = "".join(c for c in error[:500] if c.isprintable())
    if error:
        sys.stdout.buffer.write((": " + error).encode("utf-8", "replace"))
PY
}
