import json
import sys
import time

log, body_path = sys.argv[1], sys.argv[2]
argv = sys.argv[3:]
with open(log, "a") as f:
    f.write(json.dumps({"at": time.time(), "argv": argv}) + "\n")
with open(log) as f:
    attempt = sum(1 for _ in f)
out = write_out = None
i = 0
while i < len(argv):
    if argv[i] in ("-o", "--output") and i + 1 < len(argv):
        out = argv[i + 1]
        i += 2
        continue
    if argv[i] in ("-w", "--write-out") and i + 1 < len(argv):
        write_out = argv[i + 1]
        i += 2
        continue
    i += 1
if attempt == 1:
    with open(body_path, "rb") as f:
        body = f.read()
    if out is None:
        sys.stdout.buffer.write(body)
    else:
        with open(out, "wb") as f:
            f.write(body)
    code, size, status = "200", str(len(body)), 0
else:
    sys.stderr.write("curl: (28) Connection timed out after 1001 milliseconds\n")
    sys.stderr.flush()
    code, size, status = "000", "0", 28
if write_out is not None:
    sys.stdout.write(write_out.replace("%{http_code}", code).replace("%{size_download}", size))
sys.stdout.flush()
sys.exit(status)
