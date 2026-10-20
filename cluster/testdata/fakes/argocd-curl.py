import json
import os
import re
import sys
import time

log, config_path = sys.argv[1], sys.argv[2]
argv = sys.argv[3:]
with open(config_path) as f:
    cfg = json.load(f)

SCHEME = re.compile(r"^[a-z][a-z0-9+.-]*://", re.I)
VALUE_FLAGS = {
    "-o", "--output", "-w", "--write-out", "-H", "--header", "-X", "--request", "--connect-timeout", "--max-time", "-m",
    "--proto", "--data-binary", "-d", "--data", "-b", "--cookie", "-u", "--user", "--max-redirs", "--retry", "-A",
    "--user-agent", "--max-filesize", "--cacert", "-K", "--config", "--resolve", "--oauth2-bearer", "-e", "--referer",
}
urls, opts, flags = [], {}, []
i = 0
while i < len(argv):
    a = argv[i]
    if SCHEME.match(a):
        urls.append(a)
        i += 1
    elif a in VALUE_FLAGS and i + 1 < len(argv):
        opts[a] = argv[i + 1]
        i += 2
    else:
        flags.append(a)
        i += 1


letters = {c for a in flags if a.startswith("-") and not a.startswith("--") for c in a[1:]}


def host_of(url):
    return SCHEME.sub("", url).split("/", 1)[0].rsplit("@", 1)[-1].rsplit(":", 1)[0]


# Calls to a loopback host reach the platform and the user data, which the next curl on PATH answers.
if not urls or all(host_of(u) in ("127.0.0.1", "localhost", "[::1]") for u in urls):
    rest = [p for p in os.environ.get("PATH", "").split(os.pathsep) if os.path.abspath(p) != cfg["shimDir"]]
    os.environ["PATH"] = os.pathsep.join(rest)
    os.execvp("curl", ["curl"] + argv)

with open(log, "a") as f:
    f.write(json.dumps({"at": time.time(), "argv": argv}) + "\n")

url = urls[-1]
code, size, status, message, body = "000", "0", 0, "", b""
write_out = opts.get("-w", opts.get("--write-out"))
out = opts.get("-o", opts.get("--output"))
route = cfg["routes"].get(url[len(cfg["base"]):]) if url.startswith(cfg["base"] + "/") else None
if "=https" in opts.get("--proto", "") and not url.lower().startswith("https://"):
    status, message = 1, "curl: (1) Protocol \"%s\" disabled" % url.split(":", 1)[0]
elif route is None:
    status, message = 99, "curl: (99) this fake answers only the Argo CD routes it was given at " + cfg["base"]
elif "k" not in letters and "--insecure" not in flags:
    status, message = 60, "curl: (60) SSL certificate problem: self-signed certificate"
elif route.get("exit", 0) != 0:
    status, message = route["exit"], "curl: (%d) %s" % (route["exit"], route.get("stderr", "failed"))
else:
    body = route["body"].encode("utf-8")
    code, size = str(route["status"]), str(len(body))
    if ("f" in letters or "--fail" in flags) and route["status"] >= 400:
        status, message, body, size = 22, "curl: (22) The requested URL returned error: %d" % route["status"], b"", "0"

if body:
    if out in (None, "-"):
        sys.stdout.buffer.write(body)
    elif out != "/dev/null":
        with open(out, "wb") as f:
            f.write(body)
if message:
    sys.stderr.write(message + "\n")
    sys.stderr.flush()
if write_out is not None:
    text = write_out.replace("\\n", "\n").replace("\\t", "\t")
    for name, value in (("http_code", code), ("response_code", code), ("size_download", size), ("exitcode", str(status))):
        text = text.replace("%{" + name + "}", value)
    sys.stdout.write(text)
sys.stdout.flush()
sys.exit(status)
