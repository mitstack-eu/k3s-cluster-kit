#!/usr/bin/env python3
# Initialises mitstack's home cluster's OpenBao, or writes the GitHub App's
# key or the apps' sealed values into it. init commits the root token and
# recovery key to the cluster repository, each a PGP message to the owner's
# key, before it sets OpenBao up with the root token it holds in memory alone.
# write-app-key writes the key the Sealed Secrets controller opened, and
# write-app-secrets writes each mounted key named <namespace>.<key> to
# kv/data/apps/<namespace>/env, each again whenever a value changes. Every
# command reaches OpenBao over TLS alone and verifies it against the cluster's
# authority in MITSTACK_OPENBAO_CA.
# Usage: mitstack-openbao init | write-app-key | write-app-secrets, run by the
#   openbao-init Job and the github-app-writer and app-secrets-writer
#   Deployments in mitstack-node; the MITSTACK_* variables name OpenBao,
#   GitHub and the mounted files.
# It exists so OpenBao's init and every sealed value reach the cluster through
# Git alone, with no route into the cluster, no running platform and no policy
# written after init.
import base64
import hashlib
import json
import os
import re
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request

E = lambda k, d=None: os.environ.get(k) or d
OPENBAO = E("MITSTACK_OPENBAO_ADDR", "https://openbao.openbao.svc:8200")
OPENBAO_CA = E("MITSTACK_OPENBAO_CA", "/etc/mitstack/openbao-ca/ca.crt")
GITHUB = E("MITSTACK_GITHUB_API_URL", "https://api.github.com")
RECIPIENT = E("MITSTACK_RECIPIENT_FILE", "/etc/mitstack/recipient/recipient.asc")
APP_KEY = E("MITSTACK_APP_KEY_FILE", "/etc/mitstack/github-app/private-key")
APP_SECRETS = E("MITSTACK_APP_SECRETS_DIR", "/etc/mitstack/app-secrets")
SA_TOKEN = E("MITSTACK_SA_TOKEN_FILE", "/var/run/secrets/kubernetes.io/serviceaccount/token")
WAIT = float(E("MITSTACK_RETRY_SECONDS", "10"))
INIT_FILE = "openbao-init.asc"
APP_KEY_PATH = "kv/data/argocd/github-app"
APP_SECRETS_PATH = "kv/data/apps/%s/env"
NAMESPACE = re.compile(r"[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?")


def say(msg):
    print("mitstack-openbao: " + msg, file=sys.stderr, flush=True)


def fail(msg):
    say(msg)
    sys.exit(1)


def call(method, url, body=None, token=None, auth="X-Vault-Token", context=None):
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(url, data=data, method=method, headers={"Content-Type": "application/json"})
    if token:
        req.add_header(auth, token if auth == "X-Vault-Token" else "Bearer " + token)
    try:
        with urllib.request.urlopen(req, timeout=30, context=context) as resp:
            raw = resp.read()
            return resp.status, json.loads(raw) if raw else {}
    except urllib.error.HTTPError as e:
        return e.code, {}


def openbao_tls():
    """Trusts the cluster's authority alone, read on every call so a renewed authority takes effect at once."""
    return ssl.create_default_context(cafile=OPENBAO_CA)


def bao(method, path, body=None, token=None):
    status, answer = call(method, OPENBAO + "/v1/" + path, body, token, context=openbao_tls())
    if status >= 300:
        raise RuntimeError("OpenBao answered %d to %s %s" % (status, method, path))
    return answer


def retry(what, fn):
    """Runs fn until it succeeds, since the pod holds what nothing else can recover."""
    while True:
        try:
            return fn()
        except (OSError, RuntimeError, ValueError) as e:
            say("%s failed, retrying in %gs: %s" % (what, WAIT, e))
            time.sleep(WAIT)


def gpg(*args, stdin=b""):
    home = E("GNUPGHOME", "/tmp/gnupg")
    os.makedirs(home, mode=0o700, exist_ok=True)
    done = subprocess.run(["gpg", "--batch", "--homedir", home, *args], input=stdin, capture_output=True)
    if done.returncode != 0:
        raise ValueError(done.stderr.decode(errors="replace").strip())
    return done.stdout


def encrypt(plain):
    return gpg("--trust-model", "always", "--armor", "--recipient-file", RECIPIENT, "--encrypt", stdin=plain).decode()


def armor(binary):
    """Armors a binary PGP message as RFC 4880 section 6 does, so gpg --decrypt reads it."""
    crc = 0xB704CE
    for byte in binary:
        crc ^= byte << 16
        for _ in range(8):
            crc <<= 1
            if crc & 0x1000000:
                crc ^= 0x1864CFB
    body = base64.b64encode(binary).decode()
    lines = [body[i:i + 64] for i in range(0, len(body), 64)]
    checksum = base64.b64encode((crc & 0xFFFFFF).to_bytes(3, "big")).decode()
    return "\n".join(["-----BEGIN PGP MESSAGE-----", ""] + lines + ["=" + checksum, "-----END PGP MESSAGE-----", ""])


def b64url(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def app_token():
    """Mints a one-hour token that may write only the cluster repository's contents."""
    now = int(time.time())
    claims = b64url(json.dumps({"alg": "RS256", "typ": "JWT"}).encode()) + "." + \
        b64url(json.dumps({"iat": now - 60, "exp": now + 540, "iss": E("MITSTACK_GITHUB_APP_ID")}).encode())
    signed = subprocess.run(["openssl", "dgst", "-sha256", "-sign", APP_KEY], input=claims.encode(), capture_output=True)
    if signed.returncode != 0:
        raise ValueError("signing the App's JWT: " + signed.stderr.decode(errors="replace").strip())
    status, answer = call("POST", "%s/app/installations/%s/access_tokens" % (GITHUB, E("MITSTACK_GITHUB_INSTALLATION_ID")),
                          {"repositories": [E("MITSTACK_REPOSITORY").split("/")[1]], "permissions": {"contents": "write"}},
                          claims + "." + b64url(signed.stdout), auth="Authorization")
    if status != 201:
        raise RuntimeError("GitHub answered %d to the App token request" % status)
    return answer["token"]


def contents_url():
    return "%s/repos/%s/contents/%s" % (GITHUB, E("MITSTACK_REPOSITORY"), INIT_FILE)


def init_file_committed():
    status, _ = call("GET", contents_url(), token=app_token(), auth="Authorization")
    if status not in (200, 404):
        raise RuntimeError("GitHub answered %d to reading %s" % (status, INIT_FILE))
    return status == 200


def commit(messages):
    status, _ = call("PUT", contents_url(), {
        "message": "Record OpenBao's root token and recovery key, each a PGP message to the owner",
        "content": base64.b64encode(messages.encode()).decode()}, app_token(), auth="Authorization")
    if status != 201:
        raise RuntimeError("GitHub answered %d to committing %s" % (status, INIT_FILE))


def enable(kind, path, body, root):
    """Enables a mount or an auth method unless a lost answer hides that it already is."""
    enabled = bao("GET", "sys/" + kind, token=root)
    if path + "/" not in enabled.get("data", enabled):
        bao("POST", "sys/%s/%s" % (kind, path), body, root)


def policy(*grants):
    return "".join('path "%s" {\n  capabilities = [%s]\n}\n' % (path, ", ".join('"%s"' % c for c in caps)) for path, caps in grants)


def role(account, namespace, policy_name, ttl):
    return {"bound_service_account_names": [account], "bound_service_account_namespaces": [namespace],
            "policies": [policy_name], "ttl": ttl}


def kubernetes_accessor(root):
    auths = bao("GET", "sys/auth", token=root)
    accessor = auths.get("data", auths).get("kubernetes/", {}).get("accessor")
    if not accessor:
        raise RuntimeError("OpenBao lists no accessor for the auth method kubernetes/")
    return accessor


def set_up(root):
    """Writes the mounts, policies and roles 03-cluster-repository.yaml, the writers and each slice's External Secrets expect."""
    retry("enabling kv", lambda: enable("mounts", "kv", {"type": "kv", "options": {"version": "2"}}, root))
    retry("enabling Kubernetes auth", lambda: enable("auth", "kubernetes", {"type": "kubernetes"}, root))
    accessor = retry("reading the Kubernetes auth accessor", lambda: kubernetes_accessor(root))
    namespace = "{{identity.entity.aliases.%s.metadata.service_account_namespace}}" % accessor
    host = "https://%s:%s" % (E("KUBERNETES_SERVICE_HOST"), E("KUBERNETES_SERVICE_PORT", "443"))
    for method, path, body in [
        ("POST", "auth/kubernetes/config", {"kubernetes_host": host}),
        ("PUT", "sys/policies/acl/argocd-github-app", {"policy": policy((APP_KEY_PATH, ["read"]))}),
        ("PUT", "sys/policies/acl/github-app-writer", {"policy": policy((APP_KEY_PATH, ["create", "update"]))}),
        ("PUT", "sys/policies/acl/app-secrets-reader", {"policy": policy(("kv/data/apps/%s/*" % namespace, ["read"]),
                                                                         ("kv/metadata/apps/%s/*" % namespace, ["read", "list"]))}),
        ("PUT", "sys/policies/acl/app-secrets-writer", {"policy": policy(("kv/data/apps/*", ["create", "update"]))}),
        ("POST", "auth/kubernetes/role/argocd", role("openbao-argocd", "argocd", "argocd-github-app", "15m")),
        ("POST", "auth/kubernetes/role/github-app-writer", role("github-app-writer", "mitstack-node", "github-app-writer", "5m")),
        ("POST", "auth/kubernetes/role/app-secrets", role("app", "app-*", "app-secrets-reader", "15m")),
        ("POST", "auth/kubernetes/role/app-secrets-writer", role("app-secrets-writer", "mitstack-node", "app-secrets-writer", "5m")),
    ]:
        retry(method + " " + path, lambda: bao(method, path, body, root))


def init():
    try:
        encrypt(b"probe")
    except ValueError as e:
        fail("the recipient in %s cannot encrypt, so OpenBao was left uninitialised: %s" % (RECIPIENT, e))
    initialised = retry("reading OpenBao's init state", lambda: bao("GET", "sys/init"))["initialized"]
    if initialised:
        if retry("reading " + INIT_FILE, init_file_committed):
            say("OpenBao is initialised, and the cluster repository holds %s; this Job no longer holds the root token, "
                "so it sets nothing up" % INIT_FILE)
            return
        fail("OpenBao is initialised but the cluster repository holds no %s, so its root token and recovery key "
             "are lost; the store holds nothing yet, so reinstall the server" % INIT_FILE)
    recipient = base64.b64encode(gpg("--dearmor", stdin=open(RECIPIENT, "rb").read())).decode()
    answer = bao("PUT", "sys/init", {"recovery_shares": 1, "recovery_threshold": 1, "recovery_pgp_keys": [recipient]})
    root = answer["root_token"]
    messages = ("OpenBao root token:\n" + encrypt(root.encode()) +
                "OpenBao recovery key:\n" + armor(base64.b64decode(answer["recovery_keys_base64"][0])))
    retry("committing " + INIT_FILE, lambda: commit(messages))
    say("committed %s to %s" % (INIT_FILE, E("MITSTACK_REPOSITORY")))
    set_up(root)
    say("enabled kv and Kubernetes auth, and wrote the roles argocd, github-app-writer, app-secrets and app-secrets-writer")


def login(role_name):
    jwt = open(SA_TOKEN).read().strip()
    return bao("POST", "auth/kubernetes/login", {"role": role_name, "jwt": jwt})["auth"]["client_token"]


def write_app_key():
    written = None
    while True:
        with open(APP_KEY, "rb") as f:
            key = f.read()
        if hashlib.sha256(key).digest() != written:
            def write():
                bao("POST", APP_KEY_PATH, {"data": {"private-key": key.decode()}}, login("github-app-writer"))
            retry("writing the App's key", write)
            written = hashlib.sha256(key).digest()
            say("wrote the App's key to %s" % APP_KEY_PATH)
        time.sleep(WAIT)


def mounted_app_secrets():
    """Groups the mounted keys named <namespace>.<key> by namespace, and names each key it skips."""
    grouped, skipped = {}, []
    try:
        names = sorted(os.listdir(APP_SECRETS))
    except FileNotFoundError:
        return grouped, skipped
    for name in names:
        namespace, _, key = name.partition(".")
        if not namespace:
            continue
        if not key or not NAMESPACE.fullmatch(namespace):
            skipped.append(name)
            continue
        try:
            with open(os.path.join(APP_SECRETS, name), encoding="utf-8") as f:
                grouped.setdefault(namespace, {})[key] = f.read()
        except UnicodeDecodeError:
            skipped.append(name)
    return grouped, skipped


def fingerprint(data):
    return hashlib.sha256(json.dumps(data, sort_keys=True).encode()).digest()


def write_app_secrets():
    written, reported = {}, []
    while True:
        secrets, skipped = mounted_app_secrets()
        if skipped and skipped != reported:
            say("skipped %s, since each key must be <namespace>.<key> with a UTF-8 value" % ", ".join(skipped))
        reported = skipped
        changed = {ns: data for ns, data in secrets.items() if fingerprint(data) != written.get(ns)}
        if changed:
            def write():
                token = login("app-secrets-writer")
                for ns, data in changed.items():
                    bao("POST", APP_SECRETS_PATH % ns, {"data": data}, token)
            retry("writing the apps' values", write)
            for ns, data in changed.items():
                written[ns] = fingerprint(data)
                say("wrote %d keys to %s" % (len(data), APP_SECRETS_PATH % ns))
        time.sleep(WAIT)


if __name__ == "__main__":
    commands = {"init": init, "write-app-key": write_app_key, "write-app-secrets": write_app_secrets}
    if len(sys.argv) != 2 or sys.argv[1] not in commands:
        fail("usage: mitstack-openbao init | mitstack-openbao write-app-key | mitstack-openbao write-app-secrets")
    if not OPENBAO.startswith("https://"):
        fail("MITSTACK_OPENBAO_ADDR is %s; OpenBao is reached over https alone" % OPENBAO)
    commands[sys.argv[1]]()
