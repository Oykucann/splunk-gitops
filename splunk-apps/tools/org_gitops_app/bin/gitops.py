#!/usr/bin/env python3
"""org_gitops_app: pulls Splunk apps from GitLab and deploys them according to this server's role.

Run (as the splunk user):
  $SPLUNK_HOME/bin/splunk cmd python3 $SPLUNK_HOME/etc/apps/org_gitops_app/bin/gitops.py <command>

Commands:
  status      role, inventory, CM active/standby/single, GitLab connection, token expiry, last state
  plan        shows the diff between Git and disk; writes nothing
  stage       writes the diff to the target directories; does NOT apply/push/reload
  apply       writes and runs the role action (CM bundle apply, deployer push, DS reload)
  set-token   stores the GitLab token encrypted in storage/passwords
  run         scripted input mode: plan/stage/apply according to `mode` in gitops.conf

Options: --sha <commit> (a specific commit, e.g. for rollback), --only <dest>
Auth: the passAuth session key when run as a scripted input. When run by hand the Splunk user
is prompted for; for automation the GITOPS_SPLUNK_AUTH=user:password environment variable is read.
"""
import argparse, configparser, datetime, fcntl, getpass, hashlib, io, json, logging, logging.handlers
import os, re, shutil, ssl, sys, tarfile, time, urllib.error, urllib.parse, urllib.request
from pathlib import PurePosixPath

APP_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APP_NAME = os.path.basename(APP_DIR)
SPLUNK_HOME = os.environ.get("SPLUNK_HOME") or os.path.dirname(os.path.dirname(os.path.dirname(APP_DIR)))
VAR_DIR = os.path.join(SPLUNK_HOME, "var", "lib", APP_NAME)
LOG_FILE = os.path.join(SPLUNK_HOME, "var", "log", "splunk", APP_NAME + ".log")

DESTS = {  # dest key -> directory under the inventory path (default_path)
    "manager_apps": "etc/manager-apps",
    "master_apps": "etc/master-apps",   # legacy name; cannot be used together with manager_apps on one CM
    "deployment_apps": "etc/deployment-apps",
    "shcluster_apps": "etc/shcluster/apps",
    "etc_apps": "etc/apps",
}
ROLE_DESTS = {
    "cm": ["manager_apps", "master_apps", "etc_apps"],
    "ds": ["deployment_apps", "etc_apps"],
    "deployer": ["shcluster_apps", "etc_apps"],
    "sh": ["etc_apps"],
}
# preserved in etc/apps: objects created in the UI are not overwritten by Git
PRESERVE = {"etc_apps": ["local", "metadata/local.meta"]}
ALWAYS_IGNORE = re.compile(r"(^|/)(__pycache__(/|$)|[^/]*\.pyc$|\.DS_Store$)")
APP_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")
PROTECTED = {"_cluster", "search", "launcher", "learned", "splunk_httpinput", "splunk_internal_metrics",
             "introspection_generator_addon", "SplunkForwarder", "SplunkLightForwarder", "legacy",
             "sample_app", "framework", "appsbrowser", "alert_logevent", "alert_webhook", "user-prefs",
             "journald_input", "python_upgrade_readiness_app", "splunk_secure_gateway",
             "splunk_assist", "splunk_essentials_9_0", "dmc", "_cluster_admin"}
# a restart is recommended when these confs change (heuristic, not an exhaustive list)
RESTART_CONFS = {"server.conf", "web.conf", "outputs.conf", "authentication.conf", "limits.conf",
                 "distsearch.conf", "deploymentclient.conf", "inputs.conf", "indexes.conf", "pdf_server.conf"}

CM_DESTS = ("manager_apps", "master_apps")
INVENTORY_DEFAULT = "org_splunk_inventory.yaml"
BASE = SPLUNK_HOME  # path read from the inventory; set in run()


def dest_dir(d):
    return os.path.join(BASE, DESTS[d])


log = logging.getLogger(APP_NAME)


class GitopsError(Exception):
    pass


def kv(**k):
    out = []
    for a, b in k.items():
        if b is None:
            continue
        b = str(b)
        out.append('%s="%s"' % (a, b.replace('"', "'")) if (" " in b or "," in b or not b) else "%s=%s" % (a, b))
    return " ".join(out)


def setup_logging(console):
    log.setLevel(logging.INFO)
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    fh = logging.handlers.RotatingFileHandler(LOG_FILE, maxBytes=10 * 1024 * 1024, backupCount=3)
    fh.setFormatter(logging.Formatter("%(asctime)s level=%(levelname)s %(message)s"))
    log.addHandler(fh)
    if console:
        ch = logging.StreamHandler(sys.stdout)
        ch.setFormatter(logging.Formatter("%(levelname)-7s %(message)s"))
        log.addHandler(ch)


# ---------------------------------------------------------------- settings
def load_conf():
    cp = configparser.ConfigParser(interpolation=None, strict=False, comment_prefixes=("#", ";"))
    cp.optionxform = str
    for p in (os.path.join(APP_DIR, "default", "gitops.conf"), os.path.join(APP_DIR, "local", "gitops.conf")):
        if os.path.exists(p):
            with open(p) as f:
                cp.read_string(f.read(), source=p)
    if not cp.has_section("gitops"):
        raise GitopsError("gitops.conf icinde [gitops] yok")
    c = dict(cp.items("gitops"))
    for k in ("host_id", "role", "gitlab_url", "project"):
        if not c.get(k):
            raise GitopsError("gitops.conf: %s bos (local/gitops.conf'a yazin)" % k)
    if c["role"] not in ROLE_DESTS:
        raise GitopsError("gitops.conf: role %s gecersiz (cm|ds|deployer|sh)" % c["role"])
    b = lambda k: c.get(k, "false").strip().lower() in ("1", "true", "yes")
    c["inventory_file"] = (c.get("inventory_file") or INVENTORY_DEFAULT).strip().lstrip("/")
    if ".." in PurePosixPath(c["inventory_file"]).parts:
        raise GitopsError("gitops.conf: inventory_file repo icinde bir yol olmali")
    c["_allow_rolling_restart"] = b("allow_rolling_restart")
    c["_require_rf_sf_met"] = b("require_rf_sf_met")
    c["_splunk_verify_tls"] = b("splunk_verify_tls")
    c["_extra_protected"] = {x.strip() for x in c.get("protected_apps", "").split(",") if x.strip()}
    return c


# ---------------------------------------------------------------- HTTP
def http(url, method="GET", data=None, headers=None, ctx=None, timeout=60, max_bytes=None):
    body = urllib.parse.urlencode(data, doseq=True).encode() if isinstance(data, dict) else data
    req = urllib.request.Request(url, data=body, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=timeout) as r:
            raw = r.read(max_bytes + 1) if max_bytes else r.read()
            if max_bytes and len(raw) > max_bytes:
                raise GitopsError("yanit %d MB sinirini asti: %s" % (max_bytes // 1048576, url.split("?")[0]))
            return r.status, raw
    except urllib.error.HTTPError as e:
        return e.code, e.read()


class Splunk:
    def __init__(self, conf, session_key=None):
        self.uri = conf.get("splunk_mgmt_uri", "https://127.0.0.1:8089").rstrip("/")
        self.ctx = ssl.create_default_context()
        if not conf["_splunk_verify_tls"]:
            self.ctx.check_hostname = False
            self.ctx.verify_mode = ssl.CERT_NONE
        self.key = session_key

    user = "splunk-system-user"

    def login(self, user, pw):
        code, raw = http(self.uri + "/services/auth/login", "POST", {"username": user, "password": pw, "output_mode": "json"}, ctx=self.ctx)
        if code != 200:
            raise GitopsError("Splunk girisi basarisiz (HTTP %s)" % code)
        self.key = json.loads(raw)["sessionKey"]
        self.user = user

    def req(self, path, method="GET", data=None, ok=(200, 201), timeout=120):
        sep = "&" if "?" in path else "?"
        url = self.uri + path + ("" if method != "GET" else sep + "output_mode=json")
        if method != "GET":
            data = dict(data or {}); data["output_mode"] = "json"
        code, raw = http(url, method, data, {"Authorization": "Splunk " + self.key} if self.key else {}, self.ctx, timeout)
        if ok and code not in ok:
            msg = raw[:300].decode("utf-8", "replace")
            raise GitopsError("Splunk REST %s %s -> HTTP %s %s" % (method, path.split("?")[0], code, msg))
        try:
            return code, json.loads(raw) if raw else {}
        except ValueError:
            return code, {"_raw": raw.decode("utf-8", "replace")}

    def content(self, path):
        return self.req(path)[1]["entry"][0]["content"]

    # token ---------------------------------------------------------
    def _pw_path(self, name):
        ent = urllib.parse.quote("%s:%s:" % (APP_NAME, name), safe="")
        return "/servicesNS/nobody/%s/storage/passwords/%s" % (APP_NAME, ent)

    def get_secret(self, name):
        code, d = self.req(self._pw_path(name), ok=None)
        if code == 404:
            raise GitopsError("storage/passwords'te %s yok: once 'set-token' calistirin" % name)
        if code != 200:
            raise GitopsError("storage/passwords okunamadi (HTTP %s); kullanicinin list_storage_passwords yetkisi var mi?" % code)
        return d["entry"][0]["content"]["clear_password"]

    def set_secret(self, name, value):
        code, _ = self.req(self._pw_path(name), "POST", {"password": value}, ok=None)
        if code == 404:
            self.req("/servicesNS/nobody/%s/storage/passwords" % APP_NAME, "POST",
                     {"name": name, "realm": APP_NAME, "password": value})
        elif code not in (200, 201):
            raise GitopsError("token yazilamadi (HTTP %s)" % code)


class GitLab:
    def __init__(self, conf, token):
        self.base = conf["gitlab_url"].rstrip("/") + "/api/v4"
        self.pid = urllib.parse.quote(conf["project"], safe="")
        self.branch = conf.get("branch", "main")
        self.timeout = int(conf.get("http_timeout", "60"))
        self.max_bytes = int(conf.get("max_archive_mb", "500")) * 1048576
        self.ctx = ssl.create_default_context(cafile=conf.get("ca_bundle") or None)
        self.h = {"PRIVATE-TOKEN": token, "User-Agent": APP_NAME}

    def get(self, path, raw=False, ok404=False):
        code, body = http(self.base + path, headers=self.h, ctx=self.ctx, timeout=self.timeout,
                          max_bytes=self.max_bytes if raw else None)
        if code == 404 and ok404:
            return None
        if code != 200:
            hint = {401: "token gecersiz, iptal edilmis ya da suresi dolmus",
                    403: "token scope'u yetersiz (read_api gerekli) ya da role Reporter degil",
                    404: "proje/branch/commit bulunamadi ya da token'in projeye erisimi yok"}.get(code, "")
            log.error(kv(event="gitlab_error", status=code, path=path.split("?")[0], hint=hint))
            raise GitopsError("GitLab %s -> HTTP %s %s" % (path.split("?")[0], code, hint))
        return body if raw else json.loads(body)

    def head_sha(self):
        return self.get("/projects/%s/repository/branches/%s" % (self.pid, urllib.parse.quote(self.branch, safe="")))["commit"]["id"]

    def resolve(self, ref):
        return self.get("/projects/%s/repository/commits/%s" % (self.pid, urllib.parse.quote(ref, safe="")))["id"] if not re.fullmatch(r"[0-9a-f]{40}", ref) else ref

    def archive(self, sha):
        return self.get("/projects/%s/repository/archive.tar.gz?sha=%s" % (self.pid, sha), raw=True)

    def token_info(self):
        try:
            return self.get("/personal_access_tokens/self", ok404=True)
        except GitopsError:
            return None


# ---------------------------------------------------------------- release
def safe_extract(data, dest):
    """Extracts the archive with checks: absolute paths, '..', links and special files are rejected; the top-level directory is stripped."""
    tmp = dest + ".partial"
    shutil.rmtree(tmp, ignore_errors=True)
    os.makedirs(tmp)
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tf:
        members = tf.getmembers()
        tops = set()
        for m in members:
            p = PurePosixPath(m.name)
            if m.name.startswith("/") or ".." in p.parts:
                raise GitopsError("arsivde guvensiz yol: %s" % m.name)
            if not (m.isfile() or m.isdir()):
                raise GitopsError("arsivde link/ozel dosya: %s" % m.name)
            tops.add(p.parts[0])
        if len(tops) != 1:
            raise GitopsError("arsiv tek bir ust dizin icermiyor")
        for m in members:
            parts = PurePosixPath(m.name).parts[1:]
            if not parts:
                continue
            target = os.path.join(tmp, *parts)
            if m.isdir():
                os.makedirs(target, exist_ok=True)
                continue
            os.makedirs(os.path.dirname(target), exist_ok=True)
            with tf.extractfile(m) as src, open(target, "wb") as out:
                shutil.copyfileobj(src, out)
            os.chmod(target, 0o755 if m.mode & 0o111 else 0o644)
    shutil.rmtree(dest, ignore_errors=True)
    os.rename(tmp, dest)


def get_release(gl, sha):
    rel = os.path.join(VAR_DIR, "releases", sha)
    if os.path.exists(os.path.join(rel, ".complete")):
        return rel
    os.makedirs(os.path.dirname(rel), exist_ok=True)
    data = gl.archive(sha)
    safe_extract(data, rel)
    open(os.path.join(rel, ".complete"), "w").close()
    # keep the last 3 releases
    rels = sorted((os.path.join(VAR_DIR, "releases", d) for d in os.listdir(os.path.join(VAR_DIR, "releases"))), key=os.path.getmtime)
    for old in rels[:-3]:
        if old != rel:
            shutil.rmtree(old, ignore_errors=True)
    log.info(kv(event="release_downloaded", sha=sha, bytes=len(data)))
    return rel


def _scalar(v, what):
    """Accept both `x` and `[x]` in YAML."""
    if isinstance(v, list):
        if len(v) != 1:
            raise GitopsError("envanter: %s tek deger olmali" % what)
        v = v[0]
    return v


def _yesno(v, what):
    v = _scalar(v, what)
    if isinstance(v, bool):  # YAML 1.1: yes/no/true/false -> bool
        return v
    if isinstance(v, str) and v.strip().lower() in ("yes", "true", "evet"):
        return True
    if isinstance(v, str) and v.strip().lower() in ("no", "false", "hayir"):
        return False
    raise GitopsError("envanter: %s yes ya da no olmali (%r)" % (what, v))


def _path(v, what):
    v = _scalar(v, what)
    if not isinstance(v, str) or not v.startswith("/"):
        raise GitopsError("envanter: %s mutlak bir dizin olmali (%r)" % (what, v))
    return os.path.normpath(v)


def load_inventory(rel, conf, extra_protected, check_home=True):
    """Reads and validates the inventory. Returns: (want, meta)
    want: {dest: [app, ...]}; meta: {"base", "cm_ha", "file"}"""
    try:
        import yaml
    except ImportError:
        raise GitopsError("PyYAML yok: Splunk python'unda 'import yaml' calismiyor")
    fn = conf.get("inventory_file") or INVENTORY_DEFAULT
    p = os.path.join(rel, fn)
    if not os.path.isfile(p):
        raise GitopsError("repoda %s yok" % fn)
    try:
        with open(p) as f:
            t = yaml.safe_load(f)
    except yaml.YAMLError as e:
        raise GitopsError("%s okunamadi: %s" % (fn, str(e).replace("\n", " ")))
    if not isinstance(t, dict) or t.get("version") != 1 or not isinstance(t.get("roles"), dict):
        raise GitopsError("%s: 'version: 1' ve 'roles:' gerekli" % fn)
    for k in t:
        if k not in ("version", "default_path", "roles"):
            raise GitopsError("%s: bilinmeyen anahtar %s" % (fn, k))
    host, role = conf["host_id"], conf["role"]
    found = []
    for rname, r in t["roles"].items():
        if rname not in ROLE_DESTS or not isinstance(r, dict):
            raise GitopsError("%s: bilinmeyen rol %s" % (fn, rname))
        hosts = r.get("hosts") or []
        if isinstance(hosts, list):
            hosts = {h: {} for h in hosts}
        if not isinstance(hosts, dict):
            raise GitopsError("%s: %s.hosts liste ya da sozluk olmali" % (fn, rname))
        role_keys = set(ROLE_DESTS[rname]) | {"hosts", "path"} | ({"cm_ha_availability"} if rname == "cm" else set())
        for k in r:
            if k not in role_keys:
                raise GitopsError("%s: %s rolunde %s olamaz" % (fn, rname, k))
        if rname == "cm":
            if "cm_ha_availability" not in r:
                raise GitopsError("%s: cm rolunde cm_ha_availability (yes|no) zorunlu" % fn)
            _yesno(r["cm_ha_availability"], "cm.cm_ha_availability")
        for h, hr in hosts.items():
            for k in (hr or {}):
                if k not in set(ROLE_DESTS[rname]) | {"path"}:
                    raise GitopsError("%s: %s icin %s olamaz" % (fn, h, k))
        if host in hosts:
            found.append((rname, r, hosts[host] or {}))
    if not found:
        raise GitopsError("%s'de bu host (%s) yok" % (fn, host))
    if len(found) > 1 or found[0][0] != role:
        raise GitopsError("%s'de %s rolu %s, gitops.conf'ta %s" % (fn, host, ",".join(f[0] for f in found), role))
    _, r, hr = found[0]
    # path: host > role > default_path
    if "path" in hr:
        base = _path(hr["path"], "%s.path" % host)
    elif "path" in r:
        base = _path(r["path"], "%s.path" % role)
    elif "default_path" in t:
        base = _path(t["default_path"], "default_path")
    else:
        raise GitopsError("%s: default_path yok" % fn)
    if check_home:
        here = os.path.realpath(os.path.join(SPLUNK_HOME, "etc"))
        if os.path.realpath(os.path.join(base, "etc")) != here:
            raise GitopsError("%s: %s icin path %s, ama bu Splunk %s altinda calisiyor" % (fn, host, base, SPLUNK_HOME))
    meta = {"base": base, "file": fn,
            "cm_ha": _yesno(r["cm_ha_availability"], "cm.cm_ha_availability") if role == "cm" else None}
    want = {}
    for d in ROLE_DESTS[role]:
        apps = list(r.get(d) or []) + [a for a in (hr.get(d) or []) if a not in (r.get(d) or [])]
        for a in apps:
            if isinstance(a, str) and (a == APP_NAME or a in PROTECTED or a in extra_protected or a.startswith("splunk_") or a.startswith("Splunk_SA_")):
                raise GitopsError("korunan app yonetilemez: %s" % a)
            if not isinstance(a, str) or not APP_NAME_RE.match(a):
                raise GitopsError("gecersiz app adi: %r" % a)
            src = os.path.join(rel, "apps", a)
            if not os.path.isdir(src):
                raise GitopsError("%s'deki %s repoda apps/ altinda yok" % (fn, a))
            if d == "etc_apps":
                for pres in PRESERVE["etc_apps"]:
                    if os.path.exists(os.path.join(src, pres)):
                        raise GitopsError("%s: etc/apps'e gidecek app'te %s olamaz (default/ kullanin)" % (a, pres))
        if len(set(apps)) != len(apps):
            raise GitopsError("%s listesinde tekrar eden app var" % d)
        want[d] = apps
    if role == "cm" and want.get("manager_apps") and want.get("master_apps"):
        raise GitopsError("%s: %s icin manager_apps ve master_apps birlikte kullanilamaz; birini secin" % (fn, host))
    return want, meta


# ---------------------------------------------------------------- disk
def tree_hash(path, preserve=()):
    h = hashlib.sha1()
    if not os.path.isdir(path):
        return None
    for d, dirs, files in os.walk(path):
        dirs.sort()
        for f in sorted(files):
            p = os.path.join(d, f)
            rp = os.path.relpath(p, path).replace(os.sep, "/")
            if ALWAYS_IGNORE.search(rp) or any(rp == x or rp.startswith(x + "/") for x in preserve):
                continue
            h.update(rp.encode() + b"\0" + (b"x" if os.access(p, os.X_OK) else b"-"))
            with open(p, "rb") as fh:
                h.update(hashlib.sha1(fh.read()).digest())
    return h.hexdigest()


def load_state():
    p = os.path.join(VAR_DIR, "state.json")
    if os.path.exists(p):
        with open(p) as f:
            return json.load(f)
    return {"dests": {}}


def save_state(st):
    os.makedirs(VAR_DIR, exist_ok=True)
    p = os.path.join(VAR_DIR, "state.json")
    with open(p + ".tmp", "w") as f:
        json.dump(st, f, indent=1, sort_keys=True)
    os.replace(p + ".tmp", p)


def recover(dest_dir):
    """Cleans up a half-finished write."""
    if not os.path.isdir(dest_dir):
        return
    for n in os.listdir(dest_dir):
        p = os.path.join(dest_dir, n)
        if n.startswith(".gitops_old_"):
            app = n[len(".gitops_old_"):]
            if not os.path.exists(os.path.join(dest_dir, app)):
                os.rename(p, os.path.join(dest_dir, app))
                log.warning(kv(event="recovered", dest=dest_dir, app=app))
            else:
                shutil.rmtree(p, ignore_errors=True)
        elif n.startswith(".gitops_new_"):
            shutil.rmtree(p, ignore_errors=True)


def compute_plan(rel, want, st, only):
    plan = {}
    for d, apps in want.items():
        if only and d != only:
            continue
        dd = dest_dir(d)
        pres = PRESERVE.get(d, [])
        managed = st["dests"].get(d, {}).get("apps", {})
        items = []
        for a in apps:
            g = tree_hash(os.path.join(rel, "apps", a))
            k = tree_hash(os.path.join(dd, a), pres)
            if k is None:
                op = "add"
            elif k == g:
                op = "unchanged" if a in managed else "adopt"
            elif a not in managed:
                op = "adopt_update"   # on disk but not managed yet; will be replaced by the Git version
            elif managed.get(a) == g:
                op = "drift"          # Git unchanged but modified by hand on disk
            else:
                op = "update"
            items.append({"app": a, "op": op, "git": g})
        for a in sorted(set(managed) - set(apps)):
            if os.path.isdir(os.path.join(dd, a)):
                items.append({"app": a, "op": "remove", "git": None})
        plan[d] = items
    return plan


def changed(items):
    return [i for i in items if i["op"] not in ("unchanged", "adopt")]


def backup(conf, d, dd, apps, old_sha, new_sha):
    bdir = os.path.join(conf.get("backup_dir") or os.path.join(VAR_DIR, "backup"), conf["host_id"], d)
    os.makedirs(bdir, exist_ok=True)
    need = sum(os.path.getsize(os.path.join(r, f)) for a in apps for r, _, fs in os.walk(os.path.join(dd, a)) for f in fs)
    free = shutil.disk_usage(bdir).free
    min_free = int(conf.get("min_free_mb", "1024")) * 1048576
    if free - need < min_free:
        raise GitopsError("yedek dizininde yer yok: bos %d MB, gereken %d MB + %d MB pay" % (free // 1048576, need // 1048576, min_free // 1048576))
    name = "%s_%s_to_%s.tgz" % (time.strftime("%Y%m%d-%H%M%S"), (old_sha or "none")[:8], new_sha[:8])
    p = os.path.join(bdir, name)
    with tarfile.open(p + ".partial", "w:gz") as tf:
        for a in apps:
            if os.path.isdir(os.path.join(dd, a)):
                tf.add(os.path.join(dd, a), arcname=a)
    os.rename(p + ".partial", p)
    keep = int(conf.get("backup_keep", "2"))
    files = sorted(f for f in os.listdir(bdir) if f.endswith(".tgz"))
    for f in files[:-keep]:
        os.remove(os.path.join(bdir, f))
    log.info(kv(event="backup", dest=d, file=p, apps=len(apps), kept=min(len(files), keep)))
    return p


def write_app(src, dd, app, preserve):
    tmp = os.path.join(dd, ".gitops_new_" + app)
    old = os.path.join(dd, ".gitops_old_" + app)
    cur = os.path.join(dd, app)
    shutil.rmtree(tmp, ignore_errors=True)
    shutil.copytree(src, tmp)
    if os.path.isdir(cur):
        for x in preserve:
            s = os.path.join(cur, x)
            if os.path.isdir(s):
                shutil.copytree(s, os.path.join(tmp, x))
            elif os.path.exists(s):
                os.makedirs(os.path.dirname(os.path.join(tmp, x)), exist_ok=True)
                shutil.copy2(s, os.path.join(tmp, x))
        os.rename(cur, old)
    os.rename(tmp, cur)
    shutil.rmtree(old, ignore_errors=True)


def remove_app(dd, app):
    old = os.path.join(dd, ".gitops_old_" + app)
    os.rename(os.path.join(dd, app), old)
    shutil.rmtree(old)


def restart_hint(rel, items):
    confs = set()
    for i in items:
        if i["op"] == "remove":
            confs.add("(app silindi)")
            continue
        for r, _, fs in os.walk(os.path.join(rel, "apps", i["app"])):
            for f in fs:
                if f in RESTART_CONFS:
                    confs.add(f)
            if os.path.basename(r) == "bin" and fs:
                confs.add("bin/")
    return sorted(confs)


# ---------------------------------------------------------------- role actions
def cm_ha_status(conf, sp):
    code, _ = http(sp.uri + "/services/cluster/manager/ha_active_status", ctx=sp.ctx, timeout=10)
    return code


def cm_gate(conf, sp, ha):
    """May this CM write to manager-apps/master-apps? Returns: (writable, state)
    Measured in the lab (9.4.12): a single CM without redundancy also returns 503 on
    ha_active_status, so 503 alone does not mean "standby". What tells them apart is
    cluster/config manager_switchover_mode (single CM: disabled; active-passive: manual/auto).
    cluster/config mode is still "master" on 9.4.
    ha=True : only the active CM writes (200), the standby skips (503). Stops if there is no redundancy.
    ha=False: a single CM writes. If this CM is actually the standby of an active-passive pair it
              stops (so two CMs never apply to the same cluster); if it is the active one it warns and writes.
    ha=None : inventory could not be read; state is only reported, nothing is written."""
    cfg = sp.content("/services/cluster/config")
    mode, sw = cfg.get("mode"), (cfg.get("manager_switchover_mode") or "disabled")
    if mode not in ("manager", "master"):
        raise GitopsError("bu sunucu cluster manager degil (mode=%s)" % mode)
    redundant = sw != "disabled"
    code = cm_ha_status(conf, sp) if redundant else None
    state = ("active" if code == 200 else "standby" if code == 503 else "ha_active_status=%s" % code) if redundant else "single"
    if ha is None:
        return False, "%s (switchover=%s)" % (state, sw)
    if ha:
        if not redundant:
            raise GitopsError("envanterde cm_ha_availability=yes ama bu CM'de redundancy yok (manager_switchover_mode=disabled); envanteri no yapin")
        if code in (200, 503):
            return code == 200, state
        raise GitopsError("ha_active_status beklenmeyen yanit: HTTP %s" % code)
    if redundant:
        if code == 200:
            log.warning(kv(event="cm_ha_mismatch", switchover=sw,
                           msg="envanter no ama bu CM aktif-pasif ciftin aktifi; esi standby oldugu icin o calismayi durdurur. Envanteri yes yapin"))
            return True, "active"
        raise GitopsError("envanterde cm_ha_availability=no ama bu CM aktif-pasif ciftin parcasi (switchover=%s, %s); envanteri yes yapin" % (sw, state))
    return True, "single"


def cm_bundle(sp):
    c = sp.content("/services/cluster/manager/info")
    g = lambda k: (c.get(k) or {}).get("checksum") or (c.get(k) or {}).get("bundle_id")
    return c, g("active_bundle"), g("latest_bundle"), g("last_validated_bundle")


def action_cm(conf, sp, timeout=900):
    c, active, latest, _ = cm_bundle(sp)
    if c.get("maintenance_mode"):
        raise GitopsError("CM maintenance mode'da; apply yapilmadi")
    if c.get("rolling_restart_flag"):
        raise GitopsError("rolling restart suruyor; apply yapilmadi")
    if c.get("apply_bundle_status", {}).get("status") not in (None, "None", ""):
        raise GitopsError("bundle islemi suruyor: %s" % c["apply_bundle_status"])
    gen = sp.content("/services/cluster/manager/generation")
    if conf["_require_rf_sf_met"] and not (gen.get("replication_factor_met") in ("1", 1, True) and gen.get("search_factor_met") in ("1", 1, True)):
        raise GitopsError("RF/SF met degil; apply yapilmadi")
    # Behaviour measured in the lab (9.4.12):
    #  - If manager-apps DIFFERS from the active bundle, validate updates last_validated_bundle
    #    (checksum + timestamp); status briefly shows "Bundle validation is in progress".
    #  - If it is the SAME, no field changes; last_validated may show an older validation.
    #  - latest_bundle is updated by apply, not by validate.
    before = (c.get("last_validated_bundle") or {}).get("timestamp")
    sp.req("/services/cluster/manager/control/default/validate_bundle", "POST", {"check-restart": "true"})
    t0 = time.time(); seen_busy = False
    while True:
        time.sleep(2)
        c, active, latest, validated = cm_bundle(sp)
        busy = (c.get("apply_bundle_status") or {}).get("status") not in (None, "None", "")
        ts = (c.get("last_validated_bundle") or {}).get("timestamp")
        if busy:
            seen_busy = True
        elif ts != before:
            break                                   # new content validated
        elif time.time() - t0 >= 15:
            log.info(kv(event="cm_apply", result="unchanged", bundle=active, saw_validation=seen_busy))
            return {"bundle": active, "result": "unchanged"}
        if time.time() - t0 > 300:
            raise GitopsError("bundle validation 300 sn icinde bitmedi")
    if validated == active:
        log.info(kv(event="cm_apply", result="unchanged", bundle=active))
        return {"bundle": active, "result": "unchanged"}
    st = c.get("last_validated_bundle") or {}
    if str(st.get("is_valid_bundle")).lower() in ("0", "false"):
        raise GitopsError("bundle gecersiz: %s" % json.dumps(c.get("apply_bundle_status") or st)[:300])
    restart = str(c.get("last_check_restart_bundle_result")).lower() in ("1", "true")
    log.info(kv(event="cm_validate", bundle=validated, active=active, restart_required=restart))
    if restart and not conf["_allow_rolling_restart"]:
        raise GitopsError("bundle peer'larda restart gerektiriyor ve allow_rolling_restart=false; elle apply edin")
    sp.req("/services/cluster/manager/control/default/apply", "POST", {})
    t0 = time.time()
    while time.time() - t0 < timeout:
        time.sleep(5)
        _, d = sp.req("/services/cluster/manager/peers?count=0")
        allp = [e["content"] for e in d["entry"]]
        peers = [p for p in allp if p.get("status") == "Up"]  # a Down peer cannot receive the bundle; not waited for, reported
        ok = sum(1 for p in peers if p.get("active_bundle_id") == validated)
        if ok == len(peers):
            down = [p.get("label") for p in allp if p.get("status") != "Up"]
            if down or not allp:
                log.warning(kv(event="cm_apply_peers", up=len(peers), not_up=",".join(map(str, down)) or None,
                               msg="Up olmayan peer'lar geri geldiginde bundle'i CM'den alir" if down else "CM'de hic peer yok"))
            _, active, _, _ = cm_bundle(sp)
            log.info(kv(event="cm_apply", result="applied", bundle=validated, peers=len(peers), secs=int(time.time() - t0)))
            return {"bundle": validated, "result": "applied", "peers": len(peers)}
    raise GitopsError("bundle %d sn icinde tum peer'lara ulasmadi (%d/%d)" % (timeout, ok, len(peers)))


def action_ds(conf, sp):
    # splunkd only sees serverclass.conf in a newly copied app after the app list is reloaded
    sp.req("/services/apps/local/_reload", "POST", {}, ok=None)
    sp.req("/services/deployment/server/config/_reload", "POST", {})
    log.info(kv(event="ds_reload", result="ok"))
    return {"result": "reloaded"}


def action_deployer(conf, sp):
    target = conf.get("shc_target_uri")
    if not target:
        raise GitopsError("gitops.conf: shc_target_uri bos")
    data = {"target": target, "action": "all"}
    # a push fails while members are in a rolling restart (including one started by the previous push): wait and retry
    limit = int(conf.get("deployer_retry_secs", "900")); t0 = time.time(); n = 0
    while True:
        n += 1
        code, d = sp.req("/services/apps/deploy", "POST", data, ok=None, timeout=900)
        if code in (200, 201):
            break
        msg = json.dumps(d)[:400]
        busy = any(x in msg for x in ("Network-layer", "restart", "not ready", "Connection refused", "captain"))
        if not busy or time.time() - t0 > limit:
            raise GitopsError("deployer push HTTP %s (deneme %d): %s" % (code, n, msg))
        log.warning(kv(event="shc_push_retry", attempt=n, status=code, msg=msg[:200]))
        time.sleep(30)
    log.info(kv(event="shc_push", result="ok", target=target, attempts=n,
                note="uyeler gerekiyorsa rolling restart yapar (Splunk davranisi)"))
    return {"result": "pushed", "target": target}


def action_refresh_apps(conf, sp):
    sp.req("/services/apps/local/_reload", "POST", {}, ok=None)
    return {"result": "apps_reloaded"}


# ---------------------------------------------------------------- main flow
def get_session(conf, args):
    sp = Splunk(conf)
    if args.cmd == "run":
        key = sys.stdin.readline().strip()
        if not key:
            raise GitopsError("passAuth oturum anahtari gelmedi (inputs.conf passAuth?)")
        sp.key = key
        return sp
    auth = os.environ.get("GITOPS_SPLUNK_AUTH")
    if auth and ":" in auth:
        u, p = auth.split(":", 1)
    else:
        u = input("Splunk kullanicisi: ")
        p = getpass.getpass("Splunk sifresi: ")
    sp.login(u, p)
    return sp


def token_check(conf, gl):
    info = gl.token_info()
    exp = (info or {}).get("expires_at") or conf.get("token_expires")
    src = "gitlab" if (info or {}).get("expires_at") else ("conf" if exp else "none")
    days = None
    if exp:
        days = (datetime.date.fromisoformat(exp[:10]) - datetime.date.today()).days
    warn = int(conf.get("token_warn_days", "30"))
    lvl = logging.WARNING if days is not None and days <= warn else logging.INFO
    log.log(lvl, kv(event="token_check", token_name=(info or {}).get("name"), expires=exp, days_left=days, source=src,
                    scopes=",".join((info or {}).get("scopes") or [])))
    if days is not None and days <= warn:
        log.warning(kv(event="token_expiring", days_left=days, msg="token %s gun icinde bitiyor, yenileyin" % days))
    return info, exp, days


def cmd_set_token(conf, sp):
    tok = getpass.getpass("GitLab token: ") if sys.stdin.isatty() else sys.stdin.readline().strip()
    if not tok:
        raise GitopsError("bos token")
    sp.set_secret("gitlab_token", tok)
    gl = GitLab(conf, tok)
    try:
        sha = gl.head_sha()
        log.info(kv(event="set_token", result="ok", branch=gl.branch, head=sha[:8]))
    except GitopsError as e:
        log.warning(kv(event="set_token", result="saved_but_check_failed", error=str(e)))


def cmd_status(conf, sp, st):
    log.info(kv(event="status", host_id=conf["host_id"], role=conf["role"], splunk_home=SPLUNK_HOME, mode=conf.get("mode", "plan")))
    gl = GitLab(conf, sp.get_secret("gitlab_token"))
    meta = None
    try:
        rel = get_release(gl, gl.head_sha())
        _, meta = load_inventory(rel, conf, conf["_extra_protected"])
        log.info(kv(event="inventory", file=meta["file"], path=meta["base"], cm_ha_availability=meta["cm_ha"]))
    except GitopsError as e:
        log.error(kv(event="inventory_failed", error=str(e)))
    if conf["role"] == "cm":
        try:
            ok, why = cm_gate(conf, sp, meta["cm_ha"] if meta else None)
        except GitopsError as e:
            ok, why = False, "HATA: %s" % e
        active = cm_bundle(sp)[1] if ok else None  # a standby CM returns 503 on cluster/manager/info
        log.info(kv(event="cm_state", writable=ok, state=why, active_bundle=active))
    try:
        v = gl.get("/version").get("version")
    except GitopsError:
        v = "okunamadi"
    log.info(kv(event="gitlab", url=conf["gitlab_url"], project=conf["project"], branch=gl.branch, version=v))
    token_check(conf, gl)
    head = gl.head_sha()
    log.info(kv(event="head", sha=head))
    for d, s in sorted(st["dests"].items()):
        log.info(kv(event="last_applied", dest=d, sha=(s.get("sha") or "")[:8], at=s.get("at"), apps=len(s.get("apps", {})),
                    pending_action=s.get("pending_action", False)))


def run(conf, args, sp):
    st = load_state()
    if args.cmd == "status":
        return cmd_status(conf, sp, st)
    gl = GitLab(conf, sp.get_secret("gitlab_token"))
    token_check(conf, gl)  # on every run: warn on screen and in the log 30 days before expiry
    sha = gl.resolve(args.sha) if args.sha else gl.head_sha()
    rel = get_release(gl, sha)
    global BASE
    want, meta = load_inventory(rel, conf, conf["_extra_protected"])
    BASE = meta["base"]
    mode = args.cmd if args.cmd != "run" else conf.get("mode", "plan")
    if mode not in ("plan", "stage", "apply"):
        raise GitopsError("mode %s gecersiz" % mode)
    gate_ok, gate_why = True, ""
    if conf["role"] == "cm":
        gate_ok, gate_why = cm_gate(conf, sp, meta["cm_ha"])
    for d in DESTS:
        recover(dest_dir(d))
    plan = compute_plan(rel, want, st, args.only)
    log.info(kv(event="plan_start", sha=sha[:8], mode=mode, host_id=conf["host_id"], role=conf["role"],
                inventory=meta["file"], path=BASE, cm_ha_availability=meta["cm_ha"], cm_state=gate_why or None))
    total = 0
    for d, items in plan.items():
        ch = changed(items)
        total += len(ch)
        for i in items:
            if i["op"] != "unchanged" or args.verbose:
                log.info(kv(event="plan", dest=d, app=i["app"], op=i["op"]))
        skip = d in CM_DESTS and not gate_ok
        log.info(kv(event="plan_dest", dest=d, changes=len(ch), skipped=gate_why if skip else None,
                    pending_action=st["dests"].get(d, {}).get("pending_action", False)))
    if mode == "plan":
        log.info(kv(event="run_done", mode=mode, sha=sha[:8], changes=total))
        return 0
    rc = 0
    actions = {}  # action key -> [dest, ...]; runs AFTER all writes are done
    for d, items in plan.items():
        if d in CM_DESTS and not gate_ok:
            log.info(kv(event="skip", dest=d, reason=gate_why))
            continue
        dd = dest_dir(d)
        ds = st["dests"].setdefault(d, {"apps": {}})
        ch = changed(items)
        if mode == "stage":
            for i in [i for i in ch if i["op"] == "drift"]:
                log.warning(kv(event="drift", dest=d, app=i["app"], msg="diskte elle degistirilmis; stage ezmez, apply Git'teki haliyle ezer"))
            ch = [i for i in ch if i["op"] != "drift"]
        if ch:
            os.makedirs(dd, exist_ok=True)  # do not create an unused dest directory (e.g. master-apps) for nothing
            olds = [i["app"] for i in ch if i["op"] != "add"]
            if olds:  # no backup needed when apps are only added
                backup(conf, d, dd, olds, ds.get("sha"), sha)
            for i in ch:
                if i["op"] == "remove":
                    remove_app(dd, i["app"])
                else:
                    write_app(os.path.join(rel, "apps", i["app"]), dd, i["app"], PRESERVE.get(d, []))
                log.info(kv(event="write", dest=d, app=i["app"], op=i["op"]))
            ds["pending_action"] = True
            hint = restart_hint(rel, ch)
            if d == "etc_apps" and hint:
                ds["restart_recommended"] = hint
                log.warning(kv(event="restart_recommended", dest=d, confs=",".join(hint),
                               msg="bu sunucuda splunkd restart gerekebilir; script restart yapmaz"))
        ds["apps"] = {i["app"]: i["git"] for i in items if i["op"] != "remove"}
        if mode == "stage":  # in stage, keep the old hash of a drifted app that was not overwritten
            for i in items:
                if i["op"] == "drift":
                    ds["apps"][i["app"]] = st["dests"].get(d, {}).get("apps", {}).get(i["app"], i["git"])
        ds["sha"], ds["at"] = sha, time.strftime("%Y-%m-%dT%H:%M:%S%z")
        save_state(st)
        # On an active/single CM, apply validates every time and does not rely on the pending flag
        # (manual stage, diff after a switchover, an interrupted run). Peers are untouched if nothing changed.
        if mode == "apply" and (ds.get("pending_action") or d in CM_DESTS):
            actions.setdefault(action_key(conf, d), []).append(d)
        elif ds.get("pending_action"):
            log.info(kv(event="pending_action", dest=d, msg=pending_msg(d)))
    # Actions run after the writes: e.g. on a DS, a new deployment app + a new serverclass in the same
    # commit are both seen by one reload; on a CM both manager/master dests are written first.
    for key, ds_list in actions.items():
        try:
            res = do_action(conf, sp, ds_list[0])
            for d in ds_list:
                st["dests"][d]["pending_action"] = False
                st["dests"][d]["last_action"] = res
        except GitopsError as e:
            log.error(kv(event="action_failed", dest=",".join(ds_list), error=str(e)))
            rc = 2
        save_state(st)
    if conf["role"] == "cm" and gate_ok:
        _, active, _, _ = cm_bundle(sp)
        log.info(kv(event="cm_bundle", active_bundle=active))
    log.info(kv(event="run_done", mode=mode, sha=sha[:8], changes=total, rc=rc))
    return rc


def pending_msg(d):
    return {"manager_apps": "elle: splunk validate cluster-bundle --check-restart; splunk apply cluster-bundle",
            "master_apps": "elle: splunk validate cluster-bundle --check-restart; splunk apply cluster-bundle",
            "shcluster_apps": "elle: splunk apply shcluster-bundle -target <uye>",
            "deployment_apps": "elle: splunk reload deploy-server",
            "etc_apps": "etc/apps yazildi; gerekiyorsa restart elle"}[d]


def action_key(conf, d):
    if conf["role"] == "ds":
        return "ds_reload"  # deployment-apps and serverclass (etc/apps) with a single reload
    if d in CM_DESTS:
        return "cm_bundle"
    return d


def do_action(conf, sp, d):
    role = conf["role"]
    if d in CM_DESTS:
        return action_cm(conf, sp)
    if d == "shcluster_apps":
        return action_deployer(conf, sp)
    if d == "deployment_apps" or (d == "etc_apps" and role == "ds"):
        return action_ds(conf, sp)
    if d == "etc_apps":
        return action_refresh_apps(conf, sp)
    return {}


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("cmd", nargs="?", default="run", choices=["status", "plan", "stage", "apply", "set-token", "run"])
    ap.add_argument("--sha", help="branch yerine bu commit")
    ap.add_argument("--only", choices=list(DESTS), help="yalniz bu hedef")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()
    setup_logging(console=args.cmd != "run")
    os.makedirs(VAR_DIR, exist_ok=True)
    lockf = open(os.path.join(VAR_DIR, "lock"), "w")
    try:
        fcntl.flock(lockf, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        log.error(kv(event="locked", msg="baska bir gitops calismasi suruyor"))
        return 3
    try:
        conf = load_conf()
        if args.only and args.only not in ROLE_DESTS[conf["role"]]:
            raise GitopsError("%s rolunde %s hedefi yok" % (conf["role"], args.only))
        sp = get_session(conf, args)
        log.info(kv(event="run_start", cmd=args.cmd, splunk_user=sp.user, host_id=conf["host_id"], role=conf["role"],
                    sha=args.sha, only=args.only))
        if args.cmd == "set-token":
            return cmd_set_token(conf, sp) or 0
        return run(conf, args, sp) or 0
    except GitopsError as e:
        log.error(kv(event="run_failed", cmd=args.cmd, error=str(e)))
        return 1
    except Exception as e:  # unexpected: log it so nothing is left half-done unnoticed
        log.exception(kv(event="run_crashed", cmd=args.cmd, error=repr(e)))
        return 1


if __name__ == "__main__":
    sys.exit(main())
