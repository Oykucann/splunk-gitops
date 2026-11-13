#!/usr/bin/env python3
"""Pre-MR repo check. Does not connect to any server or to GitLab, and writes nothing.

Finds every inventory file in the repo: org_splunk_inventory.yaml at the root and, with several
environments, envs/<env>/org_splunk_inventory.yaml. For every host in each file it runs the same
check the server-side script runs (load_inventory in gitops.py). In addition:
  - every app under apps/ must have default/app.conf
  - apps under apps/ that no inventory assigns (warning)
  - files and keys that must not be in Git: local.meta, symlinks,
    values in pass4SymmKey / sslPassword / password settings

Usage (at the repo root):  python3 tools/check_repo.py
Requires: python3 and PyYAML (pip install pyyaml)
Exit code: 0 = clean, 1 = errors (do not merge the MR)
"""
import glob
import importlib.util
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GITOPS = os.path.join(ROOT, "tools", "org_gitops_app", "bin", "gitops.py")
SECRET_RE = re.compile(r"^\s*(pass4SymmKey|sslPassword|sslKeysfilePassword|bindDNpassword|password)\s*=\s*(\S.*)$", re.I)
INV = "org_splunk_inventory.yaml"


def load_gitops():
    spec = importlib.util.spec_from_file_location("gitops", GITOPS)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def main():
    try:
        import yaml
    except ImportError:
        print("ERROR PyYAML missing: pip install pyyaml")
        return 1
    g = load_gitops()
    errors, warns = [], []
    used = set()
    nhosts = 0

    inv_files = ([INV] if os.path.isfile(os.path.join(ROOT, INV)) else []) + \
        sorted(os.path.relpath(p, ROOT) for p in glob.glob(os.path.join(ROOT, "envs", "*", INV)))
    if not inv_files:
        print("ERROR no inventory: %s or envs/<env>/%s" % (INV, INV))
        return 1

    for fn in inv_files:
        print("== %s" % fn)
        try:
            with open(os.path.join(ROOT, fn)) as f:
                t = yaml.safe_load(f) or {}
        except (OSError, yaml.YAMLError) as e:
            errors.append("cannot read %s: %s" % (fn, e))
            continue
        hosts = []
        for rname, r in (t.get("roles") or {}).items():
            if not isinstance(r, dict):
                continue
            hs = r.get("hosts") or []
            hosts += [(h, rname) for h in (hs if isinstance(hs, list) else list(hs))]
            # Count apps of failing hosts as "assigned" too (avoid false warnings)
            for b in [r] + (list(hs.values()) if isinstance(hs, dict) else []):
                for k, v in (b or {}).items():
                    if k in g.DESTS and isinstance(v, list):
                        used.update(a for a in v if isinstance(a, str))
        seen = {}
        for h, rname in hosts:
            if h in seen:
                errors.append("%s: %s is in two roles: %s, %s" % (fn, h, seen[h], rname))
            seen[h] = rname
        nhosts += len(hosts)
        # The server-side script's check, per host (whether the path is right is checked on the server itself)
        for h, rname in hosts:
            try:
                want, meta = g.load_inventory(ROOT, {"host_id": h, "role": rname, "inventory_file": fn}, set(), check_home=False)
            except g.GitopsError as e:
                errors.append("%s: %s (%s): %s" % (fn, h, rname, e))
                continue
            parts = ["%s=%d" % (d, len(a)) for d, a in want.items() if a or d != "master_apps"]
            extra = " ha=%s" % ("yes" if meta["cm_ha"] else "no") if rname == "cm" else ""
            print("OK   %-14s %-9s path=%s%s  %s" % (h, rname, meta["base"], extra, " ".join(parts)))

    # apps/ contents
    apps_dir = os.path.join(ROOT, "apps")
    for a in sorted(os.listdir(apps_dir)) if os.path.isdir(apps_dir) else []:
        p = os.path.join(apps_dir, a)
        if not os.path.isdir(p) or a.startswith("."):
            continue
        if not os.path.isfile(os.path.join(p, "default", "app.conf")):
            warns.append("%s: default/app.conf missing" % a)
        if a not in used:
            warns.append("%s: under apps/ but not assigned in any inventory" % a)
        for d, dirs, files in os.walk(p):
            rel = os.path.relpath(d, apps_dir)
            if "local" in dirs:
                warns.append("%s/local/: only accepted in manager/deployment/shcluster apps; move the settings to default/" % rel)
            for fn in files:
                fp = os.path.join(d, fn)
                rp = os.path.relpath(fp, apps_dir)
                if fn == "local.meta":
                    errors.append("%s: local.meta must not be in Git" % rp)
                if os.path.islink(fp):
                    errors.append("%s: symlinks are not allowed" % rp)
                if not fn.endswith(".conf"):
                    continue
                try:
                    with open(fp, errors="replace") as fh:
                        for n, line in enumerate(fh, 1):
                            m = SECRET_RE.match(line)
                            if not (m and m.group(2).strip()):
                                continue
                            if re.match(r"\$\d+\$", m.group(2).strip()):
                                warns.append("%s:%d: %s is stored encrypted ($N$); it only decrypts with that server's splunk.secret, is it really needed?" % (rp, n, m.group(1)))
                            else:
                                errors.append("%s:%d: %s in plain text; secrets must not be in Git" % (rp, n, m.group(1)))
                except OSError as e:
                    errors.append("%s: cannot read (%s)" % (rp, e))

    for w in warns:
        print("WARN ", w)
    for e in errors:
        print("ERROR", e)
    print("\n%d inventories, %d hosts, %d assigned apps, %d warnings, %d errors" % (len(inv_files), nhosts, len(used), len(warns), len(errors)))
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
