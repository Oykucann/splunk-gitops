# splunk-apps

The single source of truth for Splunk apps. Each server pulls the apps assigned to it in `org_splunk_inventory.yaml` itself, using `org_gitops_app`. Detailed schema: https://claude.ai/artifact/G1A9aeJmyfb6bpqDmkQEVU

```
splunk-apps/
├── .gitattributes        # all text files as LF
├── .gitignore            # local.meta, passwords.conf, *.pem, __pycache__
├── .gitlab-ci.yml        # tools/check_repo.py on MRs (delete if you have no runner)
├── README.md
├── org_splunk_inventory.yaml   # which server → which app → which directory
├── envs/<env>/org_splunk_inventory.yaml   # (optional) several environments
├── apps/                 # each app once, flat: apps/<app_name>/default/...
└── tools/
    ├── check_repo.py     # pre-MR check; does not connect to servers
    └── org_gitops_app/   # the script itself; installed on servers BY HAND, never deployed
```

## Rules

- **Several environments:** Put each inventory under `envs/<env>/org_splunk_inventory.yaml` and add `inventory_file = envs/<env>/org_splunk_inventory.yaml` to `local/gitops.conf` on that environment's servers. `check_repo.py` checks every inventory.
- **CM:** Use `cm_ha_availability: yes` for an active-passive pair, and `no` for a single CM (or when each CM manages its own cluster).
- **`main` is protected:** It changes only through MRs. Approving the MR approves the change.
- **App names:** Letters, digits and `_ . -`. A company-name prefix is recommended.
- **Apps going to `etc_apps`:** Must not contain `local/` or `metadata/local.meta`; settings go under `default/`. The server's `local/` is preserved.
- **Never in Git:** `etc/system/local` (pass4SymmKey, sslPassword, site/redundancy), tokens, LDAP bind passwords, certificates.
- **Apps that cannot be managed:** `_cluster`, `search`, `launcher`, `splunk_*`, `Splunk_SA_*`, `org_gitops_app`.
- **Deletion:** When an app is removed from a list, it is deleted only if the script installed it. Apps placed by hand stay.

## First fill: take today's state exactly as it is

The goal is to see only `adopt` and `unchanged` in the first `plan` output. Copy without fixing anything; make improvements later in separate MRs.

Take an archive on each server (as the `splunk` user, read-only):

```bash
# cm01 (active CM)
tar czf /tmp/cm01_manager-apps.tgz -C /data/splunk/etc/manager-apps --exclude=_cluster .
# ds01 / ds02
tar czf /tmp/ds01_deployment-apps.tgz -C /data/splunk/etc/deployment-apps .
# shcdeployer01
tar czf /tmp/deployer_shcluster-apps.tgz -C /data/splunk/etc/shcluster/apps .
# SHs and etc/apps: only the apps you want to manage
tar czf /tmp/sh01_apps.tgz -C /data/splunk/etc/apps org_app1 org_app2
```

Extract the archives under `apps/` on your own machine. If the same name has different content on two servers, stop: either split it into two apps or decide which one is correct. Then:

1. **`etc_apps` apps:** Do not put the server's `local/` directory into the repo. If a setting must go into the repo, move it into `default/`; the first plan will then show `adopt_update`, which is expected.
2. **`serverclass.conf` on the DS:** If it lives under `etc/system/local` today, move it into an app as `org_ds01_serverclass/default/serverclass.conf`. Remove the `system/local` copy on the server after the script has installed this app; `system/local` always takes precedence over apps.
3. **Inventory:** Add the apps to the right lists. Set `default_path` and, for CMs, `cm_ha_availability` to match your environment.
4. **Check:**
   ```bash
   python3 tools/check_repo.py
   ```
   If there are no errors, open the MR.

## Day-to-day flow

```bash
git switch -c change/short-description
# edit apps/ or org_splunk_inventory.yaml
python3 tools/check_repo.py
git commit -am "org_idx_props: new sourcetype"
git push -u origin HEAD     # → MR → approval → merge
```

After the merge, in phase 1, on the relevant server:

```bash
G="/data/splunk/bin/splunk cmd python3 /data/splunk/etc/apps/org_gitops_app/bin/gitops.py"
$G plan      # is this the diff you expect?
$G stage     # writes to disk, no push/apply
# then by hand: apply cluster-bundle / apply shcluster-bundle / reload deploy-server
```

To roll back, either open an MR with `git revert` or, in an emergency, run `$G apply --sha <old_commit>` on the server.

## Updating `tools/org_gitops_app`

The script lives in the repo but does not deploy itself. Copy the new version to each server by hand. Do not touch `local/`; that is where `gitops.conf` and the token live. Then:

```bash
curl -sk -u <user> -X POST https://127.0.0.1:8089/services/apps/local/_reload
$G status
```
