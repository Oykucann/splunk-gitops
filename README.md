# org_gitops_app: Splunk app deployment from GitLab (pull model)

A Splunk app that runs on every Splunk server. It reads the inventory in the GitLab repo (`org_splunk_inventory.yaml`), pulls only the apps that belong to its own role, and writes them to the right directory. Optionally it also runs the role's action: CM bundle apply, deployer push or DS reload.

**Nothing runs automatically in phase 1.** The scripted input ships disabled. You run `plan` and `stage` and do the push by hand.

## Servers and directories

| Server | `role` | Directories it writes | `apply` action |
|---|---|---|---|
| cm01, cm02 | `cm` | `etc/manager-apps` (or `etc/master-apps`, the legacy name). With `cm_ha_availability: yes` **only the active CM** writes (`ha_active_status` 200); with `no` every CM writes to its own cluster. `etc/apps`: on every CM. | validate (check-restart), apply cluster-bundle, then waits until 6/6 peers are on the new bundle |
| ds01, ds02 | `ds` | `etc/deployment-apps`, `etc/apps` (including `serverclass.conf`) | `reload deploy-server` |
| deployer | `deployer` | `etc/shcluster/apps`, `etc/apps` | `apply shcluster-bundle` |
| sh01, sh02 | `sh` | `etc/apps` | reloads the app list; restart is manual |

Rules:
- **Scope:** Only apps listed in the inventory are touched. Splunk's own apps, `_cluster`, `splunk_*` and `org_gitops_app` itself cannot be managed.
- **Deletion:** Only an app the script installed earlier and that has been removed from the list is deleted. Apps placed by hand stay.
- **`etc/apps` protection:** `local/` and `metadata/local.meta` are preserved, so objects created in the UI are not overwritten. These apps in Git must not contain `local/`.
- **Restart:** The script never restarts a server. On a CM it stops if the bundle requires a peer restart and `allow_rolling_restart = false`.
- **Backup:** Before every change, the old version of each changed app is backed up under `backup_dir/<host>/<dest>/`. The last 2 backups per dest are kept.

## Repo layout and inventory

Ready-made skeleton: [`splunk-apps/`](splunk-apps/README.md). It contains an empty `org_splunk_inventory.yaml` with the prod host names, `tools/check_repo.py` for pre-MR checks, and `.gitlab-ci.yml`.

```
apps/<app_name>/default/...  metadata/default.meta
org_splunk_inventory.yaml                # single environment
envs/<env>/org_splunk_inventory.yaml     # several environments in one repo
```

Rules:
- **Lists:** Role-level lists go to every host in that role; host-level lists are added to them.
- **Directory:** Built as `<path>/etc/<dest>`. For example `manager_apps` → `/data/splunk/etc/manager-apps`.
  - The directory name uses a hyphen, the key an underscore.
  - `path` precedence: host > role > `default_path`.
  - If `path` is not the directory of the Splunk running on that server, the run stops.
- **`cm_ha_availability`:** Required for the cm role.
  - `yes`: only the active CM writes and applies.
  - `no`: each CM is the only CM of its own cluster and writes.
  - If this says `no` but the CM turns out to be a standby, the run stops, so two CMs never apply to the same cluster.
  - If this says `yes` but the CM has no redundancy, the run also stops.
- **`master_apps`:** The legacy name (`etc/master-apps`). Cannot be combined with `manager_apps` on one CM.
- **YAML style:** Write plain values: `default_path: /data/splunk`, `cm_ha_availability: no`. The `[ ... ]` list form is also accepted.
- **Several environments:** Add this line to the server's `local/gitops.conf`:
  ```
  inventory_file = envs/<env>/org_splunk_inventory.yaml
  ```

```yaml
version: 1
default_path: /data/splunk
roles:
  cm:
    cm_ha_availability: yes
    hosts: [cm01, cm02]
    manager_apps: [org_all_indexes]
    etc_apps: [org_cm_base]
  ds:
    hosts:
      ds01: {deployment_apps: [org_uf_site1_base], etc_apps: [org_ds01_serverclass]}
      ds02: {deployment_apps: [org_uf_site2_base], etc_apps: [org_ds02_serverclass]}
    deployment_apps: [org_uf_common]
  deployer:
    hosts: [shcdeployer01]
    shcluster_apps: [org_sh_base]
  sh:
    hosts: [sh01, sh02]
    etc_apps: [org_sh_base]
```

## Installation (on every server, as the `splunk` user)

1. **Copy the app:** Put the `org_gitops_app` directory under `/data/splunk/etc/apps/`.
2. **Write the server-specific settings:** `/data/splunk/etc/apps/org_gitops_app/local/gitops.conf`
   ```
   [gitops]
   host_id = cm01
   role = cm
   gitlab_url = https://gitlab.company.local
   project = group/splunk-apps
   ca_bundle = /data/splunk/etc/auth/company_ca.pem
   splunk_mgmt_uri = https://127.0.0.1:8089
   ```
   Extra line for the deployer: `shc_target_uri = https://<an-shc-member>:8089`
3. **Register the app with Splunk (no restart needed):**
   ```bash
   curl -sk -u admin -X POST https://127.0.0.1:8089/services/apps/local/_reload
   ```
4. **Enter the token.** It is prompted for without echo and stored encrypted in `local/passwords.conf`:
   ```bash
   /data/splunk/bin/splunk cmd python3 /data/splunk/etc/apps/org_gitops_app/bin/gitops.py set-token
   ```
5. **Test the connection:**
   ```bash
   /data/splunk/bin/splunk cmd python3 /data/splunk/etc/apps/org_gitops_app/bin/gitops.py status
   ```

The backup directory must exist and be writable by the `splunk` user: `mkdir -p /home/splunk/org_gitops_app_backup`.

## Commands

Shorthand: `G="/data/splunk/bin/splunk cmd python3 /data/splunk/etc/apps/org_gitops_app/bin/gitops.py"`

| Command | What it does |
|---|---|
| `$G status` | Role, inventory, CM active/standby/single, GitLab, token expiry, last applied commit |
| `$G plan` | List of differences; writes nothing |
| `$G stage` | Writes the differences to disk; no push, apply or reload. Does not overwrite apps changed by hand (drift); reports them. |
| `$G apply` | Writes and runs the role's action |
| `$G apply --only manager_apps` | A single dest |
| `$G apply --sha <commit>` | A specific commit; for emergency rollback |

When run by hand, the Splunk user and password are prompted for. The person who ran it is recorded in `_audit` and in the log.

### Manual push in phase 1

```bash
$G plan
$G stage
# CM (only on the active one, or on a single CM):
/data/splunk/bin/splunk validate cluster-bundle --check-restart
/data/splunk/bin/splunk apply cluster-bundle
# deployer:
/data/splunk/bin/splunk apply shcluster-bundle -target https://<member>:8089
# DS:
/data/splunk/bin/splunk reload deploy-server
```

### Switching to automatic

`local/inputs.conf`:
```
[script://$SPLUNK_HOME/etc/apps/org_gitops_app/bin/gitops.py]
disabled = 0
```
Then reload the inputs:
```bash
curl -sk -u admin -X POST https://127.0.0.1:8089/servicesNS/nobody/org_gitops_app/data/inputs/script/_reload
```
What an automatic run does is set by `mode` in `local/gitops.conf`: first `plan`, then `stage`, then `apply`. The session key comes via `passAuth`; no password is stored.

## GitLab token

- **Type:** Project access token
- **Role:** Reporter
- **Scope:** `read_api`
- **Lifetime:** 1 year

On every run the script reads the token's expiry date from GitLab. 30 days before expiry it writes a warning to the `status` output and the log. If GitLab does not return a date, `token_expires` in `gitops.conf` is used.

To renew the token, run `set-token` and then `status` on every server. Put a reminder in the shared calendar 30 days before expiry.

## Log

`/data/splunk/var/log/splunk/org_gitops_app.log` is indexed into `_internal`:
```
index=_internal source=*org_gitops_app.log (event=run_done OR event=write OR event=action_failed OR event=run_failed)
```

## Behaviour measured in the lab (worth knowing in prod)

Details: `lab/gitops/README.md`.

- **On an active CM, `apply` validates on every run.** With no changes it takes ~15 s and does not touch the peers. After a manual apply the script does not apply twice.
- **Bundle that requires a restart:** The script stops and returns rc=2. The app waits in `manager-apps`. Two options:
  - Run `apply cluster-bundle` by hand in a maintenance window; the peers do a rolling restart.
  - Or revert the change in Git.

  If someone else applies by hand while the app is waiting, a rolling restart starts.
- **Telling a single CM apart:** A single CM without redundancy also returns 503 on `ha_active_status`. That is why the script looks at `manager_switchover_mode` in `cluster/config`: `disabled` on a single CM, `manual`/`auto` on an active-passive pair. If `cm_ha_availability` in the inventory contradicts this, the script stops.
- **If a peer is Down**, apply still happens; only Up peers are waited for and the Down ones are logged. A Down peer gets the bundle from the CM when it comes back.
- **If RF/SF is not met** (e.g. right after a switchover), no apply is done. It is applied on the next run.
- **Deployer push:** Runs with the deployer's own session; no separate user is needed on the SHC members. A push can trigger a rolling restart on the members. While the restart is running, the script retries every 30 s for up to 15 minutes.
- **`stage` on SHs:** Writes the files, but a new app only shows up after `apply` (the app list is reloaded) or a restart. Some changed settings in existing apps need a restart. The script logs this as `restart_recommended` and does not restart.
- **DS:** The script reloads the app list first, then runs `reload deploy-server`, so a new `serverclass.conf` app is picked up too.
- **Permissions for manual runs:** The user running it by hand must be able to read storage/passwords and to run bundle apply, push and DS reload. The lab used admin; a narrower role was not tested.
