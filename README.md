# netra-vuln-agent

Runs Trivy on a Linux VM and sends a slim report of HIGH/CRITICAL package vulnerabilities to netra-vuln central.

```
  ┌──────────────────────────────┐
  │ VM                           │
  │ timer -> vuln-agent scan ────┼──HTTPS──> central API -> MySQL
  │                              │            (push only)
  └──────────────────────────────┘
```

## Install

On the VM, download the binary for its arch from the latest GitHub Release, check it, and install:
```sh
a=$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')
u=https://github.com/idnatiya/netra-vuln-agent/releases/latest/download
curl -fsSLO "$u/vuln-agent-linux-$a" -fsSLO "$u/SHA256SUMS"
grep " vuln-agent-linux-$a\$" SHA256SUMS | sha256sum -c - \
  && chmod +x "vuln-agent-linux-$a" && sudo "./vuln-agent-linux-$a" install
rm -f "vuln-agent-linux-$a" SHA256SUMS
```
Run the same block to update. For a specific version set `u=https://github.com/idnatiya/netra-vuln-agent/releases/download/vX.Y.Z`. The checksum catches a broken download, not a compromised release.

`vuln-agent install` copies the binary to `/opt/vuln-agent/bin/vuln-agent` (linked as `/usr/bin/vuln-agent`), downloads the pinned Trivy release (checksum verified), writes a `/etc/vuln-agent/config.yaml` template if none exists, and enables the daily scan and 15-minute heartbeat systemd timers. It is safe to rerun; an existing config is never touched. See `config.example.yaml` for all config fields.

From a checkout, install or update over SSH (builds both binaries, picks the VM's arch, runs `install`; sudo may ask for a password):
```sh
make deploy HOSTS="user@vm1 user@vm2"
```
A host installed earlier with the old npm package needs `sudo npm rm -g netra-vuln-agent` once, so its npm shim no longer shadows `/usr/bin/vuln-agent`.

Updating from a version with the report page: `install` removes `vuln-agent-serve.service` and `/var/lib/vuln-agent/reports/`, but `serve_addr` must be removed from the config first, or `scan` and `heartbeat` fail to load it:
```sh
ssh user@vm "sudo sed -i '/^serve_addr:/d' /etc/vuln-agent/config.yaml"
```
A host without `central_url` (the old standalone mode) needs to be set up for central as below.

Uninstall:
```sh
sudo systemctl disable --now vuln-agent-scan.timer vuln-agent-heartbeat.timer
sudo rm -f /etc/systemd/system/vuln-agent-* /usr/bin/vuln-agent && sudo systemctl daemon-reload
sudo rm -rf /opt/vuln-agent /etc/vuln-agent /var/lib/vuln-agent
```

## Connect to central

Set `central_url` and `client_id` (from `central client create <name>`), then:

```sh
sudo VULN_AGENT_ENROLL_TOKEN=<client enroll token> vuln-agent enroll
sudo vuln-agent check
sudo vuln-agent scan
```
Failed sends are spooled and retried on the next scan or `vuln-agent flush`. To revoke a host, run `central host revoke <hostname>` on central.

## What gets scanned

Two kinds of Trivy runs per scan, kept small on purpose:
- **OS packages** (`rootfs / --pkg-types os`): everything installed with apt/dnf, so the kernel, OpenSSH, nginx/Apache, PHP, Node.js from NodeSource, OpenSSL, and so on.
- **App dependencies** (`rootfs <dir> --pkg-types library`) in `/var/www`, `/srv`, `/opt`, plus the working dir of every pm2 app saved with `pm2 save` (read from `/root/.pm2/dump.pm2` and `/home/*/.pm2/dump.pm2`; pm2 is never run). This finds Laravel/Composer packages (`vendor/composer/installed.json`) and Node packages (`node_modules`); lockfiles alone are not read.

Apps elsewhere: list their folders in `/etc/vuln-agent/config.yaml` (this replaces the default list; `[]` scans OS packages only):
```yaml
app_dirs: ["/var/www", "/srv", "/opt", "/home/deploy/apps"]
```

## Excluding folders

Trivy skips `/proc`, `/sys`, `/dev`, `/run`, `/tmp`, snap/docker/containerd state, `/mnt`, `/media`, caches, `/usr/share/doc`, and `/opt/vuln-agent` by default. To skip more on one host, list them in `/etc/vuln-agent/config.yaml`; they are added to the defaults (or to central's list):
```yaml
extra_skip_dirs: ["/data/backup", "/home/*/projects"]
```
Run `sudo vuln-agent check` after editing. To change the list for every host of a client, set `skip_dirs` on central instead (`central client set-config`); that one replaces the default list, so include the defaults you still want.

## What the agent reads and sends

It reads, through Trivy, the OS package database and the app folders above (skipping pseudo filesystems and caches), pm2 dump files, `/etc/os-release`, the running kernel, uptime, the reboot-required flag, and whether automatic updates are enabled. The report holds that host metadata and, per finding: target, type, CVE, package name/path, installed and fixed version, severity, and title. Nothing else is sent, and the agent never runs commands it receives from central.

## License

Copyright (C) 2026 idnatiya

GPL-3.0-only. See [LICENSE](LICENSE).
