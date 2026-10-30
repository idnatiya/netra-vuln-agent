# netra-vuln-agent

Runs Trivy on a Linux VM, keeps a slim report of HIGH/CRITICAL package vulnerabilities, and optionally sends it to netra-vuln central.

```
             standalone                         with central
  ┌──────────────────────────────┐   ┌──────────────────────────────┐
  │ VM                           │   │ VM                           │
  │ timer -> vuln-agent scan     │   │ timer -> vuln-agent scan ────┼──HTTPS──> central API -> MySQL
  │   -> /var/lib/vuln-agent/    │   │   -> /var/lib/vuln-agent/    │            (push only)
  │      reports/ + latest.html  │   │      reports/ + latest.html  │
  │ vuln-agent serve (127.0.0.1) │   │                              │
  └──────────────────────────────┘   └──────────────────────────────┘
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

`vuln-agent install` copies the binary to `/opt/vuln-agent/bin/vuln-agent` (linked as `/usr/bin/vuln-agent`), downloads the pinned Trivy release (checksum verified), writes a standalone `/etc/vuln-agent/config.yaml` if none exists, enables the daily scan and 15-minute heartbeat systemd timers, and starts the report page on `127.0.0.1:8090` (`vuln-agent-serve.service`). It is safe to rerun; an existing config is never touched. See `config.example.yaml` for all config fields.

From a checkout, install or update over SSH (builds both binaries, picks the VM's arch, runs `install`; sudo may ask for a password):
```sh
make deploy HOSTS="user@vm1 user@vm2"
```
A host installed earlier with the old npm package needs `sudo npm rm -g netra-vuln-agent` once, so its npm shim no longer shadows `/usr/bin/vuln-agent`.

Uninstall:
```sh
sudo systemctl disable --now vuln-agent-scan.timer vuln-agent-heartbeat.timer vuln-agent-serve.service
sudo rm -f /etc/systemd/system/vuln-agent-* /usr/bin/vuln-agent && sudo systemctl daemon-reload
sudo rm -rf /opt/vuln-agent /etc/vuln-agent /var/lib/vuln-agent
```

## Standalone

Leave `central_url`, `client_id`, and `token` empty.

```sh
sudo vuln-agent check
sudo vuln-agent scan
sudo vuln-agent report            # newest report as JSON
sudo vuln-agent report -html > report.html
```
The report page runs as `vuln-agent-serve.service`. From a laptop: `ssh -L 8090:127.0.0.1:8090 <vm>`, then open http://localhost:8090.
`/var/lib/vuln-agent/reports/latest.html` is refreshed after every scan. The 30 newest reports are kept.

The page has no authentication. Keep it on loopback; setting `serve_addr` in the config to another address (e.g. a Tailscale IP, `100.64.0.1:8090`) lets anyone who can reach it read the host's vulnerabilities. After changing it, run `sudo systemctl restart vuln-agent-serve`. To turn the page off: `sudo systemctl disable --now vuln-agent-serve` (install only enables it on the first install, so this sticks across updates).

## With central

Set `central_url` and `client_id` (from `central client create <name>`), then:

```sh
sudo VULN_AGENT_ENROLL_TOKEN=<client enroll token> vuln-agent enroll
sudo vuln-agent check
sudo vuln-agent scan
```
Reports are kept locally as in standalone mode and also sent to central. Failed sends are spooled and retried on the next scan or `vuln-agent flush`. To revoke a host, run `central host revoke <hostname>` on central.

## What gets scanned

Two kinds of Trivy runs per scan, kept small on purpose:
- **OS packages** (`rootfs / --pkg-types os`): everything installed with apt/dnf, so the kernel, OpenSSH, nginx/Apache, PHP, Node.js from NodeSource, OpenSSL, and so on.
- **App dependencies** (`rootfs <dir> --pkg-types library`) in `/var/www`, `/srv`, `/opt`, plus the working dir of every pm2 app saved with `pm2 save` (read from `/root/.pm2/dump.pm2` and `/home/*/.pm2/dump.pm2`; pm2 is never run). This finds Laravel/Composer packages (`vendor/composer/installed.json`) and Node packages (`node_modules`); lockfiles alone are not read.

Apps elsewhere: list their folders in `/etc/vuln-agent/config.yaml` (this replaces the default list; `[]` scans OS packages only):
```yaml
app_dirs: ["/var/www", "/srv", "/opt", "/home/deploy/apps"]
```

## Excluding folders

Trivy skips `/proc`, `/sys`, `/dev`, `/run`, `/tmp`, snap/docker/containerd state, `/mnt`, `/media`, caches, `/usr/share/doc`, and `/opt/vuln-agent` by default. To skip more on one host, list them in `/etc/vuln-agent/config.yaml`; they are added to the defaults (or to central's list), in both modes:
```yaml
extra_skip_dirs: ["/data/backup", "/home/*/projects"]
```
Run `sudo vuln-agent check` after editing. To change the list for every host of a client, set `skip_dirs` on central instead (`central client set-config`); that one replaces the default list, so include the defaults you still want.

## What the agent reads and sends

It reads, through Trivy, the OS package database and the app folders above (skipping pseudo filesystems and caches), pm2 dump files, `/etc/os-release`, the running kernel, uptime, the reboot-required flag, and whether automatic updates are enabled. The report holds that host metadata and, per finding: target, type, CVE, package name/path, installed and fixed version, severity, and title. Nothing else is sent, and the agent never runs commands it receives from central.

## License

Copyright (C) 2026 idnatiya

GPL-3.0-only. See [LICENSE](LICENSE).
