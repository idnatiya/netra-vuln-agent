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

```sh
make build-linux     # dist/vuln-agent-linux-{amd64,arm64}
scp dist/vuln-agent-linux-amd64 <vm>:
ssh <vm> sudo ./vuln-agent-linux-amd64 install
```
`install` copies the binary to `/opt/vuln-agent/bin/vuln-agent` (linked as `/usr/bin/vuln-agent`), downloads the pinned Trivy release (checksum verified), writes a standalone `/etc/vuln-agent/config.yaml` if none exists, and enables the daily scan and 15-minute heartbeat systemd timers. It is safe to rerun; an existing config is never touched. See `packaging/config.example.yaml` for all config fields.

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
sudo vuln-agent serve             # http://127.0.0.1:8090, from a laptop: ssh -L 8090:127.0.0.1:8090 <vm>
```
`/var/lib/vuln-agent/reports/latest.html` is refreshed after every scan. The 30 newest reports are kept.

`serve` has no authentication. Keep it on loopback; binding another address (e.g. a Tailscale IP) lets anyone who can reach it read the host's vulnerabilities.

## With central

Set `central_url` and `client_id` (from `central client create <name>`), then:

```sh
sudo VULN_AGENT_ENROLL_TOKEN=<client enroll token> vuln-agent enroll
sudo vuln-agent check
sudo vuln-agent scan
```
Reports are kept locally as in standalone mode and also sent to central. Failed sends are spooled and retried on the next scan or `vuln-agent flush`. To revoke a host, run `central host revoke <hostname>` on central.

## What the agent reads and sends

It reads the filesystem through Trivy (`rootfs /`, skipping pseudo filesystems and caches), `/etc/os-release`, the running kernel, uptime, the reboot-required flag, and whether automatic updates are enabled. The report holds that host metadata and, per finding: target, type, CVE, package name/path, installed and fixed version, severity, and title. Nothing else is sent, and the agent never runs commands it receives from central.
