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

## Install (binary, for now)

```sh
make build-linux     # dist/vuln-agent-linux-{amd64,arm64}
```
Copy the binary to `/opt/vuln-agent/bin/vuln-agent` and Trivy to `/opt/vuln-agent/bin/trivy` (or use the Ansible role in `deploy/ansible`), then write `/etc/vuln-agent/config.yaml` (mode 600) from `packaging/config.example.yaml`.

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
