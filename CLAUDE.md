# Project: netra-vuln-agent

## Language
Everything in this repo is written in **English**: code, identifiers, comments, log messages, error strings, docs, commit messages, and config examples.

## Context
A small non-AI program installed on Linux VMs (Ubuntu/Debian and the RHEL family: AlmaLinux/Rocky/CentOS). It runs Trivy, slims down the results, and keeps them. Two modes, chosen by the config:
- **Standalone** (`central_url` empty): reports stay on the host (`/var/lib/vuln-agent/reports/`), viewable as `latest.html`, `vuln-agent report`, or `vuln-agent serve`.
- **With central** (`central_url` + `client_id` set): reports are also sent to central (repo `netra-vuln`: API + MySQL + admin dashboard), which manages 26 VMs across several clients.

Central imports this module for the JSON contract (`wire`, `scanconfig`). Tag a release (`vX.Y.Z`) when the contract changes and bump it in central's `go.mod`.

If a design decision is ambiguous, ask first.

## Mandatory Principles
1. **Passive agent**: the agent ONLY sends data and fetches declarative (read-only) config. It MUST NOT have any feature to run commands, scripts, or auto-updates from central in any form. `serve` is read-only and never triggers a scan.
2. **Push only**: all communication with central is initiated by the agent. Transport is HTTPS by default; plain HTTP is allowed only over an already-encrypted network (e.g. Tailscale), and the agent logs a warning when it is used.
3. **Simple and maintainable**: the only external dependency is `gopkg.in/yaml.v3`. Keep scope small.

## Stack
- Language: **Go** (latest stable); stdlib `net/http` for the central client and `serve`, `html/template` for the report page
- Static binary (`CGO_ENABLED=0`), targets `linux/amd64` and `linux/arm64`
- Scanner: **Trivy binary** invoked via `os/exec` (DO NOT import Trivy as a library). Trivy version is pinned in the build config.
- Packaging (Phase 4): **nfpm** or **GoReleaser** producing `.deb` and `.rpm`, plus a `.tar.gz` tarball + `install.sh`
- Deployment: **Ansible role** (`deploy/ansible/roles/vuln_agent`)
- CI: **GitHub Actions**

## Repo Layout
```
go.mod                  # module github.com/idnatiya/netra-vuln-agent
cmd/vuln-agent/         # composition root: parse subcommand, wire adapters -> usecases
internal/
  domain/               # entities + pure business rules (Finding, Report, HostInfo, ScanConfig), stdlib only
  usecase/              # scan/heartbeat/flush/enroll/check orchestration; ports (interfaces) in ports.go
  adapter/
    trivy/              # Scanner: exec Trivy + streaming parser
    hostinfo/           # Linux HostInspector
    central/            # HTTP client to central; dto.go maps domain <-> wire
    spool/              # filesystem report store (send spool and local history)
    localconfig/        # config.yaml + ScanConfig cache
    web/                # HTML report page + read-only HTTP handler
wire/                   # public: the JSON contract with central
scanconfig/             # public: Config, Default(), Validate() (central validates overrides with it)
packaging/              # config.example.yaml (systemd units, nfpm config in Phase 4)
deploy/ansible/         # role "vuln_agent", dev inventory, example per-client inventory
deploy/dev/fakecentral/ # dev stand-in for central (logs + saves agent payloads)
docs/
```
Dependency rule: `domain` <- `usecase` <- `adapter` <- `cmd`. Domain knows nothing about JSON/HTTP/exec. Interfaces are defined on the consumer side.

### Contract (`wire`, `scanconfig`)
Only JSON-tagged contract types. Central decodes requests leniently (ignores unknown fields, so newer agents keep working); the agent decodes responses strictly, so central must never add response fields. The agent's `domain.ScanConfig` is an alias of `scanconfig.Config`.

## File locations
- Agent binary: `/opt/vuln-agent/bin/vuln-agent`, symlinked as `/usr/bin/vuln-agent` (so `sudo vuln-agent scan` works; run it after patching a VM to resolve fixed findings right away)
- Trivy binary: `/opt/vuln-agent/bin/trivy`
- Config: `/etc/vuln-agent/config.yaml` (mode 600, owner root)
- Spool (unsent reports, central mode): `/var/lib/vuln-agent/spool/` (5 newest)
- Report history (both modes): `/var/lib/vuln-agent/reports/` (30 newest gzip JSON + `latest.html`)
- Trivy cache: `/var/lib/vuln-agent/cache/`

## Local config (`config.yaml`)
See `packaging/config.example.yaml`.
```yaml
central_url: https://<central.domain>   # empty = standalone; http:// allowed over Tailscale, with a warning
client_id: <client_a>                   # must be empty when standalone
token: <per-host token>                 # must be empty when standalone
hostname_override: ""                   # optional; defaults to the OS hostname
ca_file: ""                             # optional, for a custom CA
```

## CLI subcommands
- `vuln-agent scan`: run one scan cycle, keep the report in the history, refresh `latest.html`, and (central mode) send it (invoked by a systemd timer)
- `vuln-agent report [-html]`: print the newest report as JSON, or the HTML page
- `vuln-agent serve [-addr 127.0.0.1:8090]`: read-only HTTP over the history (`/`, `/reports/{id}`, `/reports/{id}.json`, `/healthz`). No auth, so it binds loopback by default and warns on any other address; reach it with `ssh -L`.
- `vuln-agent heartbeat`: send a heartbeat (no-op when standalone)
- `vuln-agent flush`: resend spooled reports (central only)
- `vuln-agent enroll [--force]` (central only): read `central_url` + `client_id` from config, read the enroll token from env `VULN_AGENT_ENROLL_TOKEN` or stdin (NEVER via CLI args, so it does not leak in `ps`), call `POST /api/v1/enroll`, and write `host_token` into `config.yaml` atomically (mode 600). Refuse if a token is already set, unless `--force`.
- `vuln-agent version`
- `vuln-agent check`: validate config and the Trivy binary, plus token and connectivity to central in central mode

## `scan` flow
1. Central mode: send spooled reports first, then fetch scan config from `GET /api/v1/config` (read-only). On failure (or standalone), use the last locally cached config, or the default if none exists.
2. Run Trivy with a `context` timeout (default 40 minutes), at low priority, with default arguments:
   ```
   rootfs /
   --scanners vuln
   --list-all-pkgs=false
   --ignore-unfixed
   --severity HIGH,CRITICAL
   --timeout 30m
   --cache-dir /var/lib/vuln-agent/cache
   --skip-dirs /proc,/sys,/dev,/run,/tmp,/snap,/var/lib/snapd,/var/lib/docker,/var/lib/containerd,/mnt,/media,/var/cache,/root/.cache,/home/*/.cache,/home/*/.local/share/pnpm,/usr/share/doc
   --format json -q --output <temp file>
   ```
   `severity`, `ignore_unfixed`, `skip_dirs`, and `timeout` can be overridden by config from central, but the agent ONLY accepts those fields. Reject any other field.
3. Decode the output with `json.NewDecoder` (streaming) into a slim struct containing only:
   `Target, Type, VulnerabilityID, PkgName, PkgPath, InstalledVersion, FixedVersion, Severity, Title`.
4. Add host metadata:
   `hostname, os_family, os_name, os_version, arch, kernel_running, uptime_seconds, reboot_required (check /var/run/reboot-required or needs-restarting -r), unattended_upgrades_enabled (or dnf-automatic on RHEL), agent_version, trivy_version, scanned_at, scan_duration_seconds`.
5. Save the report to the history, then (central mode) send it gzipped to `POST /api/v1/report`.
6. If sending fails, save it to the spool. Status codes: 400/413/422 = permanent reject (dropped); 401/403/409/429/5xx = spooled and retried.
7. If Trivy fails, still keep/send a report with status `error` and its error message (truncated to at most 4KB).

The HTML page shows host facts, counts, findings by severity, and new/resolved since the previous successful scan (key: CVE, package, installed version, target, pkg path). Its CSP is `default-src 'none'; style-src 'unsafe-inline'`: no scripts or remote assets.

## Heartbeat
`POST /api/v1/heartbeat` with compact host metadata. Scheduled every 15 minutes.

## systemd (Phase 4)
- `vuln-agent-scan.service` + `vuln-agent-scan.timer` (daily, `RandomizedDelaySec=2h`, `Persistent=true`)
- `vuln-agent-heartbeat.service` + `.timer` (every 15 minutes)
- `vuln-agent-serve.service` (optional, not enabled by default)
- Resource limits: `CPUQuota=100%`, `MemoryMax=1G`, `Nice=19`, `IOSchedulingClass=idle`

## Logging
Log to stdout/stderr (into journald), structured format (`log/slog`). NEVER print the token in logs.

## Deployment (`deploy/ansible/roles/vuln_agent`)
- Detect `ansible_architecture` (x86_64/aarch64) and later `ansible_os_family` for `.deb`/`.rpm`
- `vuln_agent_install_method: binary` (now: copy `dist/vuln-agent-linux-<arch>` + pinned Trivy release with checksum) -> `package` once Phase 4 ships packages; tarball fallback for unknown distros
- Template `config.yaml` from inventory vars, compared by content and preserving the existing host token (enroll rewrites the file)
- Empty `vuln_agent_central_url` + `vuln_agent_client_id` = standalone (no enroll)
- Enroll only when no token (or `vuln_agent_force_enroll`), enroll token from Ansible Vault, `no_log`
- Run `vuln-agent check`; enable timers once packaging provides the systemd units
- Example inventory grouped per client with different SSH user/port/key per group and `ProxyJump`
- Sample VM loop: `make scan-dev ARGS="-e @<enroll-vars.yml>"` (a mode-600 file with `vuln_agent_enroll_token`, never committed)

## Packaging & CI (Phase 4)
- nfpm/GoReleaser produces: `.deb`, `.rpm`, `.tar.gz` (amd64 + arm64)
- Download the pinned Trivy binary at build time, verify its checksum, bundle it into the package
- Postinstall: create directories, set permissions, `systemctl daemon-reload`, enable timers (but do not start a scan if the config is not filled in yet)
- Preremove: stop and disable timers
- GitHub Actions: lint, test, build, package, publish release artifacts

## Testing
- `make test`
- Unit tests for the Trivy parser with JSON fixtures (including large files and empty output)
- Usecase tests with fakes for both modes; HTML/handler tests (escaping, diff, path safety)

## Out of Scope (do not build)
- Remote command execution in the agent
- Agent auto-update from central
- Secret, misconfig, or license scanning (vuln only for now)
- AI/LLM integration
