# Project: netra-vuln-agent

## Language
Everything in this repo is written in **English**: code, identifiers, comments, log messages, error strings, docs, commit messages, and config examples.

## Context
A small non-AI program installed on Linux VMs (Ubuntu/Debian and the RHEL family: AlmaLinux/Rocky/CentOS). It runs Trivy, slims down the results, and keeps them. Two modes, chosen by the config:
- **Standalone** (`central_url` empty): reports stay on the host (`/var/lib/vuln-agent/reports/`), viewable as `latest.html`, `vuln-agent report`, or `vuln-agent serve`.
- **With central** (`central_url` + `client_id` set): reports are also sent to central (repo `netra-vuln`: API + MySQL + admin dashboard), which manages 26 VMs across several clients.

Central imports this module for the JSON contract (`pkg/wire`, `pkg/scanconfig`). Tag a release (`vX.Y.Z`) when the contract changes and bump it in central's `go.mod`.

If a design decision is ambiguous, ask first.

## Mandatory Principles
1. **Passive agent**: the agent ONLY sends data and fetches declarative (read-only) config. It MUST NOT have any feature to run commands, scripts, or auto-updates from central in any form. `serve` is read-only and never triggers a scan.
2. **Push only**: all communication with central is initiated by the agent. Transport is HTTPS by default; plain HTTP is allowed only over an already-encrypted network (e.g. Tailscale), and the agent logs a warning when it is used.
3. **Simple and maintainable**: the only external dependency is `gopkg.in/yaml.v3`. Keep scope small.

## Stack
- Language: **Go** (latest stable; build toolchain pinned by `toolchain` in `go.mod`, bump it for Go security releases; keep the `go` line low so central can build); stdlib `net/http` for the central client and `serve`, `html/template` for the report page
- Static binary (`CGO_ENABLED=0`), targets `linux/amd64` and `linux/arm64`
- Scanner: **Trivy binary** invoked via `os/exec` (DO NOT import Trivy as a library). Trivy version is pinned by `TRIVY_VERSION` in the `Makefile` (ldflag `main.trivyVersion`).
- Install: `vuln-agent install` (no Ansible, no .deb/.rpm, no CI release pipeline)
- Distribution: npm package `netra-vuln-agent` (`sudo npm i -g netra-vuln-agent`). Root `package.json` + `vuln-agent.js` (Node shim, no deps) ship both `dist/vuln-agent-linux-{amd64,arm64}` binaries. Postinstall runs `vuln-agent install` only when global and root, and always exits 0 (a failed postinstall makes npm remove the binary needed to retry).
- License: GPL-3.0-only (`LICENSE`, copyright idnatiya); keep new dependencies GPL-3.0-compatible.
- Release: bump `version` in `package.json`, commit, tag `vX.Y.Z`, `make npm-pack` (binaries get the same version), `npm publish <tgz>`.
- Manual/dev update over SSH: `make deploy HOSTS="user@vm ..."` (build, scp to the user's home, `sudo ./vuln-agent.new install`, remove it).

## Repo Layout
Folder pattern follows [khannedy/golang-clean-architecture](https://github.com/khannedy/golang-clean-architecture), stdlib only (none of its libraries). Files carry a layer suffix (`scan_usecase.go`, `report_repository.go`, `central_gateway.go`).
```
go.mod                  # module github.com/idnatiya/netra-vuln-agent
cmd/vuln-agent/         # main.go only: version vars (ldflags) + cli.Run
internal/
  entity/               # entities + pure business rules (Finding, Report, HostInfo, ScanConfig), stdlib only
  usecase/              # scan/heartbeat/flush/enroll/check orchestration; ports (interfaces) in ports.go
  repository/           # filesystem storage: reports (send spool + local history), scan config cache
  gateway/
    central/            # HTTP client to central
    trivy/              # Scanner: exec Trivy + streaming parser; Trivy release installer
    hostinfo/           # Linux HostInspector
  model/converter/      # entity -> wire mapping
  delivery/
    cli/                # subcommands (Run), install command
    http/               # HTML report page + read-only HTTP handler (imported as reporthttp)
  config/               # config.yaml (Load, Validate, host token) + app.go wiring (paths, NewApp)
pkg/
  wire/                 # public: the JSON contract with central
  scanconfig/           # public: Config, Default(), Validate() (central validates overrides with it)
test/                   # all tests, black-box (package test); fixtures in test/testdata
README.md
config.example.yaml
```
Keep root folders to `cmd internal pkg test`; `pkg/` holds only what central imports.
Dependency rule: `entity` <- `usecase` <- `repository`/`gateway`/`model` <- `config` <- `delivery` <- `cmd`. Entity knows nothing about JSON/HTTP/exec. Interfaces are defined on the consumer side (`usecase/ports.go`).

### Contract (`pkg/wire`, `pkg/scanconfig`)
Only JSON-tagged contract types. Central decodes requests leniently (ignores unknown fields, so newer agents keep working); the agent decodes responses strictly, so central must never add response fields. The agent's `entity.ScanConfig` is an alias of `scanconfig.Config`.

## File locations
- Agent binary: `/opt/vuln-agent/bin/vuln-agent`, symlinked as `/usr/bin/vuln-agent` (so `sudo vuln-agent scan` works; run it after patching a VM to resolve fixed findings right away)
- Trivy binary: `/opt/vuln-agent/bin/trivy`
- Config: `/etc/vuln-agent/config.yaml` (mode 600, owner root)
- Spool (unsent reports, central mode): `/var/lib/vuln-agent/spool/` (5 newest)
- Report history (both modes): `/var/lib/vuln-agent/reports/` (30 newest gzip JSON + `latest.html`)
- Trivy cache: `/var/lib/vuln-agent/cache/`

## Local config (`config.yaml`)
See `config.example.yaml`.
```yaml
central_url: https://<central.domain>   # empty = standalone; http:// allowed over Tailscale, with a warning
client_id: <client_a>                   # must be empty when standalone
token: <per-host token>                 # must be empty when standalone
hostname_override: ""                   # optional; defaults to the OS hostname
ca_file: ""                             # optional, for a custom CA
extra_skip_dirs: []                     # optional; added to the skip_dirs in effect (both modes)
serve_addr: ""                          # optional; report page address, empty = 127.0.0.1:8090
```

## CLI subcommands
- `vuln-agent scan`: run one scan cycle, keep the report in the history, refresh `latest.html`, and (central mode) send it (invoked by a systemd timer)
- `vuln-agent report [-html]`: print the newest report as JSON, or the HTML page
- `vuln-agent serve [-addr host:port]`: read-only HTTP over the history (`/`, `/reports/{id}`, `/reports/{id}.json`, `/healthz`). Address: `-addr`, else `serve_addr` from the config, else `127.0.0.1:8090`. No auth, so it binds loopback by default and warns on any other address; reach it with `ssh -L`. Runs as `vuln-agent-serve.service`.
- `vuln-agent heartbeat`: send a heartbeat (no-op when standalone)
- `vuln-agent flush`: resend spooled reports (central only)
- `vuln-agent enroll [--force]` (central only): read `central_url` + `client_id` from config, read the enroll token from env `VULN_AGENT_ENROLL_TOKEN` or stdin (NEVER via CLI args, so it does not leak in `ps`), call `POST /api/v1/enroll`, and write `host_token` into `config.yaml` atomically (mode 600). Refuse if a token is already set, unless `--force`.
- `vuln-agent version`
- `vuln-agent check`: validate config and the Trivy binary, plus token and connectivity to central in central mode
- `vuln-agent install` (root, operator-run, idempotent): see Install below

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
   `severity`, `ignore_unfixed`, `skip_dirs`, and `timeout` can be overridden by config from central, but the agent ONLY accepts those fields. Reject any other field. Central's `skip_dirs` replaces the default list; the local `extra_skip_dirs` is then appended (duplicates skipped; dropped with a warning if the merged config is invalid, e.g. over 100 entries). The scan config cache keeps central's config without the extras.
3. Decode the output with `json.NewDecoder` (streaming) into a slim struct containing only:
   `Target, Type, VulnerabilityID, PkgName, PkgPath, InstalledVersion, FixedVersion, Severity, Title`.
4. Add host metadata:
   `hostname, os_family, os_name, os_version, arch, kernel_running, uptime_seconds, reboot_required (check /var/run/reboot-required or needs-restarting -r), unattended_upgrades_enabled (or dnf-automatic on RHEL), agent_version, trivy_version, scanned_at, scan_duration_seconds`.
5. Save the report to the history, then (central mode) send it gzipped to `POST /api/v1/report`.
6. If sending fails, save it to the spool. Status codes: 400/413/422 = permanent reject (dropped); 401/403/409/429/5xx = spooled and retried.
7. If Trivy fails, still keep/send a report with status `error` and its error message (truncated to at most 4KB).

The HTML page shows host facts, counts, findings grouped per component like central's dashboard (`Finding.Component()` in `internal/entity/component_entity.go`, a copy of central's rules: OS packages by installed version, app folder, or binary), each with a fix note and a command shown as text only (never run), and new/resolved since the previous successful scan (key: CVE, package, installed version, target, pkg path). Its CSP is `default-src 'none'; style-src 'unsafe-inline'`: no scripts or remote assets. Its look follows `DESIGN.md` (OpenCode style: monospace system font stack, cream canvas, hairline rules, `[+]`/`[-]` markers, one dark TUI header); severity colors are the only use of the semantic palette.

## Heartbeat
`POST /api/v1/heartbeat` with compact host metadata. Scheduled every 15 minutes.

## Install (`vuln-agent install`, `internal/delivery/cli/install_command.go`)
- Create dirs (`/opt/vuln-agent/bin` 755, `/etc/vuln-agent` and `/var/lib/vuln-agent/{spool,reports,cache}` 700)
- Copy the running binary to `/opt/vuln-agent/bin/vuln-agent`, symlink `/usr/bin/vuln-agent`
- Download the pinned Trivy release from GitHub, verify it against the release checksums file, install `/opt/vuln-agent/bin/trivy` (skipped if that version is already installed)
- Write a standalone `config.yaml` (mode 600) only if none exists; never overwrite (it may hold the host token)
- Write systemd units to `/etc/systemd/system/` and enable both timers:
  - `vuln-agent-scan.service` + `.timer` (daily, `RandomizedDelaySec=2h`, `Persistent=true`)
  - `vuln-agent-heartbeat.service` + `.timer` (every 15 minutes)
  - `vuln-agent-serve.service` (`Restart=on-failure`): enabled only on the first install (unit file did not exist), so an operator's `systemctl disable` survives reruns; reruns `try-restart` it to load the new binary
  - Resource limits: `CPUQuota=100%`, `MemoryMax=1G`, `Nice=19`, `IOSchedulingClass=idle`
- Enroll stays a separate manual step (`vuln-agent enroll`)

## Logging
Log to stdout/stderr (into journald), structured format (`log/slog`). NEVER print the token in logs.

## Testing
- `make test`
- Tests live in `test/` (package `test`) and use only exported APIs; fixtures in `test/testdata/`
- Unit tests for the Trivy parser with JSON fixtures (including large files and empty output)
- Usecase tests with fakes for both modes; HTML/handler tests (escaping, diff, path safety)

## Out of Scope (do not build)
- Remote command execution in the agent
- Agent auto-update from central
- Secret, misconfig, or license scanning (vuln only for now)
- AI/LLM integration
