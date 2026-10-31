# Project: netra-vuln-agent

## Language
Everything in this repo is written in **English**: code, identifiers, comments, log messages, error strings, docs, commit messages, and config examples.

## Context
A small non-AI program installed on Linux VMs (Ubuntu/Debian and the RHEL family: AlmaLinux/Rocky/CentOS). It runs Trivy, slims down the results, and sends them to central (repo `netra-vuln`: API + MySQL + admin dashboard), which manages 26 VMs across several clients. Central is required (`central_url` + `client_id`); the agent keeps no local report history or report page, only a spool of unsent reports.

Central imports this module for the JSON contract (`pkg/wire`, `pkg/scanconfig`). Tag a release (`vX.Y.Z`) when the contract changes and bump it in central's `go.mod`.

If a design decision is ambiguous, ask first.

## Mandatory Principles
1. **Passive agent**: the agent ONLY sends data and fetches declarative (read-only) config. It MUST NOT have any feature to run commands, scripts, or auto-updates from central in any form.
2. **Push only**: all communication with central is initiated by the agent. Transport is HTTPS by default; plain HTTP is allowed only over an already-encrypted network (e.g. Tailscale), and the agent logs a warning when it is used.
3. **Simple and maintainable**: the only external dependency is `gopkg.in/yaml.v3`. Keep scope small.

## Stack
- Language: **Go** (latest stable; build toolchain pinned by `toolchain` in `go.mod`, bump it for Go security releases; keep the `go` line low so central can build); stdlib `net/http` for the central client
- Static binary (`CGO_ENABLED=0`), targets `linux/amd64` and `linux/arm64`
- Scanner: **Trivy binary** invoked via `os/exec` (DO NOT import Trivy as a library). Trivy version is pinned by `TRIVY_VERSION` in the `Makefile` (ldflag `main.trivyVersion`).
- Install: `vuln-agent install` (no Ansible, no .deb/.rpm, no CI release pipeline); central's `GET /install.sh` (its Add agent page) downloads the pinned release, checks `SHA256SUMS`, and runs `install -central-url -client-id`
- Distribution: GitHub Release assets `vuln-agent-linux-{amd64,arm64}` + `SHA256SUMS` (`make release`, manual via `gh`); the README's curl block downloads, checks, and runs `install`.
- License: GPL-3.0-only (`LICENSE`, copyright idnatiya); keep new dependencies GPL-3.0-compatible.
- Release: commit, tag `vX.Y.Z` and push the tag, `make release` (GitHub Release; refuses without a tag on HEAD and a clean tree).
- Manual/dev update over SSH: `make deploy HOSTS="user@vm ..."` (build, scp to the user's home, `sudo ./vuln-agent.new install`, remove it).

## Repo Layout
Folder pattern follows [khannedy/golang-clean-architecture](https://github.com/khannedy/golang-clean-architecture), stdlib only (none of its libraries). Files carry a layer suffix (`scan_usecase.go`, `report_repository.go`, `central_gateway.go`).
```
go.mod                  # module github.com/idnatiya/netra-vuln-agent
cmd/vuln-agent/         # main.go only: version vars (ldflags) + cli.Run
internal/
  entity/               # entities + pure business rules (Finding, Report, HostInfo, ScanConfig), stdlib only
  usecase/              # scan/heartbeat/flush/enroll/check orchestration; ports (interfaces) in ports.go
  repository/           # filesystem storage: report spool, scan config cache
  gateway/
    central/            # HTTP client to central
    trivy/              # Scanner: exec Trivy + streaming parser; Trivy release installer
    hostinfo/           # Linux HostInspector
  model/converter/      # entity -> wire mapping
  delivery/
    cli/                # subcommands (Run), install command
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
- Spool (unsent reports): `/var/lib/vuln-agent/spool/` (5 newest)
- Trivy cache: `/var/lib/vuln-agent/cache/`

## Local config (`config.yaml`)
See `config.example.yaml`.
```yaml
central_url: https://<central.domain>   # required; http:// allowed over Tailscale, with a warning
client_id: <client_a>                   # required
token: <per-host token>                 # filled in by `vuln-agent enroll`
hostname_override: ""                   # optional; defaults to the OS hostname
ca_file: ""                             # optional, for a custom CA
extra_skip_dirs: []                     # optional; added to the skip_dirs in effect
app_dirs: [...]                         # optional; app folders to scan, unset = /var/www, /srv, /opt; [] = OS only
```

## CLI subcommands
- `vuln-agent scan`: run one scan cycle and send the report to central (invoked by a systemd timer)
- `vuln-agent heartbeat`: send a heartbeat
- `vuln-agent flush`: resend spooled reports
- `vuln-agent enroll [--force]`: read `central_url` + `client_id` from config, read the enroll token from env `VULN_AGENT_ENROLL_TOKEN` or stdin (NEVER via CLI args, so it does not leak in `ps`), call `POST /api/v1/enroll`, and write `host_token` into `config.yaml` atomically (mode 600). Refuse if a token is already set, unless `--force`.
- `vuln-agent version`
- `vuln-agent check`: validate config and the Trivy binary, plus token and connectivity to central in central mode
- `vuln-agent install [-central-url URL -client-id ID]` (root, operator-run, idempotent): see Install below

## `scan` flow
1. Send spooled reports first, then fetch scan config from `GET /api/v1/config` (read-only). On failure, use the last locally cached config, or the default if none exists.
2. Run Trivy with a `context` timeout (default 40 minutes) covering all runs, at low priority. One run for OS packages (`rootfs / --pkg-types os`), then one per existing app dir (`rootfs <dir> --pkg-types library`; app dirs = `app_dirs` (default `/var/www`, `/srv`, `/opt`) plus the `pm_cwd` of pm2 apps read from `/root/.pm2/dump.pm2` and `/home/*/.pm2/dump.pm2`, never by running pm2; missing, nested, and duplicate dirs dropped). App run paths are relative to the dir, so `Target`/`PkgPath` get the dir prefixed. Any failed run makes the scan an error. Default arguments:
   ```
   rootfs <target>
   --scanners vuln
   --pkg-types os|library
   --list-all-pkgs=false
   --ignore-unfixed
   --severity HIGH,CRITICAL
   --timeout 30m
   --cache-dir /var/lib/vuln-agent/cache
   --skip-dirs /proc,/sys,/dev,/run,/tmp,/snap,/var/lib/snapd,/var/lib/docker,/var/lib/containerd,/mnt,/media,/var/cache,/root/.cache,/home/*/.cache,/home/*/.local/share/pnpm,/usr/share/doc,/opt/vuln-agent
   --format json -q --output <temp file>
   ```
   `severity`, `ignore_unfixed`, `skip_dirs`, and `timeout` can be overridden by config from central, but the agent ONLY accepts those fields. Reject any other field. Central's `skip_dirs` replaces the default list; the local `extra_skip_dirs` is then appended (duplicates skipped; dropped with a warning if the merged config is invalid, e.g. over 100 entries). The scan config cache keeps central's config without the extras.
3. Decode the output with `json.NewDecoder` (streaming) into a slim struct containing only:
   `Target, Type, VulnerabilityID, PkgName, PkgPath, InstalledVersion, FixedVersion, Severity, Title`.
4. Add host metadata:
   `hostname, os_family, os_name, os_version, arch, kernel_running, uptime_seconds, reboot_required (check /var/run/reboot-required or needs-restarting -r), unattended_upgrades_enabled (or dnf-automatic on RHEL), agent_version, trivy_version, scanned_at, scan_duration_seconds`.
5. Send the report gzipped to `POST /api/v1/report`.
6. If sending fails, save it to the spool. Status codes: 400/413/422 = permanent reject (dropped); 401/403/409/429/5xx = spooled and retried.
7. If Trivy fails, still send a report with status `error` and its error message (truncated to at most 4KB).

## Heartbeat
`POST /api/v1/heartbeat` with compact host metadata. Scheduled every 15 minutes.

## Install (`vuln-agent install`, `internal/delivery/cli/install_command.go`)
- Create dirs (`/opt/vuln-agent/bin` 755, `/etc/vuln-agent` and `/var/lib/vuln-agent/{spool,cache}` 700)
- Copy the running binary to `/opt/vuln-agent/bin/vuln-agent`, symlink `/usr/bin/vuln-agent`
- Download the pinned Trivy release from GitHub, verify it against the release checksums file, install `/opt/vuln-agent/bin/trivy` (skipped if that version is already installed)
- Write a `config.yaml` template (mode 600) only if none exists; never overwrite (it may hold the host token)
- Write systemd units to `/etc/systemd/system/` and enable both timers:
  - `vuln-agent-scan.service` + `.timer` (daily, `RandomizedDelaySec=2h`, `Persistent=true`)
  - `vuln-agent-heartbeat.service` + `.timer` (every 15 minutes)
  - Migration: disables and removes the old `vuln-agent-serve.service` and deletes `/var/lib/vuln-agent/reports/` (drop once every VM is updated)
  - Resource limits: `CPUQuota=100%`, `MemoryMax=1G`, `Nice=19`, `IOSchedulingClass=idle`
- With `-central-url` + `-client-id` (both or neither): fill them into a new config (`config.Template`); then, if `$VULN_AGENT_ENROLL_TOKEN` is set and the config has no token, enroll and `systemctl start --no-block vuln-agent-scan.service`. An enrolled host is left as is. Without the flags, enroll stays a separate manual step (`vuln-agent enroll`)

## Logging
Log to stdout/stderr (into journald), structured format (`log/slog`). NEVER print the token in logs.

## Testing
- `make test`
- Tests live in `test/` (package `test`) and use only exported APIs; fixtures in `test/testdata/`
- Unit tests for the Trivy parser with JSON fixtures (including large files and empty output)
- Usecase tests with fakes

## Out of Scope (do not build)
- Remote command execution in the agent
- Agent auto-update from central
- Secret, misconfig, or license scanning (vuln only for now)
- AI/LLM integration
