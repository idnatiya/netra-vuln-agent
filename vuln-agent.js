#!/usr/bin/env node
// npm wrapper: runs the bundled Go binary. As the postinstall script it runs
// `vuln-agent install` when npm runs as root, and never fails the npm install
// (npm would roll the package back and remove the binary needed to retry).
// ponytail: one package carries both arch binaries (~18MB); split into per-arch
// optionalDependencies packages if download size matters.
'use strict';
const { spawnSync } = require('child_process');
const fs = require('fs');
const path = require('path');

const arch = { x64: 'amd64', arm64: 'arm64' }[process.arch];
const bin = path.join(__dirname, 'dist', `vuln-agent-linux-${arch}`);
const retry = 'sudo "$(command -v vuln-agent)" install';

try {
  fs.chmodSync(bin, 0o755); // npm pack may drop the exec bit
} catch (_) {}

// npm hides lifecycle script output, so status lines also go to the terminal.
function say(msg) {
  try {
    fs.writeFileSync('/dev/tty', `${msg}\n`);
  } catch (_) {
    console.error(msg);
  }
}

if (process.env.npm_lifecycle_event === 'postinstall') {
  if (process.env.npm_config_global !== 'true') process.exit(0);
  if (process.getuid() !== 0) {
    say(`vuln-agent: not root, skipped system install. Run: ${retry}`);
    process.exit(0);
  }
  const r = spawnSync(bin, ['install'], { stdio: 'inherit' });
  if (r.error || r.status !== 0) {
    say(`vuln-agent: install did not finish (${r.error ? r.error.message : `exit ${r.status}`}). See the log with: ${retry}`);
  } else {
    say('vuln-agent: installed. Next: edit /etc/vuln-agent/config.yaml for central mode, then sudo vuln-agent check');
  }
  process.exit(0);
}

const r = spawnSync(bin, process.argv.slice(2), { stdio: 'inherit' });
if (r.error) {
  console.error(`vuln-agent: ${r.error.message}`);
  process.exit(1);
}
if (r.signal) process.kill(process.pid, r.signal);
process.exit(r.status);
