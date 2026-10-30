//go:build linux

package runner

// Loader scripts for the load scenario. They are written into /aegis at runtime and run inside the analyzed
// runtime. Each resolves missing dependencies to a permissive stub (so a package that imports things not shipped
// still exercises its own top-level code), reads the per-run sentinel file right before importing the package
// (the marker the strace parser counts from), imports the package's entry points, and waits a few seconds so
// timers / async work run.

// nodeLoaderJS: argv = [pkgDir, entrypoints...]. Uses Module._load to stub unresolved requires.
const nodeLoaderJS = `'use strict';
const Module = require('module');
const path = require('path');
const fs = require('fs');
function mkStub() {
  const h = {
    get(t, p) { if (p === 'then') return undefined; if (p === Symbol.toPrimitive) return () => ''; return stub; },
    apply() { return stub; },
    construct() { return stub; },
  };
  return new Proxy(function () {}, h);
}
const stub = mkStub();
const orig = Module._load;
Module._load = function (request, parent, isMain) {
  try { return orig.apply(this, arguments); }
  catch (e) { try { process.stderr.write('[aegis] stub module: ' + request + '\n'); } catch (_) {} return stub; }
};
try { fs.readFileSync(process.env.AEGIS_SENTINEL || '/nonexistent'); } catch (e) {}
const pkgDir = process.argv[2];
const entries = process.argv.slice(3);
const targets = entries.length ? entries : [pkgDir];
for (const t of targets) {
  const target = path.isAbsolute(t) ? t : path.join(pkgDir, t);
  try { require(target); } catch (e) { try { process.stderr.write('[aegis] require ' + target + ': ' + (e && e.message) + '\n'); } catch (_) {} }
  try { import(target).catch(function () {}); } catch (e) {}
}
setTimeout(function () { process.exit(0); }, 3000);
`

// pyLoaderPy: argv = [sitedirsCSV, modules...]. Installs a stub meta-path finder for missing imports.
const pyLoaderPy = `import sys, os, site, importlib, types
import importlib.abc, importlib.machinery

for d in (sys.argv[1].split(',') if len(sys.argv) > 1 else []):
    if d and os.path.isdir(d):
        try:
            site.addsitedir(d)   # also processes .pth files
        except Exception:
            pass
        if d not in sys.path:
            sys.path.insert(0, d)

class _StubLoader(importlib.abc.Loader):
    def create_module(self, spec):
        m = types.ModuleType(spec.name)
        def __getattr__(name, _m=m):
            return _m
        m.__getattr__ = __getattr__
        m.__path__ = []
        return m
    def exec_module(self, module):
        pass

class _StubFinder(importlib.abc.MetaPathFinder):
    def find_spec(self, name, path=None, target=None):
        return importlib.machinery.ModuleSpec(name, _StubLoader())

sys.meta_path.append(_StubFinder())

try:
    with open(os.environ.get('AEGIS_SENTINEL', '/nonexistent')) as _f:
        _f.read()
except Exception:
    pass

for mod in sys.argv[2:]:
    try:
        importlib.import_module(mod)
    except Exception as e:
        try:
            sys.stderr.write('[aegis] import %s: %s\n' % (mod, e))
        except Exception:
            pass

import time
time.sleep(3)
`

// commonEnv returns the base environment for an analyzed process: the sandbox user, the CA-trust variables so
// the HTTPS sink is trusted, offline/telemetry-off settings for the package managers, the sentinel path, and the
// decoy CI-persona + secret variables.
func commonEnv(home, caPEM, caDir, sentinel string, decoy map[string]string) []string {
	env := []string{
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"HOME=" + home,
		"USER=sandbox",
		"LOGNAME=sandbox",
		"SHELL=/bin/sh",
		"TMPDIR=/tmp",
		"LANG=C.UTF-8",
		"AEGIS_SENTINEL=" + sentinel,
		// Trust the sandbox CA across the common runtimes/tools.
		"NODE_EXTRA_CA_CERTS=" + caPEM,
		"SSL_CERT_FILE=" + caPEM,
		"SSL_CERT_DIR=" + caDir,
		"REQUESTS_CA_BUNDLE=" + caPEM,
		"PIP_CERT=" + caPEM,
		"CURL_CA_BUNDLE=" + caPEM,
		"GIT_SSL_CAINFO=" + caPEM,
		"CARGO_HTTP_CAINFO=" + caPEM,
		// Keep the package managers offline and quiet.
		"PIP_NO_INPUT=1",
		"PIP_DISABLE_PIP_VERSION_CHECK=1",
		"PIP_NO_COLOR=1",
		"NPM_CONFIG_UPDATE_NOTIFIER=false",
		"NPM_CONFIG_FUND=false",
		"NPM_CONFIG_AUDIT=false",
		"DOTNET_CLI_TELEMETRY_OPTOUT=1",
		"DOTNET_NOLOGO=1",
		"DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1",
		"DOTNET_CLI_HOME=/tmp/dotnet",
		"NUGET_PACKAGES=/tmp/nuget",
		"POWERSHELL_TELEMETRY_OPTOUT=1",
		"POWERSHELL_UPDATECHECK=Off",
	}
	for _, k := range sortedKeys(decoy) {
		env = append(env, k+"="+decoy[k])
	}
	return env
}
