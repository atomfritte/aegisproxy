package runner

import (
	"os"
	"path/filepath"
	"testing"

	"aegisproxy/control-plane/internal/sandbox"
)

// writeTree writes files (relative slash paths -> content) under a new temp dir and returns the dir plus the
// classified inventory the parsers/scanners consume.
func writeTree(t *testing.T, files map[string]string) (string, []sandbox.File) {
	t.Helper()
	root := t.TempDir()
	for rel, content := range files {
		abs := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(abs, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root, buildInventory(root)
}

func buildInventory(root string) []sandbox.File {
	var inv []sandbox.File
	filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(root, p)
		rel = filepath.ToSlash(rel)
		inv = append(inv, sandbox.File{Path: rel, Size: info.Size(), Kind: classifyKind(rel, p, info.Size())})
		return nil
	})
	return inv
}

func hookKinds(hs []sandbox.InstallHook) map[string]int {
	m := map[string]int{}
	for _, h := range hs {
		m[h.Kind]++
	}
	return m
}

func TestParseNpm(t *testing.T) {
	root, inv := writeTree(t, map[string]string{
		"package/package.json": `{"name":"demo","version":"1.2.3","license":"MIT","main":"index.js",
			"scripts":{"preinstall":"node setup.js","postinstall":"echo hi"},
			"dependencies":{"left-pad":"^1.0.0"},"bin":{"demo":"cli.js"}}`,
		"package/index.js": "module.exports=1",
		"package/cli.js":   "#!/usr/bin/env node",
	})
	res := ParseEcosystem("npm", root, inv)
	if res.Manifest["name"] != "demo" || res.Manifest["version"] != "1.2.3" {
		t.Errorf("manifest = %v", res.Manifest)
	}
	k := hookKinds(res.Hooks)
	if k["npm-script"] != 2 {
		t.Errorf("npm-script hooks = %d, want 2", k["npm-script"])
	}
	if len(res.Entrypoints) == 0 || res.Entrypoints[0] != "index.js" {
		t.Errorf("entrypoints = %v", res.Entrypoints)
	}
}

func TestParseNpmGyp(t *testing.T) {
	root, inv := writeTree(t, map[string]string{
		"package/package.json": `{"name":"n","version":"1.0.0"}`,
		"package/binding.gyp":  `{"targets":[]}`,
		"package/index.js":     "x",
	})
	res := ParseEcosystem("npm", root, inv)
	if hookKinds(res.Hooks)["npm-gyp"] != 1 {
		t.Errorf("expected implicit node-gyp hook, got %v", res.Hooks)
	}
}

func TestParsePypiWheel(t *testing.T) {
	root, inv := writeTree(t, map[string]string{
		"demo-1.0.dist-info/METADATA":      "Metadata-Version: 2.1\nName: demo\nVersion: 1.0\nLicense: MIT\nRequires-Dist: requests\n",
		"demo-1.0.dist-info/top_level.txt": "demo\n",
		"demo-1.0.dist-info/RECORD":        "demo/__init__.py,,\n",
		"demo/__init__.py":                 "x=1",
		"demo/evil.pth":                    "import os",
	})
	res := ParseEcosystem("pypi", root, inv)
	if res.Manifest["format"] != "wheel" || res.Manifest["name"] != "demo" {
		t.Errorf("manifest = %v", res.Manifest)
	}
	if hookKinds(res.Hooks)["pth"] != 1 {
		t.Errorf("pth hook missing: %v", res.Hooks)
	}
	if !containsStr(res.Entrypoints, "demo") {
		t.Errorf("entrypoints = %v", res.Entrypoints)
	}
}

func TestParsePypiSdist(t *testing.T) {
	root, inv := writeTree(t, map[string]string{
		"demo-1.0/PKG-INFO":         "Metadata-Version: 2.1\nName: demo\nVersion: 1.0\n",
		"demo-1.0/setup.py":         "from setuptools import setup\nsetup(name='demo')\n",
		"demo-1.0/pyproject.toml":   "[build-system]\nrequires=[\"hatchling\"]\nbuild-backend=\"hatchling.build\"\n",
		"demo-1.0/demo/__init__.py": "x=1",
	})
	res := ParseEcosystem("pypi", root, inv)
	k := hookKinds(res.Hooks)
	if k["setup-py"] != 1 || k["pep517"] != 1 {
		t.Errorf("sdist hooks = %v", res.Hooks)
	}
	if res.Manifest["build_backend"] != "hatchling.build" {
		t.Errorf("build_backend = %v", res.Manifest["build_backend"])
	}
}

func TestParseNuget(t *testing.T) {
	root, inv := writeTree(t, map[string]string{
		"demo.nuspec":         `<?xml version="1.0"?><package><metadata><id>Demo</id><version>1.0.0</version><authors>Acme</authors></metadata></package>`,
		"build/Demo.props":    `<Project></Project>`,
		"build/Demo.targets":  `<Project><Target Name="x"><Exec Command="id"/></Target></Project>`,
		"tools/init.ps1":      `Write-Host hi`,
		"lib/net8.0/Demo.dll": "MZ",
		"demo.signature.p7s":  "\x30\x80",
	})
	res := ParseEcosystem("nuget", root, inv)
	k := hookKinds(res.Hooks)
	if k["msbuild-props"] != 1 || k["msbuild-targets"] != 1 || k["nuget-ps"] != 1 {
		t.Errorf("nuget hooks = %v", res.Hooks)
	}
	if res.Manifest["name"] != "Demo" {
		t.Errorf("name = %v", res.Manifest["name"])
	}
	if res.Manifest["signature_present"] != true {
		t.Errorf("signature_present = %v", res.Manifest["signature_present"])
	}
	tfms, _ := res.Manifest["lib_tfms"].([]string)
	if !containsStr(tfms, "net8.0") {
		t.Errorf("lib_tfms = %v", tfms)
	}
}

func TestParsePsgallery(t *testing.T) {
	root, inv := writeTree(t, map[string]string{
		"Demo.psd1": `@{
RootModule = 'Demo.psm1'
ModuleVersion = '1.0.0'
Author = 'Acme'
RequiredModules = @('Pester','PSReadLine')
ScriptsToProcess = @('init.ps1')
}`,
		"Demo.psm1": "function Get-Demo {}",
		"init.ps1":  "Write-Host loaded",
	})
	res := ParseEcosystem("psgallery", root, inv)
	k := hookKinds(res.Hooks)
	if k["ps-module"] != 1 || k["ps-scripts-to-process"] != 1 {
		t.Errorf("ps hooks = %v", res.Hooks)
	}
	req, _ := res.Manifest["required_modules"].([]string)
	if !containsStr(req, "Pester") || !containsStr(req, "PSReadLine") {
		t.Errorf("required_modules = %v", req)
	}
}

func containsStr(xs []string, v string) bool {
	for _, x := range xs {
		if x == v {
			return true
		}
	}
	return false
}
