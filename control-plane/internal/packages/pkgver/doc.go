// Package pkgver implements the version semantics of the package firewall's ecosystems: npm (node-semver as npm
// resolves, npm-package-arg spec kinds), PyPI (PEP 440 versions and specifiers, PEP 508 requirements and markers,
// wheel and sdist file names, as pypa/packaging implements them), NuGet and the PowerShell Gallery (NuGet.Versioning
// versions, ranges and resolution), plus ecosystem-independent dispatchers used by rules and the resolver.
//
// Parsers never panic on untrusted input; parse results are immutable values that are safe for concurrent use.
package pkgver

// Ecosystem identifiers (the same values as models.Ecosystem*).
const (
	ecoNPM       = "npm"
	ecoPyPI      = "pypi"
	ecoNuGet     = "nuget"
	ecoPSGallery = "psgallery"
)

// maxSafeInt is JavaScript's Number.MAX_SAFE_INTEGER, the largest version component node-semver accepts.
const maxSafeInt = 1<<53 - 1
