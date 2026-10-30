package store

import (
	"aegisproxy/control-plane/internal/packages/pkgver"
)

// normalizePackageName applies the ecosystem's canonical name form.
func normalizePackageName(ecosystem, name string) string {
	return pkgver.NormalizeName(ecosystem, name)
}

// versionInBlock reports whether version falls inside a block's version expression ("*" or an
// ecosystem range). An unparsable expression matches only the exact version string.
func versionInBlock(ecosystem, version, expr string) bool {
	if expr == "" || expr == "*" {
		return true
	}
	return pkgver.RangeContains(ecosystem, expr, version)
}
