package runner

import (
	"aegisproxy/control-plane/internal/sandbox"
)

const (
	maxStaticFiles = 5000
	maxNativeFiles = 500
	maxStaticHooks = 500
)

// StaticAnalysis unpacks the artifact and performs all static inspection, returning the report's Static section
// plus the extraction root, manifest and inventory the dynamic phases need. extractRoot must be an existing empty
// directory. It never returns an error for hostile content; err is only for a failure to start extraction.
func StaticAnalysis(eco, artifactPath, format, extractRoot string, lim ExtractLimits) (sandbox.Static, *ExtractResult, ManifestResult, error) {
	var st sandbox.Static
	ext, err := Extract(extractRoot, artifactPath, format, lim)
	if err != nil {
		return st, ext, ManifestResult{Manifest: map[string]any{}}, err
	}
	st.FileCount = ext.FileCount
	st.TotalSize = ext.TotalBytes
	st.Files = capFiles(ext.Files, maxStaticFiles, &st.Dropped)
	st.NativeBinaries = capFiles(ext.NativeBinaries, maxNativeFiles, &st.Dropped)

	man := ParseEcosystem(eco, extractRoot, ext.Files)
	st.Manifest = man.Manifest
	st.Entrypoints = man.Entrypoints
	st.InstallHooks = capHooks(man.Hooks, maxStaticHooks, &st.Dropped)

	sc := ScanStatic(eco, extractRoot, ext.Files)
	st.Indicators = sc.Indicators
	st.URLs = sc.URLs
	st.Domains = sc.Domains
	st.IPs = sc.IPs
	st.Dropped += sc.Dropped

	st.Signatures = ScanSignatures(extractRoot, ext.Files)

	// Record archive-level defenses as static indicators so a reviewer sees them.
	if ext.BombSuspected {
		st.Indicators = append(st.Indicators, sandbox.Indicator{
			Rule: "archive-decompression-bomb", Severity: "high", File: artifactPath,
			Description: "a member expanded far beyond its compressed size (decompression bomb)"})
	}
	for _, rej := range ext.Rejected {
		if len(st.Indicators) >= maxIndicators+64 {
			break
		}
		st.Indicators = append(st.Indicators, sandbox.Indicator{
			Rule: "archive-unsafe-path", Severity: "high", File: rej,
			Description: "archive member with a traversal/absolute/escaping path was rejected"})
	}
	return st, ext, man, nil
}

func capFiles(in []sandbox.File, cap int, dropped *int) []sandbox.File {
	if len(in) > cap {
		*dropped += len(in) - cap
		return in[:cap]
	}
	return in
}

func capHooks(in []sandbox.InstallHook, cap int, dropped *int) []sandbox.InstallHook {
	if len(in) > cap {
		*dropped += len(in) - cap
		return in[:cap]
	}
	return in
}
