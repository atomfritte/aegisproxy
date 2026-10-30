package registry

import "strings"

// sriToBase64 extracts the base64 digest from an npm Subresource Integrity string ("sha512-<base64>").
// Only sha512 is used by npm; other algorithms return "".
func sriToBase64(sri string) string {
	sri = strings.TrimSpace(sri)
	// SRI may list several space-separated hashes; take the first sha512.
	for _, part := range strings.Fields(sri) {
		if rest, ok := strings.CutPrefix(part, "sha512-"); ok {
			return rest
		}
	}
	return ""
}
