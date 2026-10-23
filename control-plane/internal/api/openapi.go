package api

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"net/http"
	"time"
)

// openAPISpec is the OpenAPI 3.1 description of this API. openapi_test.go keeps its paths in sync
// with the route registrations of this package.
//
//go:embed openapi.yaml
var openAPISpec []byte

var openAPIETag = func() string {
	sum := sha256.Sum256(openAPISpec)
	return `"oas-` + hex.EncodeToString(sum[:12]) + `"`
}()

// handleOpenAPI serves the embedded OpenAPI document (public, cacheable, conditional requests).
func (s *Server) handleOpenAPI(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Set("Content-Type", "application/yaml")
	h.Set("Content-Disposition", `inline; filename="aegisproxy-openapi.yaml"`)
	h.Set("Cache-Control", "public, max-age=3600")
	h.Set("ETag", openAPIETag)
	http.ServeContent(w, r, "openapi.yaml", time.Time{}, bytes.NewReader(openAPISpec))
}
