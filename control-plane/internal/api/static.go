package api

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

const uiCSP = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; " +
	"font-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"

// mountUI serves the production web console build (frontend/dist) with SPA fallback routing.
func (s *Server) mountUI() {
	dir := s.cfg.UIDir
	if dir == "" {
		for _, candidate := range []string{"./ui", "../frontend/dist"} {
			if fi, err := os.Stat(filepath.Join(candidate, "index.html")); err == nil && !fi.IsDir() {
				dir = candidate
				break
			}
		}
	}
	if dir == "" {
		s.mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			_, _ = w.Write([]byte("AegisProxy control-plane API is running. The web console is not bundled with this instance (set AEGIS_UI_DIR).\n"))
		})
		return
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return
	}
	s.log.Info("serving web console", "dir", abs)
	fileServer := http.FileServer(http.Dir(abs))
	s.mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") {
			writeError(w, http.StatusNotFound, "not found")
			return
		}
		h := w.Header()
		h.Set("Content-Security-Policy", uiCSP)
		clean := filepath.Clean("/" + r.URL.Path)
		target := filepath.Join(abs, clean)
		if fi, err := os.Stat(target); err != nil || fi.IsDir() {
			// SPA fallback: unknown paths render index.html (client-side routing).
			h.Set("Cache-Control", "no-cache")
			http.ServeFile(w, r, filepath.Join(abs, "index.html"))
			return
		}
		if strings.HasPrefix(clean, "/assets/") {
			h.Set("Cache-Control", "public, max-age=31536000, immutable")
		} else {
			h.Set("Cache-Control", "no-cache")
		}
		fileServer.ServeHTTP(w, r)
	})
}
