package runner

import (
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"aegisproxy/control-plane/internal/sandbox"
)

const sinkBody = "ok\n"
const maxBodyPreview = 2 << 10 // 2 KiB

// HTTPSink is the plaintext (:80) and TLS-terminating (:443) web sink. It records the full URL, method, headers
// and a body preview of every request and answers 200 with a tiny body so multi-step client logic proceeds.
type HTTPSink struct {
	hub      *ColHub
	plain    net.Listener
	tls      net.Listener
	srvPlain *http.Server
	srvTLS   *http.Server
}

// StartHTTPSink starts the HTTP sink on plainAddr and the HTTPS sink on tlsAddr using ca for per-SNI leaves.
// Either address may be empty to skip it. In the sandbox the addresses are :80 and :443.
func StartHTTPSink(hub *ColHub, ca *SandboxCA, plainAddr, tlsAddr string) (*HTTPSink, error) {
	s := &HTTPSink{hub: hub}
	handler := http.HandlerFunc(s.handle)
	if plainAddr != "" {
		ln, err := net.Listen("tcp", plainAddr)
		if err != nil {
			return nil, err
		}
		s.plain = ln
		s.srvPlain = &http.Server{Handler: handler, ReadHeaderTimeout: 10 * time.Second}
		go s.srvPlain.Serve(ln)
	}
	if tlsAddr != "" {
		ln, err := net.Listen("tcp", tlsAddr)
		if err != nil {
			s.Close()
			return nil, err
		}
		tlsCfg := &tls.Config{GetCertificate: ca.GetCertificate, MinVersion: tls.VersionTLS12}
		s.tls = tls.NewListener(ln, tlsCfg)
		s.srvTLS = &http.Server{Handler: handler, ReadHeaderTimeout: 10 * time.Second}
		go s.srvTLS.Serve(s.tls)
	}
	return s, nil
}

func (s *HTTPSink) PlainAddr() string {
	if s.plain != nil {
		return s.plain.Addr().String()
	}
	return ""
}
func (s *HTTPSink) TLSAddr() string {
	if s.tls != nil {
		return s.tls.Addr().String()
	}
	return ""
}

func (s *HTTPSink) Close() {
	if s.srvPlain != nil {
		s.srvPlain.Close()
	}
	if s.srvTLS != nil {
		s.srvTLS.Close()
	}
}

func (s *HTTPSink) handle(w http.ResponseWriter, r *http.Request) {
	isTLS := r.TLS != nil
	scheme := "http"
	if isTLS {
		scheme = "https"
	}
	host := r.Host
	if host == "" && r.TLS != nil {
		host = r.TLS.ServerName
	}
	rec := sandbox.HTTPRequest{
		TimeMs: s.hub.C().relMs(),
		Method: r.Method,
		URL:    scheme + "://" + host + r.RequestURI,
		Host:   host,
		TLS:    isTLS,
		SNI:    tlsSNI(r),
	}
	// Headers (capped, values clamped; drop hop-by-hop noise).
	hdrs := map[string]string{}
	n := 0
	for k, vs := range r.Header {
		if n >= 32 {
			break
		}
		hdrs[k] = clampStr(strings.Join(vs, ", "), 512)
		n++
	}
	if len(hdrs) > 0 {
		rec.Headers = hdrs
	}
	// Body preview (read a bit past the preview to learn whether there is more, then stop).
	body, _ := io.ReadAll(io.LimitReader(r.Body, maxBodyPreview+1))
	rec.BodySize = int64(len(body))
	if len(body) > maxBodyPreview {
		rec.BodyPreview = printable(body[:maxBodyPreview], maxBodyPreview)
		// Drain the rest to size, bounded, so we can report an approximate size without buffering it all.
		extra, _ := io.Copy(io.Discard, io.LimitReader(r.Body, 8<<20))
		rec.BodySize += extra
	} else {
		rec.BodyPreview = printable(body, maxBodyPreview)
	}
	s.hub.C().RecordHTTP(rec)

	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("Content-Length", strconv.Itoa(len(sinkBody)))
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, sinkBody)
}

func tlsSNI(r *http.Request) string {
	if r.TLS != nil {
		return r.TLS.ServerName
	}
	return ""
}

// TCPSink is a set of plain TCP listeners on common service / RAT ports. Each records the first bytes a client
// sends (up to 2 KiB) and the sandbox address it reached (mapped back to the queried hostname), then closes.
type TCPSink struct {
	hub       *ColHub
	listeners []net.Listener
}

// DefaultSinkPorts are the generic TCP ports the sink listens on (besides 80/443, which the HTTP sink owns).
var DefaultSinkPorts = []int{
	21, 22, 23, 25, 110, 143, 465, 587, 993, 995, // mail / shell / telnet
	1080,                    // socks
	3306, 5432, 6379, 27017, // mysql / postgres / redis / mongo
	8080, 8443, 8888, 9000, // http-alt
	6667,                                        // irc
	1337, 4444, 5555, 6666, 31337, 12345, 54321, // common RAT/backdoor ports
}

// StartTCPSink starts a listener per port on the given host (":" + port). host "" means all interfaces (the
// sandbox has only loopback). Ports that fail to bind are skipped.
func StartTCPSink(hub *ColHub, host string, ports []int) *TCPSink {
	s := &TCPSink{hub: hub}
	for _, p := range ports {
		ln, err := net.Listen("tcp", net.JoinHostPort(host, strconv.Itoa(p)))
		if err != nil {
			continue
		}
		s.listeners = append(s.listeners, ln)
		go s.serve(ln, p)
	}
	return s
}

// Ports returns the ports that were successfully bound.
func (s *TCPSink) Ports() []int {
	var out []int
	for _, ln := range s.listeners {
		if _, port, err := net.SplitHostPort(ln.Addr().String()); err == nil {
			out = append(out, atoiSafe(port))
		}
	}
	return out
}

func (s *TCPSink) Close() {
	for _, ln := range s.listeners {
		ln.Close()
	}
}

func (s *TCPSink) serve(ln net.Listener, port int) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go s.handleConn(conn, port)
	}
}

func (s *TCPSink) handleConn(conn net.Conn, port int) {
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, maxBodyPreview)
	n, _ := conn.Read(buf)
	addr := ""
	if la, ok := conn.LocalAddr().(*net.TCPAddr); ok {
		addr = la.IP.String()
	}
	s.hub.C().RecordTCP(addr, port, string(buf[:n]))
}
