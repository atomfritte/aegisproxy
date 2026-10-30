package runner

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestDNSSinkAnswersAndRecords(t *testing.T) {
	col := NewCollector(time.Now())
	hub := NewColHub(col)
	srv, err := StartDNS(hub, "127.0.0.1:0", "")
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	// Build an A query for "evil.example".
	q := buildAQuery(0x1234, "evil.example", 1)
	conn, err := net.Dial("udp", srv.UDPAddr())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.Write(q)
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	// Answer must be a 127.10.x.y address.
	ip := col.AssignIP("evil.example") // same mapping as handed out
	if !strings.HasPrefix(ip, "127.10.") {
		t.Errorf("assigned ip = %s", ip)
	}
	if n < 12 {
		t.Fatalf("short answer %d", n)
	}
	// The query must be recorded.
	nw := col.Network()
	if len(nw.DNS) != 1 || nw.DNS[0].Name != "evil.example" || nw.DNS[0].Type != "A" {
		t.Errorf("dns records = %+v", nw.DNS)
	}
	// Resolve maps back.
	if col.Resolve(ip) != "evil.example" {
		t.Errorf("resolve(%s) = %q", ip, col.Resolve(ip))
	}
}

func TestHTTPSinkCapturesPlainAndTLS(t *testing.T) {
	ca, err := NewSandboxCA()
	if err != nil {
		t.Fatal(err)
	}
	col := NewCollector(time.Now())
	hub := NewColHub(col)
	sink, err := StartHTTPSink(hub, ca, "127.0.0.1:0", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer sink.Close()

	// Plain HTTP POST with a body.
	plainClient := &http.Client{Timeout: 3 * time.Second}
	resp, err := plainClient.Post("http://"+sink.PlainAddr()+"/upload?token=abc", "text/plain", strings.NewReader("secret-body"))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	// TLS client that trusts the sandbox CA and sends SNI "api.evil.example".
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(ca.CertPEM())
	tlsAddr := sink.TLSAddr()
	tlsClient := &http.Client{
		Timeout: 3 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return net.Dial("tcp", tlsAddr) // ignore the dialed host, always hit the sink
			},
			TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: "api.evil.example"},
		},
	}
	resp2, err := tlsClient.Get("https://api.evil.example/collect")
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp2.Body)
	resp2.Body.Close()

	nw := col.Network()
	if len(nw.HTTP) != 2 {
		t.Fatalf("http records = %d, want 2: %+v", len(nw.HTTP), nw.HTTP)
	}
	var sawPlain, sawTLS bool
	for _, r := range nw.HTTP {
		if r.Method == "POST" && strings.Contains(r.URL, "/upload?token=abc") && strings.Contains(r.BodyPreview, "secret-body") {
			sawPlain = true
		}
		if r.TLS && r.SNI == "api.evil.example" && strings.Contains(r.URL, "https://api.evil.example/collect") {
			sawTLS = true
		}
	}
	if !sawPlain || !sawTLS {
		t.Errorf("plain=%v tls=%v: %+v", sawPlain, sawTLS, nw.HTTP)
	}
}

func TestTCPSinkCapturesPreview(t *testing.T) {
	col := NewCollector(time.Now())
	hub := NewColHub(col)
	sink := StartTCPSink(hub, "127.0.0.1", []int{0}) // port 0 -> ephemeral
	defer sink.Close()
	addr := sink.listeners[0].Addr().String()

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	conn.Write([]byte("HELO exfil-data\r\n"))
	conn.Close()

	// Give the sink goroutine a moment.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if len(col.tcpConns()) > 0 {
			break
		}
		runtimeGosched()
	}
	conns := col.tcpConns()
	if len(conns) != 1 || !strings.Contains(conns[0].Preview, "HELO exfil-data") {
		t.Errorf("tcp conns = %+v", conns)
	}
}

func runtimeGosched() { time.Sleep(10 * time.Millisecond) }

// buildAQuery builds a minimal DNS query message for name/qtype.
func buildAQuery(id uint16, name string, qtype uint16) []byte {
	msg := []byte{byte(id >> 8), byte(id), 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	for _, label := range strings.Split(name, ".") {
		msg = append(msg, byte(len(label)))
		msg = append(msg, label...)
	}
	msg = append(msg, 0)
	msg = append(msg, byte(qtype>>8), byte(qtype), 0x00, 0x01)
	return msg
}
